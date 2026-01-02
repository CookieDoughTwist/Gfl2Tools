#!/usr/bin/env python3
"""
GFL2 Platoon Score Auto-Sniffer

Automatically captures and decodes platoon scores from Girls' Frontline 2.
Just run this script, then play the game and view platoon scores - 
the data will be automatically saved to a CSV file.

Requirements:
    - Python 3.7+
    - scapy: pip install scapy
    - Npcap (Windows) or libpcap (Linux/Mac) for packet capture
    - Run as Administrator/root for packet capture permissions

Usage:
    python gfl2_auto_sniffer.py [options]

Options:
    --output, -o    Output CSV file (default: gfl2_scores.csv)
    --interface, -i Network interface to sniff (default: auto-detect)
    --list-interfaces List available network interfaces and exit
    --verbose, -v   Show detailed output

Windows Setup:
    1. Install Python 3.7+ from python.org
    2. Install Npcap from https://npcap.com/ (check "WinPcap API-compatible Mode")
    3. Run: pip install scapy
    4. Run this script as Administrator
"""

import sys
import os
import csv
import re
import subprocess
import tempfile
import argparse
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set

try:
    from scapy.all import sniff, TCP, IP, Raw, get_if_list, conf
except ImportError:
    print("Error: scapy is not installed. Run: pip install scapy")
    sys.exit(1)


# GFL2 server characteristics
GFL2_PORT = 7001
GFL2_SERVER_PREFIXES = ['47.253.', '47.89.']  # Known Sunborn server IP ranges


class TCPStreamReassembler:
    """Reassembles TCP streams from individual packets."""
    
    def __init__(self):
        self.streams: Dict[tuple, bytearray] = defaultdict(bytearray)
        self.last_seq: Dict[tuple, int] = {}
    
    def add_packet(self, pkt) -> Optional[bytes]:
        """Add a packet to the stream. Returns complete data if stream looks complete."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        
        ip = pkt[IP]
        tcp = pkt[TCP]
        
        # Create stream key (always ordered the same way)
        stream_key = tuple(sorted([(ip.src, tcp.sport), (ip.dst, tcp.dport)]))
        
        # Only process data from server to client (server sends on port 7001)
        if tcp.sport != GFL2_PORT:
            return None
        
        payload = bytes(pkt[Raw].load)
        self.streams[stream_key].extend(payload)
        
        # Check for PSH flag which often indicates end of a message
        if tcp.flags & 0x08:  # PSH flag
            data = bytes(self.streams[stream_key])
            # Don't clear immediately - might need more data
            return data
        
        return None
    
    def get_stream(self, stream_key: tuple) -> bytes:
        return bytes(self.streams[stream_key])
    
    def clear_stream(self, stream_key: tuple):
        if stream_key in self.streams:
            del self.streams[stream_key]


def decode_varint(data: bytes, pos: int) -> tuple:
    """Decode a protobuf varint."""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            break
        shift += 7
    return result, pos


def decode_player_record_inline(record_data: bytes) -> Optional[Dict]:
    """
    Decode a player record without using external protoc.
    This is a simplified decoder for the specific GFL2 structure.
    """
    try:
        # Parse the protobuf manually
        fields = {}
        pos = 0
        
        while pos < len(record_data):
            if pos >= len(record_data):
                break
                
            tag_byte = record_data[pos]
            field_num = tag_byte >> 3
            wire_type = tag_byte & 0x7
            pos += 1
            
            if wire_type == 0:  # Varint
                value, pos = decode_varint(record_data, pos)
                fields[field_num] = value
            elif wire_type == 2:  # Length-delimited
                length, pos = decode_varint(record_data, pos)
                if pos + length > len(record_data):
                    break
                content = record_data[pos:pos+length]
                pos += length
                
                # Try to decode as string or nested message
                try:
                    decoded = content.decode('utf-8')
                    if decoded.isprintable() or '<' in decoded:
                        fields[field_num] = decoded
                    else:
                        fields[field_num] = content
                except:
                    fields[field_num] = content
            elif wire_type == 5:  # Fixed32
                if pos + 4 > len(record_data):
                    break
                pos += 4
            elif wire_type == 1:  # Fixed64
                if pos + 8 > len(record_data):
                    break
                pos += 8
            else:
                break
        
        return fields
    except:
        return None


def extract_player_records(data: bytes, use_protoc: bool = True) -> List[Dict]:
    """Extract all player score records from binary data."""
    records = {}
    i = 0
    
    while i < len(data) - 5:
        if data[i] == 0x0a:  # Field 1, length-delimited
            try:
                length, content_start = decode_varint(data, i + 1)
                
                if 200 <= length <= 600 and content_start < len(data):
                    if data[content_start] == 0x0a:  # Nested message
                        record_end = content_start + length
                        
                        if record_end <= len(data):
                            record_data = data[content_start:record_end]
                            record = None
                            
                            if use_protoc:
                                record = decode_with_protoc(record_data)
                            
                            if record is None:
                                record = decode_player_record_fallback(record_data)
                            
                            if record and record.get('name') and record['name'] not in records:
                                records[record['name']] = record
            except:
                pass
        i += 1
    
    return list(records.values())


def decode_with_protoc(record_data: bytes) -> Optional[Dict]:
    """Decode using protoc --decode_raw if available."""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(record_data)
            tmpfile = f.name
        
        result = subprocess.run(
            ['protoc', '--decode_raw'],
            stdin=open(tmpfile, 'rb'),
            capture_output=True,
            text=True,
            timeout=2
        )
        
        os.unlink(tmpfile)
        
        if result.returncode != 0 or '5:' not in result.stdout:
            return None
        
        decoded = result.stdout
        
        name_match = re.search(r'2: "([^"]+)"', decoded)
        platoon_match = re.search(r'13: "([^"]+)"', decoded)
        high_score_match = re.search(r'^5: (\d+)', decoded, re.MULTILINE)
        total_score_match = re.search(r'^6: (\d+)', decoded, re.MULTILINE)
        
        if not (name_match and high_score_match and total_score_match):
            return None
        
        return {
            'name': name_match.group(1),
            'platoon': platoon_match.group(1) if platoon_match else 'Unknown',
            'high_score': int(high_score_match.group(1)),
            'total_score': int(total_score_match.group(1))
        }
    except FileNotFoundError:
        return None  # protoc not installed
    except:
        return None


def decode_player_record_fallback(record_data: bytes) -> Optional[Dict]:
    """Fallback decoder when protoc is not available."""
    try:
        # Look for score pattern: 0x28 (field 5) followed by varint, then 0x30 (field 6)
        for i in range(len(record_data) - 10):
            if record_data[i] == 0x28:  # Field 5 tag
                high_score, pos = decode_varint(record_data, i + 1)
                if 1000 <= high_score <= 50000 and pos < len(record_data) and record_data[pos] == 0x30:
                    total_score, pos2 = decode_varint(record_data, pos + 1)
                    if 10000 <= total_score <= 500000:
                        # Found scores, now find name (field 2 in nested message)
                        name = extract_name_from_record(record_data)
                        platoon = extract_platoon_from_record(record_data)
                        
                        if name:
                            return {
                                'name': name,
                                'platoon': platoon or 'Unknown',
                                'high_score': high_score,
                                'total_score': total_score
                            }
        return None
    except:
        return None


def extract_name_from_record(data: bytes) -> Optional[str]:
    """Extract player name from record data."""
    # Look for field 2 (tag 0x12) with reasonable string length
    for i in range(len(data) - 5):
        if data[i] == 0x12:
            length = data[i + 1]
            if 2 <= length <= 25 and i + 2 + length <= len(data):
                try:
                    name = data[i + 2:i + 2 + length].decode('utf-8')
                    # Filter out non-name strings
                    if name.isprintable() and not any(x in name.lower() for x in ['<color', '<size', 'http', '.com']):
                        return name
                except:
                    pass
    return None


def extract_platoon_from_record(data: bytes) -> Optional[str]:
    """Extract platoon name from record data."""
    # Platoon is in field 13 (tag 0x6a)
    for i in range(len(data) - 5):
        if data[i] == 0x6a:
            length = data[i + 1]
            if 2 <= length <= 30 and i + 2 + length <= len(data):
                try:
                    platoon = data[i + 2:i + 2 + length].decode('utf-8')
                    if platoon.isprintable():
                        return platoon
                except:
                    pass
    return None


def extract_global_platoon_records(data: bytes, use_protoc: bool = True) -> List[Dict]:
    """
    Extract global platoon ranking records from binary data.
    These have a different structure than individual player records.
    
    Structure:
    - Field 1: Platoon ID
    - Field 2: Platoon name
    - Field 3: Level
    - Field 6: Total score
    """
    records = {}
    i = 0
    
    while i < len(data) - 10:
        if data[i] == 0x0a:  # Field 1, length-delimited
            try:
                length, content_start = decode_varint(data, i + 1)
                
                # Global platoon records are typically 100-500 bytes
                if 100 <= length <= 500 and content_start < len(data):
                    record_end = content_start + length
                    
                    if record_end <= len(data):
                        record_data = data[content_start:record_end]
                        
                        # Check if starts with field 1 (platoon ID)
                        if len(record_data) > 10 and record_data[0] == 0x08:
                            record = decode_global_platoon_record(record_data, use_protoc)
                            
                            if record and record.get('name'):
                                key = record['name']
                                # Keep the one with highest score if duplicates
                                if key not in records or record['score'] > records[key]['score']:
                                    records[key] = record
            except:
                pass
        i += 1
    
    return list(records.values())


def decode_global_platoon_record(record_data: bytes, use_protoc: bool = True) -> Optional[Dict]:
    """Decode a global platoon ranking record."""
    if use_protoc:
        record = decode_global_platoon_with_protoc(record_data)
        if record:
            return record
    
    # Fallback to manual parsing
    return decode_global_platoon_fallback(record_data)


def decode_global_platoon_with_protoc(record_data: bytes) -> Optional[Dict]:
    """Decode global platoon record using protoc."""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(record_data)
            tmpfile = f.name
        
        result = subprocess.run(
            ['protoc', '--decode_raw'],
            stdin=open(tmpfile, 'rb'),
            capture_output=True,
            text=True,
            timeout=2
        )
        
        os.unlink(tmpfile)
        
        if result.returncode != 0:
            return None
        
        decoded = result.stdout
        
        # Extract fields
        name_match = re.search(r'^2: "([^"]+)"', decoded, re.MULTILINE)
        score_match = re.search(r'^6: (\d+)', decoded, re.MULTILINE)
        level_match = re.search(r'^3: (\d+)', decoded, re.MULTILINE)
        
        if not (name_match and score_match):
            return None
        
        score = int(score_match.group(1))
        
        # Filter out non-platoon records (individual player data has scores < 10000)
        if score < 100000:
            return None
        
        return {
            'name': name_match.group(1),
            'level': int(level_match.group(1)) if level_match else 0,
            'score': score
        }
    except FileNotFoundError:
        return None
    except:
        return None


def decode_global_platoon_fallback(record_data: bytes) -> Optional[Dict]:
    """Fallback decoder for global platoon records."""
    try:
        # Look for field 6 (tag 0x30) which contains the score
        for i in range(len(record_data) - 6):
            if record_data[i] == 0x30:  # Field 6 tag
                score, _ = decode_varint(record_data, i + 1)
                
                # Global platoon scores are typically > 100,000
                if score >= 100000:
                    # Find platoon name (field 2, tag 0x12)
                    name = None
                    for j in range(i):
                        if record_data[j] == 0x12:
                            name_len = record_data[j + 1]
                            if 2 <= name_len <= 30:
                                try:
                                    name = record_data[j + 2:j + 2 + name_len].decode('utf-8')
                                    break
                                except:
                                    pass
                    
                    # Find level (field 3, tag 0x18)
                    level = 0
                    for j in range(i):
                        if record_data[j] == 0x18:
                            level, _ = decode_varint(record_data, j + 1)
                            break
                    
                    if name:
                        return {
                            'name': name,
                            'level': level,
                            'score': score
                        }
        return None
    except:
        return None


class GFL2ScoreSniffer:
    """Main sniffer class that captures and processes GFL2 traffic."""
    
    def __init__(self, output_file: str = 'gfl2_scores.csv', verbose: bool = False):
        self.output_file = output_file
        self.global_output_file = output_file.replace('.csv', '_global_platoons.csv')
        self.verbose = verbose
        self.reassembler = TCPStreamReassembler()
        self.seen_records: Set[tuple] = set()  # Track seen records to avoid duplicates
        self.seen_platoons: Set[tuple] = set()  # Track seen platoon records
        self.buffer = bytearray()
        self.last_process_time = datetime.now()
        
        # Check if protoc is available
        self.has_protoc = self._check_protoc()
        if not self.has_protoc:
            print("Note: protoc not found, using fallback decoder")
        
        # Initialize CSV files with headers if they don't exist
        if not os.path.exists(output_file):
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'name', 'platoon', 'high_score', 'total_score'])
        
        if not os.path.exists(self.global_output_file):
            with open(self.global_output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'platoon_name', 'level', 'score'])
    
    def _check_protoc(self) -> bool:
        """Check if protoc is available."""
        try:
            subprocess.run(['protoc', '--version'], capture_output=True, timeout=2)
            return True
        except:
            return False
    
    def packet_callback(self, pkt):
        """Called for each captured packet."""
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        
        ip = pkt[IP]
        tcp = pkt[TCP]
        
        # Check if this is GFL2 traffic
        is_gfl2 = (tcp.sport == GFL2_PORT or tcp.dport == GFL2_PORT)
        if not is_gfl2:
            return
        
        # Only process incoming data (from server)
        if tcp.sport != GFL2_PORT:
            return
        
        if not pkt.haslayer(Raw):
            return
        
        payload = bytes(pkt[Raw].load)
        self.buffer.extend(payload)
        
        if self.verbose:
            print(f"  Received {len(payload)} bytes from {ip.src}:{tcp.sport}")
        
        # Try to process when we have enough data and see a PSH flag
        if tcp.flags & 0x08 and len(self.buffer) > 500:
            self._process_buffer()
    
    def _process_buffer(self):
        """Process accumulated buffer for player records and global platoon records."""
        if len(self.buffer) < 500:
            return
        
        data = bytes(self.buffer)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Try to extract individual player records
        records = extract_player_records(data, use_protoc=self.has_protoc)
        
        new_records = []
        for record in records:
            record_key = (record['name'], record['high_score'], record['total_score'])
            if record_key not in self.seen_records:
                self.seen_records.add(record_key)
                new_records.append(record)
        
        if new_records:
            # Sort alphabetically by name
            new_records.sort(key=lambda x: x['name'].lower())
            self._save_records(new_records, timestamp)
            print(f"\n[{timestamp}] Found {len(new_records)} new player records:")
            for r in new_records[:10]:
                print(f"  {r['name']:20s} {r['platoon']:20s} High:{r['high_score']:6d} Total:{r['total_score']:7d}")
            if len(new_records) > 10:
                print(f"  ... and {len(new_records) - 10} more")
        
        # Try to extract global platoon records
        platoon_records = extract_global_platoon_records(data, use_protoc=self.has_protoc)
        
        new_platoons = []
        for record in platoon_records:
            record_key = (record['name'], record['score'])
            if record_key not in self.seen_platoons:
                self.seen_platoons.add(record_key)
                new_platoons.append(record)
        
        if new_platoons:
            # Sort by score descending
            new_platoons.sort(key=lambda x: x['score'], reverse=True)
            self._save_global_platoons(new_platoons, timestamp)
            print(f"\n[{timestamp}] Found {len(new_platoons)} global platoon rankings:")
            for r in new_platoons[:10]:
                print(f"  {r['name']:30s} Level:{r['level']:3d} Score:{r['score']:10d}")
            if len(new_platoons) > 10:
                print(f"  ... and {len(new_platoons) - 10} more")
        
        # Clear buffer after processing
        self.buffer.clear()
    
    def _save_records(self, records: List[Dict], timestamp: str):
        """Append records to CSV file."""
        with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for r in records:
                writer.writerow([timestamp, r['name'], r['platoon'], r['high_score'], r['total_score']])
    
    def _save_global_platoons(self, records: List[Dict], timestamp: str):
        """Append global platoon records to CSV file."""
        with open(self.global_output_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for r in records:
                writer.writerow([timestamp, r['name'], r['level'], r['score']])
    
    def start(self, interface: Optional[str] = None):
        """Start sniffing for GFL2 traffic."""
        # Build filter for GFL2 traffic
        bpf_filter = f"tcp port {GFL2_PORT}"
        
        print("=" * 60)
        print("GFL2 Platoon Score Auto-Sniffer")
        print("=" * 60)
        print(f"Player scores output: {self.output_file}")
        print(f"Global platoon output: {self.global_output_file}")
        print(f"Listening for GFL2 traffic on port {GFL2_PORT}")
        print(f"Interface: {interface or 'auto'}")
        print("-" * 60)
        print("Instructions:")
        print("  1. Start Girls' Frontline 2")
        print("  2. Open the Platoon menu and view scores")
        print("  3. For global rankings, view the platoon leaderboard")
        print("  4. Scores will be automatically captured and saved")
        print("  5. Press Ctrl+C to stop")
        print("-" * 60)
        print("Waiting for GFL2 traffic...\n")
        
        try:
            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=self.packet_callback,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nStopping sniffer...")
            # Process any remaining data
            if len(self.buffer) > 0:
                self._process_buffer()
            print(f"Results saved to: {self.output_file}")


def list_interfaces():
    """List available network interfaces."""
    print("Available network interfaces:")
    print("-" * 40)
    
    for iface in get_if_list():
        print(f"  {iface}")
    
    print("-" * 40)
    print("Use -i <interface> to specify which one to use")


def main():
    parser = argparse.ArgumentParser(
        description='Automatically capture GFL2 platoon scores',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('-o', '--output', default='gfl2_scores.csv',
                        help='Output CSV file (default: gfl2_scores.csv)')
    parser.add_argument('-i', '--interface', default=None,
                        help='Network interface to sniff')
    parser.add_argument('--list-interfaces', action='store_true',
                        help='List available network interfaces')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed output')
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        return
    
    # Check for admin/root privileges
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    if not is_admin:
        print("Warning: This script requires administrator/root privileges for packet capture.")
        print("Please run as Administrator (Windows) or with sudo (Linux/Mac).")
        if sys.platform == 'win32':
            print("\nOn Windows: Right-click and 'Run as administrator'")
        sys.exit(1)
    
    sniffer = GFL2ScoreSniffer(output_file=args.output, verbose=args.verbose)
    sniffer.start(interface=args.interface)


if __name__ == '__main__':
    main()
