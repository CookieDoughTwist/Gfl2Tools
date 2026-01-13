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
                
                # Records can be 140-600 bytes - the outer wrapper with scores
                # is typically 140-200 bytes, but can be larger with more player data
                if 140 <= length <= 600 and content_start < len(data):
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
        
        # Extract player name (first occurrence of field 2 with a string)
        name_match = re.search(r'2: "([^"]+)"', decoded)
        # Extract platoon (field 13)
        platoon_match = re.search(r'13: "([^"]+)"', decoded)
        
        # IMPORTANT: The scores are at the OUTER wrapper level, not nested.
        # In protoc output, outer fields have no leading whitespace.
        # We need the LAST occurrence of "^5:" and "^6:" (at line start, no indent)
        # to get the outer wrapper scores, not the inner nested ones.
        high_score_matches = re.findall(r'^5: (\d+)', decoded, re.MULTILINE)
        total_score_matches = re.findall(r'^6: (\d+)', decoded, re.MULTILINE)
        
        if not (name_match and high_score_matches and total_score_matches):
            return None
        
        # Use the LAST match which is the outer wrapper score
        high_score = int(high_score_matches[-1])
        total_score = int(total_score_matches[-1])
        
        # Sanity check: scores should be reasonable values
        if high_score < 100 or total_score < 100:
            return None
        
        return {
            'name': name_match.group(1),
            'platoon': platoon_match.group(1) if platoon_match else 'Unknown',
            'high_score': high_score,
            'total_score': total_score
        }
    except FileNotFoundError:
        return None  # protoc not installed
    except:
        return None


def decode_player_record_fallback(record_data: bytes) -> Optional[Dict]:
    """Fallback decoder when protoc is not available."""
    try:
        # The scores are at the OUTER wrapper level, which appears AFTER the nested
        # player data. Search from the END of the record to find the outer scores first.
        # Look for score pattern: 0x28 (field 5) followed by varint, then 0x30 (field 6)
        
        # Search backwards to find the LAST occurrence of field 5/6 pattern
        best_match = None
        for i in range(len(record_data) - 10):
            if record_data[i] == 0x28:  # Field 5 tag
                high_score, pos = decode_varint(record_data, i + 1)
                if 100 <= high_score <= 100000 and pos < len(record_data) and record_data[pos] == 0x30:
                    total_score, pos2 = decode_varint(record_data, pos + 1)
                    if 100 <= total_score <= 1000000:
                        # Keep track of this match - later matches (closer to end) are better
                        best_match = (high_score, total_score)
        
        if best_match:
            high_score, total_score = best_match
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
            # Allow single-character names (length >= 1)
            # Allow up to 50 bytes to accommodate multi-byte Unicode (e.g. Thai, Chinese, Japanese)
            # A 25-character name in Thai could be 75 bytes
            if 1 <= length <= 50 and i + 2 + length <= len(data):
                try:
                    name = data[i + 2:i + 2 + length].decode('utf-8')
                    # Filter out non-name strings (HTML tags, URLs)
                    # Don't use isprintable() as it fails on valid Unicode like Thai
                    if not any(x in name.lower() for x in ['<color', '<size', 'http', '.com', '\x00']):
                        # Basic sanity check - should have at least one letter/digit
                        if any(c.isalnum() for c in name):
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
    - Field 8.1.1: MVP player ID
    - Field 8.1.2: MVP player name
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
                            
                            if record and record.get('platoon_id'):
                                key = record['platoon_id']
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
        
        # Extract platoon fields
        platoon_id_match = re.search(r'^1: (\d+)', decoded, re.MULTILINE)
        name_match = re.search(r'^2: "([^"]+)"', decoded, re.MULTILINE)
        score_match = re.search(r'^6: (\d+)', decoded, re.MULTILINE)
        level_match = re.search(r'^3: (\d+)', decoded, re.MULTILINE)
        
        # Extract MVP info from field 8.1
        mvp_id_match = re.search(r'8 \{\s+1 \{\s+1: (\d+)', decoded)
        mvp_name_match = re.search(r'8 \{\s+1 \{\s+1: \d+\s+2: "([^"]+)"', decoded)
        
        if not (platoon_id_match and name_match and score_match):
            return None
        
        score = int(score_match.group(1))
        
        # Filter out non-platoon records (individual player data has scores < 100000)
        if score < 100000:
            return None
        
        return {
            'platoon_id': int(platoon_id_match.group(1)),
            'name': name_match.group(1),
            'level': int(level_match.group(1)) if level_match else 0,
            'score': score,
            'mvp_id': int(mvp_id_match.group(1)) if mvp_id_match else 0,
            'mvp_name': mvp_name_match.group(1) if mvp_name_match else ''
        }
    except FileNotFoundError:
        return None
    except:
        return None


def decode_global_platoon_fallback(record_data: bytes) -> Optional[Dict]:
    """Fallback decoder for global platoon records."""
    try:
        # First get platoon ID (field 1, tag 0x08)
        platoon_id = None
        if record_data[0] == 0x08:
            platoon_id, next_pos = decode_varint(record_data, 1)
        
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
                    
                    if name and platoon_id:
                        return {
                            'platoon_id': platoon_id,
                            'name': name,
                            'level': level,
                            'score': score,
                            'mvp_id': 0,  # Fallback can't easily extract nested MVP
                            'mvp_name': ''
                        }
        return None
    except:
        return None


class GFL2ScoreSniffer:
    """Main sniffer class that captures and processes GFL2 traffic."""
    
    def __init__(self, output_file: str = 'gfl2_scores.csv', verbose: bool = False):
        self.output_file = output_file  # Append log
        self.current_state_file = output_file.replace('.csv', '_current.csv')
        self.global_output_file = output_file.replace('.csv', '_global_platoons.csv')
        self.global_current_file = output_file.replace('.csv', '_global_platoons_current.csv')
        self.verbose = verbose
        self.reassembler = TCPStreamReassembler()
        self.buffer = bytearray()
        self.last_process_time = datetime.now()
        
        # In-memory state for current scores (keyed by player/platoon name)
        self.player_scores: Dict[str, Dict] = {}
        self.platoon_scores: Dict[str, Dict] = {}
        
        # Check if protoc is available
        self.has_protoc = self._check_protoc()
        if not self.has_protoc:
            print("Note: protoc not found, using fallback decoder")
        
        # Initialize append log files with headers if they don't exist
        if not os.path.exists(output_file):
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'name', 'platoon', 'high_score', 'total_score'])
        
        if not os.path.exists(self.global_output_file):
            with open(self.global_output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'platoon_id', 'platoon_name', 'level', 'score', 'mvp_id', 'mvp_name'])
        
        # Load existing current state files if they exist
        self._load_current_state()
    
    def _load_current_state(self):
        """Load existing current state files if they exist."""
        # Load player scores
        if os.path.exists(self.current_state_file):
            try:
                with open(self.current_state_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        self.player_scores[row['name']] = {
                            'name': row['name'],
                            'platoon': row['platoon'],
                            'high_score': int(row['high_score']),
                            'total_score': int(row['total_score'])
                        }
                print(f"Loaded {len(self.player_scores)} existing player records from {self.current_state_file}")
            except Exception as e:
                print(f"Warning: Could not load {self.current_state_file}: {e}")
        
        # Load platoon scores
        if os.path.exists(self.global_current_file):
            try:
                with open(self.global_current_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        platoon_id = int(row['platoon_id'])
                        self.platoon_scores[platoon_id] = {
                            'platoon_id': platoon_id,
                            'name': row['platoon_name'],
                            'level': int(row['level']),
                            'score': int(row['score']),
                            'mvp_id': int(row['mvp_id']) if row.get('mvp_id') else 0,
                            'mvp_name': row.get('mvp_name', '')
                        }
                print(f"Loaded {len(self.platoon_scores)} existing platoon records from {self.global_current_file}")
            except Exception as e:
                print(f"Warning: Could not load {self.global_current_file}: {e}")
    
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
        updated_records = []
        for record in records:
            name = record['name']
            if name in self.player_scores:
                # Check if score changed
                old = self.player_scores[name]
                if old['high_score'] != record['high_score'] or old['total_score'] != record['total_score']:
                    updated_records.append(record)
                    self.player_scores[name] = record
            else:
                new_records.append(record)
                self.player_scores[name] = record
        
        # Append all incoming records to log (unsorted)
        all_player_records = new_records + updated_records
        if all_player_records:
            self._append_to_log(all_player_records, timestamp)
            self._save_current_player_state()
            
            print(f"\n[{timestamp}] Player scores: {len(new_records)} new, {len(updated_records)} updated")
            for r in all_player_records[:10]:
                status = "NEW" if r in new_records else "UPD"
                print(f"  [{status}] {r['name']:20s} {r['platoon']:20s} High:{r['high_score']:6d} Total:{r['total_score']:7d}")
            if len(all_player_records) > 10:
                print(f"  ... and {len(all_player_records) - 10} more")
        
        # Try to extract global platoon records
        platoon_records = extract_global_platoon_records(data, use_protoc=self.has_protoc)
        
        new_platoons = []
        updated_platoons = []
        for record in platoon_records:
            platoon_id = record['platoon_id']
            if platoon_id in self.platoon_scores:
                old = self.platoon_scores[platoon_id]
                if (old['score'] != record['score'] or old['level'] != record['level'] 
                    or old['name'] != record['name'] or old['mvp_id'] != record['mvp_id']):
                    updated_platoons.append(record)
                    self.platoon_scores[platoon_id] = record
            else:
                new_platoons.append(record)
                self.platoon_scores[platoon_id] = record
        
        all_platoon_records = new_platoons + updated_platoons
        if all_platoon_records:
            self._append_global_to_log(all_platoon_records, timestamp)
            self._save_current_platoon_state()
            
            print(f"\n[{timestamp}] Global platoons: {len(new_platoons)} new, {len(updated_platoons)} updated")
            for r in sorted(all_platoon_records, key=lambda x: x['score'], reverse=True)[:10]:
                status = "NEW" if r in new_platoons else "UPD"
                print(f"  [{status}] {r['platoon_id']:6d} {r['name']:30s} Lv:{r['level']:2d} Score:{r['score']:10d} MVP:{r['mvp_name']}")
            if len(all_platoon_records) > 10:
                print(f"  ... and {len(all_platoon_records) - 10} more")
        
        # Clear buffer after processing
        self.buffer.clear()
    
    def _append_to_log(self, records: List[Dict], timestamp: str):
        """Append records to the log CSV file (unsorted)."""
        with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for r in records:
                writer.writerow([timestamp, r['name'], r['platoon'], r['high_score'], r['total_score']])
    
    def _append_global_to_log(self, records: List[Dict], timestamp: str):
        """Append global platoon records to the log CSV file."""
        with open(self.global_output_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            for r in records:
                writer.writerow([timestamp, r['platoon_id'], r['name'], r['level'], r['score'], r['mvp_id'], r['mvp_name']])
    
    def _save_current_player_state(self):
        """Save current player state to file (sorted alphabetically)."""
        sorted_players = sorted(self.player_scores.values(), key=lambda x: x['name'].lower())
        with open(self.current_state_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['name', 'platoon', 'high_score', 'total_score'])
            for r in sorted_players:
                writer.writerow([r['name'], r['platoon'], r['high_score'], r['total_score']])
    
    def _save_current_platoon_state(self):
        """Save current platoon state to file (sorted by score descending)."""
        sorted_platoons = sorted(self.platoon_scores.values(), key=lambda x: x['score'], reverse=True)
        with open(self.global_current_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['platoon_id', 'platoon_name', 'level', 'score', 'mvp_id', 'mvp_name'])
            for r in sorted_platoons:
                writer.writerow([r['platoon_id'], r['name'], r['level'], r['score'], r['mvp_id'], r['mvp_name']])
    
    def start(self, interface: Optional[str] = None):
        """Start sniffing for GFL2 traffic."""
        # Build filter for GFL2 traffic
        bpf_filter = f"tcp port {GFL2_PORT}"
        
        print("=" * 60)
        print("GFL2 Platoon Score Auto-Sniffer")
        print("=" * 60)
        print("Output files:")
        print(f"  Player log (append):    {self.output_file}")
        print(f"  Player current (A-Z):   {self.current_state_file}")
        print(f"  Platoon log (append):   {self.global_output_file}")
        print(f"  Platoon current (rank): {self.global_current_file}")
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
