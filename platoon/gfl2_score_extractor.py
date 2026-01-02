#!/usr/bin/env python3
"""
GFL2 Platoon Score Extractor

Extracts player scores from Girls' Frontline 2 network captures.
The game uses protobuf encoding with varint fields for scores.

Usage:
    1. Capture traffic with Wireshark while viewing platoon scores
    2. Filter to the game server (typically 47.253.x.x on port 7001)
    3. Export the TCP stream: Follow -> TCP Stream -> Save As (Raw)
    4. Run: python gfl2_score_extractor.py <capture_file.bin>

Requirements:
    - Python 3.6+
    - protoc (Protocol Buffers compiler) - install via: apt install protobuf-compiler
"""

import subprocess
import tempfile
import re
import os
import sys
import csv
from typing import Dict, List, Tuple, Optional


def decode_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Decode a protobuf varint starting at position pos."""
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


def extract_player_records(data: bytes) -> List[Dict]:
    """
    Extract all player score records from the binary data.
    
    The data structure appears to be:
    - Outer message: field 1 (0x0a) with length prefix
    - Contains nested messages with player info
    - Scores are in fields 5 (high score) and 6 (total score) at the outer level
    """
    records = {}
    i = 0
    
    while i < len(data) - 5:
        # Look for message start pattern: 0x0a (field 1, length-delimited)
        if data[i] == 0x0a:
            try:
                length, content_start = decode_varint(data, i + 1)
                
                # Check for reasonable record size (player records are typically 200-500 bytes)
                if 200 <= length <= 500 and content_start < len(data) and data[content_start] == 0x0a:
                    record_end = content_start + length
                    
                    if record_end <= len(data):
                        record_data = data[content_start:record_end]
                        record = decode_player_record(record_data)
                        
                        if record and record['name'] not in records:
                            records[record['name']] = record
                            
            except Exception:
                pass
        i += 1
    
    return list(records.values())


def decode_player_record(record_data: bytes) -> Optional[Dict]:
    """Decode a single player record using protoc --decode_raw."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
        f.write(record_data)
        tmpfile = f.name
    
    try:
        result = subprocess.run(
            ['protoc', '--decode_raw'],
            stdin=open(tmpfile, 'rb'),
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode != 0:
            return None
            
        decoded = result.stdout
        
        # Check if this looks like a player record (has score fields)
        if '5:' not in decoded or '6:' not in decoded:
            return None
        
        # Extract fields using regex
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
        
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None
    finally:
        os.unlink(tmpfile)


def search_for_score(data: bytes, score: int) -> List[int]:
    """Search for a known score value in various encodings."""
    results = []
    
    # Varint encoding (this is what GFL2 uses)
    def encode_varint(n):
        result = []
        while n > 127:
            result.append((n & 0x7F) | 0x80)
            n >>= 7
        result.append(n)
        return bytes(result)
    
    pattern = encode_varint(score)
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos == -1:
            break
        results.append(('varint', pos))
        pos += 1
    
    return results


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    print(f"Reading {input_file}...")
    with open(input_file, 'rb') as f:
        data = f.read()
    
    print(f"Loaded {len(data)} bytes")
    print("Extracting player records...")
    
    records = extract_player_records(data)
    
    if not records:
        print("No player records found. Make sure you captured the correct TCP stream.")
        sys.exit(1)
    
    # Sort by total score descending
    records.sort(key=lambda x: x['total_score'], reverse=True)
    
    # Print results
    print(f"\nFound {len(records)} unique player records:\n")
    print(f"{'#':>3s} {'Name':20s} {'Platoon':20s} {'High':>7s} {'Total':>8s}")
    print("-" * 65)
    
    for idx, r in enumerate(records, 1):
        print(f"{idx:3d} {r['name']:20s} {r['platoon']:20s} {r['high_score']:7d} {r['total_score']:8d}")
    
    # Optionally save to CSV
    if len(sys.argv) >= 3 and sys.argv[2] == '--csv':
        csv_file = input_file.rsplit('.', 1)[0] + '_scores.csv'
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['name', 'platoon', 'high_score', 'total_score'])
            writer.writeheader()
            writer.writerows(records)
        print(f"\nSaved to {csv_file}")


if __name__ == '__main__':
    main()
