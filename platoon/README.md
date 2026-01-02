# GFL2 Platoon Score Auto-Sniffer

Automatically captures platoon scores from Girls' Frontline 2 while you play.
Just run the sniffer, open the platoon menu in-game, and scores are saved to CSV files.

## TLDR

Run the `start_gfl2_sniffer.bat` -> Allow everything -> Fix errors if you have them (install details below)

## Features

- **Individual Player Scores**: Captures each player's high score and total score within your platoon
- **Global Platoon Rankings**: Captures the global platoon leaderboard with platoon names, levels, and total scores
- **Auto-detection**: Automatically identifies which type of data is being viewed
- **Deduplication**: Won't save the same records twice in a session
- **Appends to CSV**: Accumulates data over multiple sessions with timestamps

## Quick Start (Windows)

### One-Time Setup

1. **Install Python 3.7+**
   - Download from https://www.python.org/downloads/
   - During install, CHECK "Add Python to PATH"

2. **Install Npcap**
   - Download from https://npcap.com/
   - During install, CHECK "Install in WinPcap API-compatible Mode"

3. **Install scapy**
   - Open Command Prompt (cmd)
   - Run: `pip install scapy`

4. **Optional: Install protoc** (improves accuracy)
   - Download from https://github.com/protocolbuffers/protobuf/releases
   - Extract and add to PATH, or just put protoc.exe in this folder

### Daily Use

1. Double-click `start_gfl2_sniffer.bat`
2. Click "Yes" if prompted for admin rights
3. Start GFL2 and open the Platoon score screen for individual scores
4. Open the global platoon leaderboard for platoon rankings
5. Scores automatically save to CSV files
6. Press Ctrl+C when done

## Output Files

### gfl2_scores.csv (Individual Player Scores)
| Column | Description |
|--------|-------------|
| timestamp | When the data was captured |
| name | Player name |
| platoon | Platoon name |
| high_score | Player's highest single match score |
| total_score | Player's total accumulated score |

### gfl2_scores_global_platoons.csv (Global Platoon Rankings)
| Column | Description |
|--------|-------------|
| timestamp | When the data was captured |
| platoon_name | Name of the platoon |
| level | Platoon level |
| score | Platoon's total score |

## Troubleshooting

**"scapy not found" or import errors**
- Make sure you're running as Administrator
- Run: `pip install scapy`
- If using Anaconda, the admin prompt may use a different Python - try: `python -m pip install scapy`

**"No packets captured" / No data appears**
- Make sure Npcap is installed with WinPcap compatibility mode
- Run as Administrator (right-click .bat → Run as administrator)
- Check that GFL2 is running on the same PC (not a different device)
- Try specifying the network interface manually (see below)

**"Permission denied"**
- Right-click the .bat file and select "Run as administrator"

**Wrong network interface**
- List available interfaces: `python gfl2_auto_sniffer.py --list-interfaces`
- Run with specific interface: `python gfl2_auto_sniffer.py -i "Your Interface Name"`

**Window closes immediately**
- Open Command Prompt as Administrator manually
- Navigate to the script folder: `cd path\to\folder`
- Run: `python gfl2_auto_sniffer.py`
- This will show any error messages

## Command Line Options

```
python gfl2_auto_sniffer.py [options]

Options:
  -o, --output FILE      Output CSV file (default: gfl2_scores.csv)
                         Global platoons will be saved to FILE_global_platoons.csv
  -i, --interface NAME   Network interface to use
  --list-interfaces      Show available interfaces
  -v, --verbose          Show detailed packet info
```

## How It Works

The game sends platoon data over TCP port 7001 using Protocol Buffers (protobuf) encoding
with varint-encoded integers. This tool:

1. Sniffs network traffic on port 7001 using scapy
2. Reassembles TCP streams to get complete messages
3. Decodes the protobuf messages to extract player/platoon data
4. Saves results to CSV files with timestamps

## Technical Details

- **Protocol**: Raw TCP on port 7001 (not HTTP/HTTPS)
- **Encoding**: Protocol Buffers with varint integers
- **Server IPs**: 47.253.x.x range (Sunborn game servers)

### Individual Player Record Structure
- Field 2: Player name
- Field 5: High score
- Field 6: Total score
- Field 13: Platoon name

### Global Platoon Record Structure
- Field 2: Platoon name
- Field 3: Level
- Field 6: Total score

## Files

- `gfl2_auto_sniffer.py` - Main Python script
- `start_gfl2_sniffer.bat` - Windows launcher (auto-requests admin)
- `gfl2_scores.csv` - Individual player scores (created automatically)
- `gfl2_scores_global_platoons.csv` - Global platoon rankings (created automatically)
- `README.md` - This file

## Requirements

- Windows 10/11 (tested), may work on Linux/Mac with modifications
- Python 3.7+
- Npcap (Windows) or libpcap (Linux/Mac)
- scapy (`pip install scapy`)
- protoc (optional, for better decoding accuracy)
