# GFL2 Platoon Score Auto-Sniffer

Automatically captures platoon scores from Girls' Frontline 2 while you play.
Just run the sniffer, open the platoon menu in-game, and scores are saved to a CSV file.

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
3. Start GFL2 and open the Platoon score screen
4. Scores automatically save to `gfl2_scores.csv`
5. Press Ctrl+C when done

## Output Format

The CSV file contains:
- `timestamp` - When the data was captured
- `name` - Player name
- `platoon` - Platoon name
- `high_score` - Player's highest single match score
- `total_score` - Player's total accumulated score

## Troubleshooting

**"scapy not found"**
- Run: `pip install scapy`

**"No packets captured"**
- Make sure Npcap is installed with WinPcap compatibility mode
- Try running as Administrator
- Check that you're on the same network as your PC (not VPN)

**"Permission denied"**
- Right-click the .bat file and "Run as administrator"

**Wrong network interface**
- Run: `python gfl2_auto_sniffer.py --list-interfaces`
- Then: `python gfl2_auto_sniffer.py -i "Your Interface Name"`

## Command Line Options

```
python gfl2_auto_sniffer.py [options]

Options:
  -o, --output FILE      Output CSV file (default: gfl2_scores.csv)
  -i, --interface NAME   Network interface to use
  --list-interfaces      Show available interfaces
  -v, --verbose          Show detailed packet info
```

## How It Works

The game sends platoon data over TCP port 7001 using Protocol Buffers encoding.
This tool sniffs that traffic, decodes the protobuf messages, and extracts the
player names and scores.

## Files

- `gfl2_auto_sniffer.py` - Main Python script
- `start_gfl2_sniffer.bat` - Windows launcher (auto-requests admin)
- `gfl2_scores.csv` - Output file (created automatically)
- `README.md` - This file
