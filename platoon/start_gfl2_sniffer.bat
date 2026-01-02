@echo off
:: GFL2 Score Sniffer Launcher
:: Double-click this file to start capturing platoon scores
:: Results will be saved to gfl2_scores.csv in this folder

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

:: Change to script directory
cd /d "%~dp0"

:: Run the sniffer
echo ============================================================
echo GFL2 Platoon Score Sniffer
echo ============================================================
echo.
echo Starting sniffer... 
echo Open GFL2 and view platoon scores to capture data.
echo Press Ctrl+C to stop and save results.
echo.

python "%~dp0gfl2_auto_sniffer.py" -o "%~dp0gfl2_scores.csv"

if %errorLevel% neq 0 (
    echo.
    echo ============================================================
    echo ERROR: Something went wrong!
    echo.
    echo Make sure you have:
    echo   1. Python 3.7+ installed (python.org)
    echo   2. Npcap installed (npcap.com)
    echo   3. scapy installed (run: pip install scapy)
    echo ============================================================
)

pause

:: Run the sniffer
echo ============================================================
echo GFL2 Platoon Score Sniffer
echo ============================================================
echo.
echo Starting sniffer... 
echo Open GFL2 and view platoon scores to capture data.
echo Press Ctrl+C to stop and save results.
echo.

python "%~dp0gfl2_auto_sniffer.py" -o "%~dp0gfl2_scores.csv"

if %errorLevel% neq 0 (
    echo.
    echo ============================================================
    echo ERROR: Something went wrong!
    echo.
    echo Make sure you have:
    echo   1. Python 3.7+ installed (python.org)
    echo   2. Npcap installed (npcap.com)
    echo   3. scapy installed (run: pip install scapy)
    echo ============================================================
)

echo DEBUG: End of script
pause
