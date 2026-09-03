@echo off
title Ultimate Network Packet Sniffer - Task 1
cd /d "%~dp0"

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ===================================================
    echo  Requesting Administrator privileges for Live Capture...
    echo ===================================================
    powershell -Command "Start-Process cmd -ArgumentList '/k cd /d """%~dp0""" && python sniffer.py' -Verb RunAs"
    exit /b
)

python sniffer.py
pause
