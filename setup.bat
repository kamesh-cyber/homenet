@echo off
REM HomeScope one-click setup for Windows.
REM Double-click this file. It runs setup.ps1, which then asks for Administrator
REM rights, installs everything (Python deps + Npcap), and starts the dashboard.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1" %*
pause
