@echo off
title SPAIDER Installer
echo Launching SPAIDER Automatic Installer...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
