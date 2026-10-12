@echo off
title SPAIDER AI Cyber Platform
cd /d "%~dp0"

echo ========================================================
echo   SPAIDER - AI Cybersecurity Command Platform
echo   RED * BLUE * PURPLE
echo ========================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-all.ps1"
