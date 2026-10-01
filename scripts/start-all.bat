@echo off
title SPAIDER AI Platform Launcher
echo ========================================================
echo   SPAIDER - AI Cybersecurity Command Platform
echo   RED * BLUE * PURPLE
echo ========================================================
echo.
echo Starting SPAIDER Backend (FastAPI on http://localhost:8001)...
start "SPAIDER Backend" cmd /k "cd backend && python -m uvicorn app.main:app --port 8001 --reload"

timeout /t 2 /nobreak >nul

echo Starting SPAIDER Frontend (Vite on http://localhost:3000)...
start "SPAIDER Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo [OK] Both servers are starting!
echo Frontend: http://localhost:3000
echo Backend API Docs: http://localhost:8001/api/docs
echo.
pause
