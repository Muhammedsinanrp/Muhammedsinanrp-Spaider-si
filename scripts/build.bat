@echo off
title Building SPAIDER
echo ========================================================
echo   Building SPAIDER Frontend and Validating Backend
echo ========================================================
echo.
echo [1/2] Checking Python Backend Syntax and Mappers...
cd backend
python -c "import app.main; print('Backend validation: OK')"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Backend validation failed!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [2/2] Compiling TypeScript and Building Frontend Production Bundle...
cd ..\frontend
call npm run build
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Frontend build failed!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo ========================================================
echo   [SUCCESS] SPAIDER built successfully!
echo ========================================================
pause
