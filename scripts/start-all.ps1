# SPAIDER — Development Environment Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  SPAIDER - AI Cybersecurity Command Platform" -ForegroundColor Green
Write-Host "  RED * BLUE * PURPLE" -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Cyan

$backendPath = Join-Path $PSScriptRoot "..\backend"
$frontendPath = Join-Path $PSScriptRoot "..\frontend"

Write-Host "`n[+] Launching SPAIDER Backend on http://localhost:8001..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$backendPath'; python -m uvicorn app.main:app --port 8001 --reload"

Start-Sleep -Seconds 2

Write-Host "[+] Launching SPAIDER Frontend on http://localhost:3000..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$frontendPath'; npm run dev"

Write-Host "`n[SUCCESS] SPAIDER services initiated!" -ForegroundColor Green
Write-Host "  * Frontend UI: http://localhost:3000" -ForegroundColor White
Write-Host "  * Swagger API Docs: http://localhost:8001/api/docs" -ForegroundColor White
Write-Host "  * Default Admin: admin / admin123" -ForegroundColor White
