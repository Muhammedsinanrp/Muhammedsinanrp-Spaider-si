# SPAIDER — Development Environment Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  SPAIDER - AI Cybersecurity Command Platform" -ForegroundColor Green
Write-Host "  RED * BLUE * PURPLE" -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Cyan

$RootDir = Split-Path -Parent $PSScriptRoot
$backendPath = Join-Path $RootDir "backend"
$frontendPath = Join-Path $RootDir "frontend"
$binPath = Join-Path $RootDir "bin"
$nucleiExe = Join-Path $binPath "nuclei.exe"
$venvPython = Join-Path $RootDir ".venv\Scripts\python.exe"

# 1. Auto-verify Nuclei Web Security Engine
if (-not (Test-Path $nucleiExe) -and -not (Get-Command nuclei -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Nuclei scanner not found. Downloading scanner binary for real pentesting..." -ForegroundColor Yellow
    if (-not (Test-Path $binPath)) { New-Item -ItemType Directory -Path $binPath -Force | Out-Null }
    $zipPath = Join-Path $env:TEMP "nuclei_quick.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_windows_amd64.zip" -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $binPath -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Write-Host "[✔] Nuclei engine installed to: $nucleiExe" -ForegroundColor Green
        & $nucleiExe -update-templates | Out-Null
    } catch {
        Write-Host "[!] Automatic download skipped: $_" -ForegroundColor Yellow
    }
}

# 2. Determine Python interpreter
$pythonExec = "python"
if (Test-Path $venvPython) {
    $pythonExec = $venvPython
}

# 3. Launch Backend
Write-Host "`n[+] Launching SPAIDER Backend on http://localhost:8001..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$backendPath'; & '$pythonExec' -m uvicorn app.main:app --port 8001 --reload"

Start-Sleep -Seconds 2

# 4. Launch Frontend
Write-Host "[+] Launching SPAIDER Frontend on http://localhost:3000..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$frontendPath'; npm run dev"

Write-Host "`n========================================================" -ForegroundColor Green
Write-Host "  ✔ SPAIDER services successfully initiated!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  * Web Dashboard:    http://localhost:3000" -ForegroundColor Cyan
Write-Host "  * Swagger API Docs: http://localhost:8001/api/docs" -ForegroundColor Cyan
Write-Host "  * Real Web Engine:  Nuclei template scanner active" -ForegroundColor Green
Write-Host "========================================================`n" -ForegroundColor Green
