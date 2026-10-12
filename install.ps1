# =============================================================================
#  SPAIDER Windows Automatic Installer
#  AI-Powered Cybersecurity Command Platform — RED · BLUE · PURPLE
# =============================================================================

$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  SPAIDER - Automated Windows Installation" -ForegroundColor Green
Write-Host "  RED * BLUE * PURPLE" -ForegroundColor Magenta
Write-Host "========================================================" -ForegroundColor Cyan

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RootDir

$BinDir = Join-Path $RootDir "bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

# 1. Check Python
Write-Host ""
Write-Host "[*] Step 1: Checking Python environment..." -ForegroundColor Cyan
$pythonFound = $false
try {
    $pyVer = python --version 2>&1
    Write-Host "[OK] Python detected: $pyVer" -ForegroundColor Green
    $pythonFound = $true
} catch {
    Write-Host "[!] 'python' command not found directly. Checking 'py' launcher..." -ForegroundColor Yellow
    try {
        $pyVer = py -3 --version 2>&1
        Write-Host "[OK] Python launcher detected: $pyVer" -ForegroundColor Green
        $pythonFound = $true
    } catch {
        Write-Host "[ERROR] Python 3 is not installed or not in PATH." -ForegroundColor Red
        Write-Host "Please install Python 3.10+ from https://www.python.org/downloads/" -ForegroundColor Yellow
        exit 1
    }
}

# 2. Check Node.js and npm
Write-Host ""
Write-Host "[*] Step 2: Checking Node.js and npm..." -ForegroundColor Cyan
try {
    $npmVer = npm --version 2>&1
    Write-Host "[OK] npm detected: v$npmVer" -ForegroundColor Green
} catch {
    Write-Host "[!] Node.js/npm not detected in PATH." -ForegroundColor Yellow
    Write-Host "    Frontend requires Node.js from https://nodejs.org/" -ForegroundColor Yellow
}

# 3. Install Nuclei (Web Security Scanner)
Write-Host ""
Write-Host "[*] Step 3: Checking / Installing Nuclei Web Vulnerability Scanner..." -ForegroundColor Cyan
$nucleiPath = Join-Path $BinDir "nuclei.exe"
$hasNuclei = (Test-Path $nucleiPath) -or (Get-Command nuclei -ErrorAction SilentlyContinue)

if (-not $hasNuclei) {
    Write-Host "[*] Downloading ProjectDiscovery Nuclei (v3.3.7 Windows x64)..." -ForegroundColor Yellow
    $zipPath = Join-Path $env:TEMP "nuclei_windows.zip"
    $nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_windows_amd64.zip"
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $nucleiUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $BinDir -Force
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
        Write-Host "[OK] Nuclei scanner installed into: $nucleiPath" -ForegroundColor Green
    } catch {
        Write-Host "[!] Automatic download failed: $_" -ForegroundColor Yellow
        Write-Host "    You can run: winget install ProjectDiscovery.Nuclei" -ForegroundColor Yellow
    }
} else {
    Write-Host "[OK] Nuclei scanner binary is available." -ForegroundColor Green
}

# Update templates
$targetNuclei = if (Test-Path $nucleiPath) { $nucleiPath } else { "nuclei" }
Write-Host "[*] Updating Nuclei vulnerability templates..." -ForegroundColor Cyan
try {
    Start-Process -FilePath $targetNuclei -ArgumentList "-update-templates" -NoNewWindow -Wait
    Write-Host "[OK] Nuclei templates updated." -ForegroundColor Green
} catch {
    Write-Host "[!] Template update notice: $_" -ForegroundColor Yellow
}

# 4. Check Nmap
Write-Host ""
Write-Host "[*] Step 4: Checking Nmap..." -ForegroundColor Cyan
if (Get-Command nmap -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Nmap detected in PATH." -ForegroundColor Green
} else {
    $defaultNmap = "C:\Program Files (x86)\Nmap\nmap.exe"
    if (Test-Path $defaultNmap) {
        Write-Host "[OK] Nmap detected at $defaultNmap" -ForegroundColor Green
    } else {
        Write-Host "[!] Nmap is optional for port scans. Download from: https://nmap.org/download.html" -ForegroundColor Yellow
    }
}

# 5. Virtualenv & Dependencies
Write-Host ""
Write-Host "[*] Step 5: Setting up Python virtual environment and dependencies..." -ForegroundColor Cyan
$venvDir = Join-Path $RootDir ".venv"
if (-not (Test-Path $venvDir)) {
    python -m venv $venvDir
    Write-Host "[OK] Virtual environment created at $venvDir" -ForegroundColor Green
}

$venvPip = Join-Path $venvDir "Scripts\pip.exe"
if (Test-Path $venvPip) {
    & $venvPip install --upgrade pip --quiet
    $reqFile = Join-Path $RootDir "backend\requirements.txt"
    if (Test-Path $reqFile) {
        Write-Host "[*] Installing Python packages from backend\requirements.txt..." -ForegroundColor Cyan
        & $venvPip install -r $reqFile --quiet
        Write-Host "[OK] Python packages installed." -ForegroundColor Green
    }
}

# 6. Frontend dependencies
Write-Host ""
Write-Host "[*] Step 6: Installing frontend dependencies..." -ForegroundColor Cyan
$frontendDir = Join-Path $RootDir "frontend"
if (Test-Path $frontendDir) {
    Push-Location $frontendDir
    try {
        npm install --silent
        Write-Host "[OK] Frontend packages installed." -ForegroundColor Green
    } catch {
        Write-Host "[!] npm install encountered an issue: $_" -ForegroundColor Yellow
    }
    Pop-Location
}

# 7. Environment file
Write-Host ""
Write-Host "[*] Step 7: Checking .env configuration..." -ForegroundColor Cyan
$envFile = Join-Path $RootDir ".env"
$envSample = Join-Path $RootDir ".env.example"
if (-not (Test-Path $envFile) -and (Test-Path $envSample)) {
    Copy-Item $envSample $envFile
    Write-Host "[OK] Created .env configuration file." -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================================" -ForegroundColor Green
Write-Host "  ALL INSTALLATION STEPS COMPLETED!" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
Write-Host "Launch all services in one command with:" -ForegroundColor White
Write-Host "   .\start.bat" -ForegroundColor Yellow
Write-Host "or:" -ForegroundColor White
Write-Host "   powershell -ExecutionPolicy Bypass -File .\scripts\start-all.ps1" -ForegroundColor Yellow
Write-Host "========================================================" -ForegroundColor Green
