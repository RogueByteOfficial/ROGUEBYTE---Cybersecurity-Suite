# ROGUEBYTE Installation & Launch Script for Windows 10/11
# Run in PowerShell: powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1

Write-Host "==========================================================" -ForegroundColor Green
Write-Host "     ROGUEBYTE // CYBERSECURITY WORKSTATION INSTALLER     " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green

$ErrorActionPreference = "Stop"

# Anchor to the project root directory containing app.py
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path "$ScriptDir\app.py") {
    Set-Location $ScriptDir
} elseif (Test-Path "$ScriptDir\..\app.py") {
    Set-Location (Resolve-Path "$ScriptDir\..").Path
}

Write-Host "[*] Working directory: $(Get-Location)" -ForegroundColor Gray

# 1. Verify Python Installation
Write-Host "[*] Checking Python environment..." -ForegroundColor Cyan
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Python 3.10+ was not found on PATH." -ForegroundColor Red
    Write-Host "    Please install Python 3.12 from https://www.python.org/downloads/ and check 'Add to PATH'." -ForegroundColor Yellow
    Exit 1
}

$pyVersion = python --version
Write-Host "[+] Found $pyVersion" -ForegroundColor Green

# 2. Virtual Environment Setup
$VenvDir = ".\.venv"
if (!(Test-Path $VenvDir)) {
    Write-Host "[*] Creating isolated virtual environment at $VenvDir..." -ForegroundColor Cyan
    python -m venv $VenvDir
}

Write-Host "[*] Activating virtual environment..." -ForegroundColor Cyan
$VenvPython = "$VenvDir\Scripts\python.exe"
$VenvPip = "$VenvDir\Scripts\pip.exe"

# 3. Upgrade pip and install dependencies
Write-Host "[*] Installing ROGUEBYTE dependencies from requirements.txt..." -ForegroundColor Cyan
& $VenvPip install --upgrade pip
& $VenvPip install -r requirements.txt

# Install package in editable mode so 'import roguebyte' is globally available in the venv
Write-Host "[*] Registering roguebyte package in virtual environment..." -ForegroundColor Cyan
& $VenvPip install -e .

# 4. Verify SQLite and Database initialization
Write-Host "[*] Initializing local database schema..." -ForegroundColor Cyan
& $VenvPython -c "import app; from roguebyte.database.db import get_db; db = get_db(); print('SQLite database ready.')"

# 5. Check WSL2 status
Write-Host "[*] Checking WSL2 integration status..." -ForegroundColor Cyan
if (Get-Command wsl -ErrorAction SilentlyContinue) {
    wsl -l -v
} else {
    Write-Host "[!] WSL is not yet enabled. You can enable it via: wsl --install" -ForegroundColor Yellow
}

# 6. Launch Application
Write-Host "`n[+] Installation complete! Launching ROGUEBYTE Desktop GUI..." -ForegroundColor Green
& $VenvPython app.py
