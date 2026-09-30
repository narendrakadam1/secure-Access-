# SECUREASSESS PowerShell Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       STARTING SECUREASSESS PLATFORM                  " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. Start Backend in separate window
Write-Host "[1/3] Starting Backend (FastAPI on Port 8000)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:PYTHONPATH='backend'; Set-Location '$ScriptDir'; python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

# 2. Start Frontend in separate window
Write-Host "[2/3] Starting Frontend (Vite on Port 5173)..." -ForegroundColor Green
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$ScriptDir\frontend'; npm run dev"

# 3. Open Browser
Start-Sleep -Seconds 3
Write-Host "[3/3] Opening Web UI at http://localhost:5173..." -ForegroundColor Yellow
Start-Process "http://localhost:5173"

Write-Host "`nSECUREASSESS is live!" -ForegroundColor Cyan
Write-Host "  Frontend : http://localhost:5173" -ForegroundColor White
Write-Host "  Backend  : http://localhost:8000/docs" -ForegroundColor White
