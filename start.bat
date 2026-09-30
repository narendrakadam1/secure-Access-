@echo off
title SECUREASSESS Quick Launcher
echo ========================================================
echo        STARTING SECUREASSESS PLATFORM
echo ========================================================
echo.

set SCRIPT_DIR=%~dp0

echo [1/3] Launching FastAPI Backend on http://127.0.0.1:8000 ...
start "SECUREASSESS - Backend (FastAPI)" cmd /k "cd /d ""%SCRIPT_DIR%"" && set PYTHONPATH=backend&& python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

echo [2/3] Launching React Frontend on http://127.0.0.1:5173 ...
start "SECUREASSESS - Frontend (Vite)" cmd /k "cd /d ""%SCRIPT_DIR%frontend"" && npm run dev"

echo [3/3] Waiting for servers to initialize...
timeout /t 3 /nobreak >nul

echo.
echo ========================================================
echo SECUREASSESS is running!
echo   Frontend UI : http://localhost:5173
echo   Backend API : http://localhost:8000/docs
echo ========================================================
echo.
start http://localhost:5173
