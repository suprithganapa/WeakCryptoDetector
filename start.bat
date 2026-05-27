@echo off
title WeakCryptoDetector - Web UI
echo =====================================================
echo   WeakCryptoDetector  -  Starting Web UI
echo =====================================================
echo.

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found. Install from https://python.org
    pause & exit /b 1
)

echo [INFO] Installing Flask if needed...
python -m pip install flask --quiet

echo [INFO] Starting server at http://localhost:5000
echo [INFO] Browser will open automatically...
echo.
echo Press Ctrl+C to stop the server.
echo.

python server.py
pause
