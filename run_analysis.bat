@echo off
:: ============================================================
::  run_analysis.bat
::  Runs the WeakCryptoDetector Pin tool against test_target.exe
::
::  Edit PIN_ROOT if Pin is not at C:\pin
::  Run from the  WeakCryptoDetector\  root folder
:: ============================================================

setlocal

set "PIN_ROOT=C:\pin"
set "TOOL=pintool\weak_crypto_detector.dll"
set "TARGET=test_target\test_target.exe"
set "REPORT=weak_crypto_report.txt"

:: ── sanity checks ──
if not exist "%PIN_ROOT%\pin.exe" (
    echo [ERROR] pin.exe not found at %PIN_ROOT%
    pause & exit /b 1
)
if not exist "%TOOL%" (
    echo [ERROR] %TOOL% not found. Build it first with pintool\build_pintool.bat
    pause & exit /b 1
)
if not exist "%TARGET%" (
    echo [ERROR] %TARGET% not found. Build it first with test_target\build_target.bat
    pause & exit /b 1
)

echo.
echo ============================================================
echo   Running WeakCryptoDetector Pin tool
echo   Tool   : %TOOL%
echo   Target : %TARGET%
echo   Report : %REPORT%
echo ============================================================
echo.

"%PIN_ROOT%\pin.exe" ^
    -t "%TOOL%" ^
    -o "%REPORT%" ^
    -- "%TARGET%"

echo.
echo ============================================================
echo   Analysis complete.  Report written to: %REPORT%
echo ============================================================
echo.

if exist "%REPORT%" (
    echo --- Contents of %REPORT% ---
    type "%REPORT%"
)

pause
endlocal
