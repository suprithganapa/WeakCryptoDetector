@echo off
:: ============================================================
::  build_pintool.bat  –  Pin 4.2  clang-cl  Windows x64
::  Run from:  x64 Native Tools Command Prompt for VS 2026
::  From directory:  WeakCryptoDetector\pintool\
:: ============================================================

setlocal

set "PIN_ROOT=C:\pin"
set "SRC=weak_crypto_detector.cpp"
set "OUT=weak_crypto_detector.dll"
set "OBJ=weak_crypto_detector.obj"

:: ── verify pin ──
if not exist "%PIN_ROOT%\pin.exe" (
    echo [ERROR] pin.exe not found at %PIN_ROOT%
    pause & exit /b 1
)

:: ── verify clang-cl is available ──
where clang-cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] clang-cl not found on PATH.
    echo         Make sure you opened "x64 Native Tools Command Prompt for VS"
    echo         AND that "C++ Clang tools for Windows" was installed in VS.
    pause & exit /b 1
)

echo.
echo [INFO] Building %OUT% with clang-cl ...
echo [INFO] PIN_ROOT = %PIN_ROOT%
echo.

:: ── COMPILE ──
clang-cl ^
  /MT /O2 /EHsc ^
  /D_SECURE_SCL=0 ^
  /D_ITERATOR_DEBUG_LEVEL=0 ^
  /DTARGET_IA32E /DHOST_IA32E /DTARGET_WINDOWS ^
  /I"%PIN_ROOT%\source\include\pin" ^
  /I"%PIN_ROOT%\source\include\pin\gen" ^
  /I"%PIN_ROOT%\extras\cxx\include" ^
  /I"%PIN_ROOT%\extras\stlport\include" ^
  /I"%PIN_ROOT%\extras\components\include" ^
  /I"%PIN_ROOT%\extras\xed-intel64\include\xed" ^
  /Wno-everything ^
  /c %SRC% /Fo%OBJ%

if %ERRORLEVEL% neq 0 (
    echo.
    echo [FAILED] Compile step failed. Check errors above.
    pause & exit /b 1
)

echo [INFO] Compile OK. Linking ...

:: ── LINK ──
link /DLL /NODEFAULTLIB ^
  /IGNORE:4210 /IGNORE:4049 /IGNORE:4217 ^
  /ENTRY:Ptrace_DllMainCRTStartup ^
  /BASE:0xC5000000 ^
  %OBJ% ^
  "%PIN_ROOT%\intel64\lib\pin.lib" ^
  "%PIN_ROOT%\intel64\lib\xed.lib" ^
  "%PIN_ROOT%\intel64\lib-ext\c_runtime\pinvm.lib" ^
  "%PIN_ROOT%\intel64\lib-ext\crtbeginS.obj" ^
  ntdll-64.lib kernel32.lib ^
  /OUT:%OUT%

if %ERRORLEVEL% neq 0 (
    echo.
    echo [FAILED] Link step failed. Check errors above.
    pause & exit /b 1
)

echo.
echo [SUCCESS] %OUT% built successfully!
echo.

endlocal