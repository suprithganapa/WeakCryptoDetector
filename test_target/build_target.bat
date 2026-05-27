@echo off
:: ============================================================
::  build_target.bat
::  Builds test_target.exe using MSVC  (x64)
::
::  Run from the  test_target\  directory,
::  or from a VS x64 Developer Command Prompt.
:: ============================================================

setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (
        `"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`
    ) do set "VS_PATH=%%i"
)

if defined VS_PATH (
    call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
    echo [INFO] VS environment activated.
) else (
    echo [WARN] Visual Studio not auto-detected.
    echo        Make sure you run from a VS x64 Developer Command Prompt.
)

echo.
echo [INFO] Compiling test_target.cpp ...

cl /nologo /EHsc /W3 /O2 ^
   test_target.cpp ^
   /link advapi32.lib bcrypt.lib ^
   /OUT:test_target.exe

if %ERRORLEVEL% == 0 (
    echo.
    echo [SUCCESS] test_target.exe built!
) else (
    echo.
    echo [FAILED]  Compilation failed.
    pause
    exit /b 1
)

endlocal
