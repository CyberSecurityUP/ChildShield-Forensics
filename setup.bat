@echo off
REM ChildShield Forensics – quick setup wrapper (Windows CMD)
REM Usage: setup.bat [PYTHON_VERSION]
REM Example: setup.bat 3.11.9

setlocal
set PYVER=%1
if "%PYVER%"=="" set PYVER=3.11.9

REM Call the PowerShell script to do the real work:
powershell -ExecutionPolicy Bypass -File "%~dp0setup.ps1" -PythonVersion %PYVER% -Build

if %ERRORLEVEL% NEQ 0 (
  echo.
  echo [!] Setup failed. Try running CMD/PowerShell as Administrator.
  exit /b 1
)

echo.
echo [OK] Setup completed.
endlocal
