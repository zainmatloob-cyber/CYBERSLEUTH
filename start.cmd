@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=%CD%\.venv\Scripts\python.exe"
if not defined CYBERSLEUTH_PORT set "CYBERSLEUTH_PORT=8000"
set "URL=http://127.0.0.1:%CYBERSLEUTH_PORT%"

if not exist "%PYTHON%" (
    echo Creating Python 3.12 virtual environment...
    py -3.12 -m venv .venv
    if errorlevel 1 goto :python_error
)

"%PYTHON%" -m pip show fastapi >nul 2>&1
if errorlevel 1 (
    echo Installing project dependencies...
    "%PYTHON%" -m pip install -r requirements.txt
    if errorlevel 1 goto :install_error
)

rem Open the browser once the server answers its health check (gives up after 60 s).
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "for ($i = 0; $i -lt 60; $i++) { try { Invoke-WebRequest -UseBasicParsing '%URL%/healthz' -TimeoutSec 1 | Out-Null; Start-Process '%URL%'; break } catch { Start-Sleep -Seconds 1 } }"

"%PYTHON%" -m src.web --port %CYBERSLEUTH_PORT%
if errorlevel 1 goto :run_error
exit /b 0

:python_error
echo Could not create the virtual environment. Install Python 3.12 and ensure the py launcher is available.
pause
exit /b 1

:install_error
echo Dependency installation failed. Check your internet connection and try again.
pause
exit /b 1

:run_error
echo CyberSleuth could not start. Is port %CYBERSLEUTH_PORT% already in use? Set CYBERSLEUTH_PORT to use another.
pause
exit /b 1
