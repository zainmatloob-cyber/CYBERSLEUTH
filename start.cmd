@echo off
setlocal
cd /d "%~dp0"

set "PYTHON=%CD%\.venv\Scripts\python.exe"

if not exist "%PYTHON%" (
    echo Creating Python 3.12 virtual environment...
    py -3.12 -m venv .venv
    if errorlevel 1 goto :python_error
)

"%PYTHON%" -m pip show streamlit >nul 2>&1
if errorlevel 1 (
    echo Installing project dependencies...
    "%PYTHON%" -m pip install -r requirements.txt
    if errorlevel 1 goto :install_error
)

"%PYTHON%" -m streamlit run app.py --server.showEmailPrompt=false
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
echo CyberSleuth could not start.
pause
exit /b 1
