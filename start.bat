@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

where python >nul 2>nul
if not errorlevel 1 python -c "import sys; assert sys.version_info.major == 3" >nul 2>nul
if not errorlevel 1 (
    set "PYTHON=python"
) else (
    where py >nul 2>nul
    if errorlevel 1 goto :python_missing
    py -3 -c "import sys" >nul 2>nul
    if errorlevel 1 goto :python_missing
    set "PYTHON=py -3"
)

%PYTHON% -c "import requests, yaml, rich" >nul 2>nul
if errorlevel 1 (
    echo Installing Python dependencies...
    %PYTHON% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Failed to install Python dependencies.
        exit /b 1
    )
)

if "%~1"=="" (
    set /p "CTF_URL=Enter the authorized CTF challenge URL: "
) else (
    set "CTF_URL=%~1"
)
if "%CTF_URL%"=="" (
    echo No challenge URL supplied.
    exit /b 1
)

if "%~2"=="" (
    %PYTHON% ctf_agent.py "%CTF_URL%"
) else (
    %PYTHON% ctf_agent.py "%CTF_URL%" "%~2"
)
exit /b %errorlevel%

:python_missing
echo Python 3 was not found. Install Python 3 from https://www.python.org/downloads/windows/
echo During installation, select "Add python.exe to PATH".
exit /b 1
