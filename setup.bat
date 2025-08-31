@echo off
:: IDS/IPS Security System - Quick Setup Script
:: This script sets up the development environment for the IDS/IPS system

title IDS/IPS System Setup

echo ===================================================================
echo                IDS/IPS Security System - Setup
echo ===================================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    echo.
    pause
    exit /b 1
)

echo [INFO] Python installation found
python --version

:: Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Python version: %PYTHON_VERSION%

:: Create virtual environment
echo.
echo [INFO] Creating virtual environment...
if exist "venv" (
    echo [INFO] Virtual environment already exists
) else (
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [INFO] Virtual environment created successfully
)

:: Activate virtual environment
echo.
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

:: Upgrade pip
echo.
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

:: Install requirements
echo.
echo [INFO] Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install some dependencies
    echo [INFO] Continuing with available packages...
)

:: Create necessary directories
echo.
echo [INFO] Creating project directories...
if not exist "data" mkdir data
if not exist "logs" mkdir logs
if not exist "config" mkdir config

:: Copy default configuration files
echo.
echo [INFO] Setting up configuration files...
if not exist "config\integration_config.json" (
    echo {> config\integration_config.json
    echo   "system": {>> config\integration_config.json
    echo     "interface": "auto",>> config\integration_config.json
    echo     "capture_filter": "tcp or udp",>> config\integration_config.json
    echo     "log_level": "INFO">> config\integration_config.json
    echo   },>> config\integration_config.json
    echo   "detection": {>> config\integration_config.json
    echo     "signature_detection": true,>> config\integration_config.json
    echo     "anomaly_detection": true,>> config\integration_config.json
    echo     "ml_detection": true,>> config\integration_config.json
    echo     "threat_threshold": 0.7>> config\integration_config.json
    echo   },>> config\integration_config.json
    echo   "prevention": {>> config\integration_config.json
    echo     "auto_block": true,>> config\integration_config.json
    echo     "block_duration": 3600>> config\integration_config.json
    echo   }>> config\integration_config.json
    echo }>> config\integration_config.json
    echo [INFO] Created default integration_config.json
)

if not exist "config\ip_blocker_config.json" (
    echo {> config\ip_blocker_config.json
    echo   "blocking": {>> config\ip_blocker_config.json
    echo     "enabled": true,>> config\ip_blocker_config.json
    echo     "method": "firewall",>> config\ip_blocker_config.json
    echo     "whitelist": []>> config\ip_blocker_config.json
    echo   },>> config\ip_blocker_config.json
    echo   "logging": {>> config\ip_blocker_config.json
    echo     "log_blocks": true,>> config\ip_blocker_config.json
    echo     "log_file": "logs/ip_blocker.log">> config\ip_blocker_config.json
    echo   }>> config\ip_blocker_config.json
    echo }>> config\ip_blocker_config.json
    echo [INFO] Created default ip_blocker_config.json
)

:: Test installation
echo.
echo [INFO] Testing installation...
python -c "import flask, psutil, scapy; print('[SUCCESS] Core dependencies imported successfully')" 2>nul
if errorlevel 1 (
    echo [WARNING] Some dependencies may not be working correctly
    echo [INFO] You can still use the portable deployment in deployments/portable/
)

:: Check if running as administrator
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo [WARNING] Not running as Administrator
    echo [INFO] Some features may require Administrator privileges
    echo [INFO] Use "Run as Administrator" for full functionality
)

echo.
echo ===================================================================
echo                        Setup Complete!
echo ===================================================================
echo.
echo Next steps:
echo   1. Test the system: python src/core/real_ids_engine.py
echo   2. Start web dashboard: python src/web/web_dashboard_real.py
echo   3. Or use portable deployment: cd deployments/portable ^&^& START_HERE.bat
echo.
echo Virtual environment is activated. To deactivate, type: deactivate
echo.
pause
