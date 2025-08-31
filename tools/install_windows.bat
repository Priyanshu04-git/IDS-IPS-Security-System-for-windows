@echo off
REM IDS/IPS System Windows Installer Script
REM This script installs the IDS/IPS system on Windows

echo ============================================
echo   IDS/IPS System Windows Installer
echo   Version: 1.0.0
echo ============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running with administrator privileges
) else (
    echo [ERROR] This installer requires administrator privileges
    echo Please run as administrator and try again
    pause
    exit /b 1
)

REM Set installation directories
set INSTALL_DIR=C:\Program Files\IDS_IPS_System
set LOG_DIR=C:\ProgramData\IDS_IPS_System\logs
set CONFIG_DIR=C:\ProgramData\IDS_IPS_System\config
set DATA_DIR=C:\ProgramData\IDS_IPS_System\data

echo [STEP] Creating installation directories...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

echo [STEP] Checking Python installation...
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Python is installed
    python --version
) else (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [STEP] Checking pip installation...
pip --version >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] pip is available
) else (
    echo [ERROR] pip is not available
    echo Please ensure pip is installed with Python
    pause
    exit /b 1
)

echo [STEP] Installing Python dependencies...
pip install --upgrade pip
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo [ERROR] Failed to install Python dependencies
    pause
    exit /b 1
)

echo [STEP] Installing additional Windows-specific dependencies...
REM Install WinPcap/Npcap for packet capture (if needed)
pip install wmi pywin32
if %errorLevel% neq 0 (
    echo [WARNING] Some Windows-specific packages may not have installed
)

echo [STEP] Copying application files...
robocopy "%~dp0" "%INSTALL_DIR%" /E /XD "__pycache__" ".git" "venv" ".venv" "node_modules" /XF "*.pyc" "*.pyo" "install.bat"
if %errorLevel% geq 8 (
    echo [ERROR] Failed to copy application files
    pause
    exit /b 1
)

echo [STEP] Copying configuration files...
if exist "%~dp0config" (
    robocopy "%~dp0config" "%CONFIG_DIR%" /E
)

echo [STEP] Setting up database...
cd /d "%INSTALL_DIR%"
python database_setup.py
if %errorLevel% neq 0 (
    echo [WARNING] Database setup may have encountered issues
)

echo [STEP] Creating Windows service configuration...
echo [Unit] > "%INSTALL_DIR%\ids_ips_service.conf"
echo Description=IDS/IPS Security Monitoring Service >> "%INSTALL_DIR%\ids_ips_service.conf"
echo [Service] >> "%INSTALL_DIR%\ids_ips_service.conf"
echo Type=simple >> "%INSTALL_DIR%\ids_ips_service.conf"
echo ExecStart=python "%INSTALL_DIR%\real_ids_engine.py" >> "%INSTALL_DIR%\ids_ips_service.conf"
echo WorkingDirectory=%INSTALL_DIR% >> "%INSTALL_DIR%\ids_ips_service.conf"
echo Restart=always >> "%INSTALL_DIR%\ids_ips_service.conf"

echo [STEP] Creating start script...
echo @echo off > "%INSTALL_DIR%\start_ids_ips.bat"
echo cd /d "%INSTALL_DIR%" >> "%INSTALL_DIR%\start_ids_ips.bat"
echo echo Starting IDS/IPS System... >> "%INSTALL_DIR%\start_ids_ips.bat"
echo python real_ids_engine.py >> "%INSTALL_DIR%\start_ids_ips.bat"
echo pause >> "%INSTALL_DIR%\start_ids_ips.bat"

echo [STEP] Creating desktop shortcut...
set SHORTCUT_PATH=%USERPROFILE%\Desktop\IDS_IPS_System.lnk
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%SHORTCUT_PATH%'); $s.TargetPath = '%INSTALL_DIR%\start_ids_ips.bat'; $s.WorkingDirectory = '%INSTALL_DIR%'; $s.Description = 'IDS/IPS Security System'; $s.Save()"

echo [STEP] Setting up Windows Firewall rules...
netsh advfirewall firewall add rule name="IDS/IPS System" dir=in action=allow protocol=TCP localport=5000
netsh advfirewall firewall add rule name="IDS/IPS System API" dir=in action=allow protocol=TCP localport=8080

echo [STEP] Creating uninstaller...
echo @echo off > "%INSTALL_DIR%\uninstall.bat"
echo echo Uninstalling IDS/IPS System... >> "%INSTALL_DIR%\uninstall.bat"
echo net stop "IDS/IPS Service" 2^>nul >> "%INSTALL_DIR%\uninstall.bat"
echo sc delete "IDS/IPS Service" 2^>nul >> "%INSTALL_DIR%\uninstall.bat"
echo rmdir /s /q "%INSTALL_DIR%" >> "%INSTALL_DIR%\uninstall.bat"
echo rmdir /s /q "%LOG_DIR%" >> "%INSTALL_DIR%\uninstall.bat"
echo rmdir /s /q "%CONFIG_DIR%" >> "%INSTALL_DIR%\uninstall.bat"
echo rmdir /s /q "%DATA_DIR%" >> "%INSTALL_DIR%\uninstall.bat"
echo del "%USERPROFILE%\Desktop\IDS_IPS_System.lnk" 2^>nul >> "%INSTALL_DIR%\uninstall.bat"
echo netsh advfirewall firewall delete rule name="IDS/IPS System" 2^>nul >> "%INSTALL_DIR%\uninstall.bat"
echo netsh advfirewall firewall delete rule name="IDS/IPS System API" 2^>nul >> "%INSTALL_DIR%\uninstall.bat"
echo echo IDS/IPS System has been uninstalled >> "%INSTALL_DIR%\uninstall.bat"
echo pause >> "%INSTALL_DIR%\uninstall.bat"

echo [STEP] Testing installation...
cd /d "%INSTALL_DIR%"
python -c "import sys; print('Python path:', sys.executable); import sqlite3; print('SQLite available'); import json; print('JSON available')"
if %errorLevel% neq 0 (
    echo [WARNING] Some components may not be working correctly
)

echo.
echo ============================================
echo   Installation Complete!
echo ============================================
echo.
echo Installation Directory: %INSTALL_DIR%
echo Logs Directory: %LOG_DIR%
echo Configuration Directory: %CONFIG_DIR%
echo.
echo To start the IDS/IPS system:
echo 1. Use the desktop shortcut "IDS_IPS_System"
echo 2. Or run: %INSTALL_DIR%\start_ids_ips.bat
echo 3. Or navigate to %INSTALL_DIR% and run: python real_ids_engine.py
echo.
echo To uninstall: Run %INSTALL_DIR%\uninstall.bat
echo.
echo Note: For packet capture functionality, you may need to install
echo Npcap from https://nmap.org/npcap/ and run as administrator.
echo.
pause
