@echo off
title IDS/IPS Security System - Unified Launcher
color 0A

REM ================================================================
REM   IDS/IPS SECURITY SYSTEM - UNIFIED LAUNCHER
REM   All-in-one launcher for the complete IDS/IPS system
REM ================================================================

setlocal EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
set "APP_DIR=%SCRIPT_DIR%app"

:main_menu
cls
echo ================================================================
echo   IDS/IPS SECURITY SYSTEM - UNIFIED LAUNCHER
echo ================================================================
echo.
echo Choose an option:
echo.
echo [1] 🛡️  START FULL IDS/IPS SYSTEM (Administrator Required)
echo     • Complete network monitoring and packet capture
echo     • Real-time threat detection and IP blocking
echo     • All security features enabled
echo.
echo [2] 🌐 WEB DASHBOARD ONLY (Real-time Data)
echo     • Access web interface at http://localhost:5000
echo     • Real-time threat monitoring dashboard
echo     • View system statistics and logs
echo.
echo [3] 🖥️  DEMO MODE (No Administrator Required)
echo     • Simulated threat detection demonstration
echo     • Safe to run without admin privileges
echo     • Shows system capabilities
echo.
echo [4] ⚙️  INSTALL/SETUP
echo     • Install required dependencies
echo     • Configure system settings
echo     • First-time setup
echo.
echo [5] 📊 SYSTEM STATUS
echo     • Check system health
echo     • View current configuration
echo     • Test components
echo.
echo [0] ❌ EXIT
echo.
echo ================================================================
set /p choice="Enter your choice (0-5): "

if "%choice%"=="1" goto :start_full_system
if "%choice%"=="2" goto :start_web_dashboard
if "%choice%"=="3" goto :start_demo_mode
if "%choice%"=="4" goto :install_setup
if "%choice%"=="5" goto :system_status
if "%choice%"=="0" goto :exit_program
echo Invalid choice. Please try again.
pause
goto :main_menu

REM ================================================================
REM   FULL IDS/IPS SYSTEM (Option 1)
REM ================================================================
:start_full_system
cls
echo ================================================================
echo   STARTING FULL IDS/IPS SYSTEM
echo ================================================================
echo.

REM Check if already running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Running with administrator privileges
    goto :run_full_system
)

echo ⚠️  Administrator privileges required for full system!
echo.
echo This will enable:
echo • Network packet capture and monitoring
echo • Real-time intrusion detection
echo • Automatic IP blocking and prevention
echo • All security features
echo.
echo Click "Yes" on the Windows security prompt to continue.
echo.
set /p confirm="Request administrator privileges? (y/N): "
if /i "%confirm%" neq "y" goto :main_menu

echo Requesting administrator privileges...
powershell -Command "Start-Process cmd -ArgumentList '/c cd /d \"%SCRIPT_DIR%\" && \"%~f0\" admin_mode' -Verb RunAs"
goto :exit_program

:run_full_system
echo 🚀 Starting full IDS/IPS security system...
echo.
cd /d "%APP_DIR%"

REM Set Python path for system Python
set "PYTHON_PATH=C:\Users\priya\AppData\Local\Programs\Python\Python311\python.exe"

REM Try real IDS first, then fallback to working system
echo Starting real-time IDS engine...
echo Using Python: %PYTHON_PATH%
"%PYTHON_PATH%" real_ids_engine.py
if %errorLevel% neq 0 (
    echo.
    echo ⚠️  Real IDS engine failed, trying working system...
    "%PYTHON_PATH%" working_ids.py
    if %errorLevel% neq 0 (
        echo.
        echo ⚠️  Working IDS failed, trying basic system...
        echo Running basic IDS demonstration...
        "%PYTHON_PATH%" simple_detector.py
    )
)

pause
goto :main_menu

REM ================================================================
REM   WEB DASHBOARD (Option 2)
REM ================================================================
:start_web_dashboard
cls
echo ================================================================
echo   STARTING WEB DASHBOARD - REAL-TIME MODE
echo ================================================================
echo.
echo 🔍 Starting real-time web dashboard...
echo 📊 Attempting to connect to live IDS/IPS components
echo 🌐 Dashboard will be available at: http://localhost:5000
echo.
echo Opening dashboard in browser...
timeout /t 3 >nul
start http://localhost:5000

cd /d "%APP_DIR%"
echo.
echo Launching enhanced dashboard with real-time data detection...

REM Set Python path for system Python with Flask
set "PYTHON_PATH=C:\Users\priya\AppData\Local\Programs\Python\Python311\python.exe"

REM Launch real-time dashboard (not enhanced demo)
echo Using Python: %PYTHON_PATH%
"%PYTHON_PATH%" web_dashboard_real.py

if %errorLevel% neq 0 (
    echo.
    echo ⚠️  Real-time dashboard failed, trying standard version...
    "%PYTHON_PATH%" web_dashboard.py
)

pause
goto :main_menu

REM ================================================================
REM   DEMO MODE (Option 3)
REM ================================================================
:start_demo_mode
cls
echo ================================================================
echo   DEMO MODE - THREAT DETECTION SIMULATION
echo ================================================================
echo.
echo 🎭 Starting demonstration mode...
echo • No administrator privileges required
echo • Simulated network monitoring with sample data
echo • Safe threat detection demonstration
echo • Educational overview of system capabilities
echo.
echo Choose demo option:
echo.
echo [1] 🖥️  Command Line Demo (Basic IDS simulation)
echo [2] 🌐 Web Dashboard Demo (Sample data visualization)
echo [0] ↩️  Back to main menu
echo.
set /p demo_choice="Enter your choice (0-2): "

if "%demo_choice%"=="1" goto :cli_demo
if "%demo_choice%"=="2" goto :web_demo
if "%demo_choice%"=="0" goto :main_menu
echo Invalid choice. Please try again.
pause
goto :start_demo_mode

:cli_demo
echo.
echo Starting command line IDS demonstration...
cd /d "%APP_DIR%"
set "PYTHON_PATH=C:\Users\priya\AppData\Local\Programs\Python\Python311\python.exe"
echo Using Python: %PYTHON_PATH%
"%PYTHON_PATH%" working_ids.py
pause
goto :main_menu

:web_demo
echo.
echo 🌐 Starting web dashboard in DEMO MODE...
echo 📊 Sample data simulation for demonstration
echo Dashboard will be available at: http://localhost:5000
echo.
echo Opening demo dashboard in browser...
timeout /t 3 >nul
start http://localhost:5000

cd /d "%APP_DIR%"
echo.
echo Launching demo dashboard with sample data...
set "PYTHON_PATH=C:\Users\priya\AppData\Local\Programs\Python\Python311\python.exe"
echo Using Python: %PYTHON_PATH%
"%PYTHON_PATH%" web_dashboard_real.py --demo

if %errorLevel% neq 0 (
    echo.
    echo ⚠️  Enhanced dashboard failed, trying standard version...
    python web_dashboard.py
)

pause
goto :main_menu

REM ================================================================
REM   INSTALL/SETUP (Option 4)
REM ================================================================
:install_setup
cls
echo ================================================================
echo   SYSTEM INSTALLATION AND SETUP
echo ================================================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Running with administrator privileges
) else (
    echo ⚠️  Warning: Some installation features require administrator privileges
    echo.
)

echo 🔧 Installing Python dependencies...
cd /d "%APP_DIR%"

echo Installing required packages...
python -m pip install --upgrade pip
python -m pip install flask psutil scapy numpy pandas

if %errorLevel% == 0 (
    echo ✅ Installation completed successfully!
) else (
    echo ❌ Installation encountered errors
    echo Please check your Python installation
)

echo.
pause
goto :main_menu

REM ================================================================
REM   SYSTEM STATUS (Option 5)
REM ================================================================
:system_status
cls
echo ================================================================
echo   SYSTEM STATUS AND HEALTH CHECK
echo ================================================================
echo.

echo 🔍 Checking system components...
echo.

REM Check Python
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Python: Available
    python --version
) else (
    echo ❌ Python: Not found or not in PATH
)

REM Check admin status
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Admin Rights: Available
) else (
    echo ⚠️  Admin Rights: Not running as administrator
)

REM Check if files exist
if exist "%APP_DIR%\real_ids_engine.py" (
    echo ✅ Real IDS Engine: Available
) else (
    echo ❌ Real IDS Engine: Missing
)

if exist "%APP_DIR%\working_ids.py" (
    echo ✅ Working IDS System: Available
) else (
    echo ❌ Working IDS System: Missing
)

if exist "%APP_DIR%\web_dashboard_real.py" (
    echo ✅ Real-time Dashboard: Available
) else (
    echo ❌ Real-time Dashboard: Missing
)

if exist "%APP_DIR%\web_dashboard.py" (
    echo ✅ Fallback Dashboard: Available
) else (
    echo ❌ Fallback Dashboard: Missing
)

echo.
echo 📊 System Configuration:
echo    Script Directory: %SCRIPT_DIR%
echo    App Directory: %APP_DIR%
echo    Current User: %USERNAME%
echo    Date/Time: %DATE% %TIME%

echo.
pause
goto :main_menu

REM ================================================================
REM   SPECIAL ADMIN MODE ENTRY POINT
REM ================================================================
:admin_mode_check
if "%1"=="admin_mode" goto :run_full_system
goto :main_menu

REM ================================================================
REM   EXIT
REM ================================================================
:exit_program
cls
echo ================================================================
echo   IDS/IPS SECURITY SYSTEM - SHUTDOWN
echo ================================================================
echo.
echo 👋 Thank you for using the IDS/IPS Security System!
echo.
echo System components have been stopped safely.
echo.
timeout /t 3 >nul
exit /b 0

REM Handle admin mode parameter
if "%1"=="admin_mode" goto :run_full_system
goto :main_menu
