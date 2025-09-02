@echo off
title IDS/IPS Demo Dashboard
color 0E

echo ================================================
echo   IDS/IPS DEMO SECURITY DASHBOARD
echo ================================================
echo.
echo Starting demo security monitoring...
echo Dashboard will be available at: http://localhost:5000
echo This is DEMO MODE with simulated data
echo.

cd /d "%~dp0app"
python web_dashboard_enhanced.py --demo

pause
