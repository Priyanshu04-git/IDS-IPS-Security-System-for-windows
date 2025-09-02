@echo off
title IDS/IPS Real-time Dashboard
color 0A

echo ================================================
echo   IDS/IPS REAL-TIME SECURITY DASHBOARD
echo ================================================
echo.
echo Starting real-time security monitoring...
echo Dashboard will be available at: http://localhost:5000
echo.

cd /d "%~dp0app"
python web_dashboard_real.py

pause
