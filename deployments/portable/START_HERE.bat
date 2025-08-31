@echo off
title IDS/IPS Security System - Quick Start
color 0A

cls
echo ================================================================
echo   IDS/IPS SECURITY SYSTEM - QUICK START
echo ================================================================
echo.
echo 🚀 Welcome to the IDS/IPS Security System!
echo.
echo This system has been simplified and consolidated.
echo All features are now available through one unified launcher.
echo.
echo ================================================================
echo.
echo Starting Unified Launcher...
timeout /t 3 >nul

REM Launch the unified launcher
call "%~dp0IDS_IPS_Unified_Launcher.bat"

exit /b 0
