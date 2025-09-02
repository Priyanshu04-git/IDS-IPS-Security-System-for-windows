# IDS/IPS Security System - Quick Start Guide

## 🚀 Quick Launch Options

### Option 1: Real-time Security Dashboard
```bash
# Double-click: Start_Real_Dashboard.bat
# Or run manually:
cd app
python web_dashboard_real.py
```
- Shows REAL threat data
- Monitors actual network traffic
- Realistic threat counts (0-5 typical)

### Option 2: Demo Security Dashboard  
```bash
# Double-click: Start_Demo_Dashboard.bat
# Or run manually:
cd app
python web_dashboard_enhanced.py --demo
```
- Shows SIMULATED threat data
- Educational demonstration
- High threat counts for demo purposes

### Option 3: Unified Launcher
```bash
# Double-click: IDS_IPS_Unified_Launcher.bat
```
- Interactive menu system
- Choose between real-time and demo modes
- Full system options

## 🔧 Troubleshooting

### Dashboard Not Loading?
1. Check port availability: `python port_check.py`
2. Run health check: `python health_check.py`
3. Try different browser or incognito mode

### High Threat Counts?
- Make sure you're using `web_dashboard_real.py` for real data
- `web_dashboard_enhanced.py` shows demo data with high counts

### Import Errors?
- Run: `python project_debugger.py`
- Check all required modules are installed

## 📊 Dashboard Access
- URL: http://localhost:5000
- Real-time updates every 5 seconds
- Mobile-friendly interface

## 🛡️ System Status
- Green indicators = System healthy
- Yellow indicators = Warnings
- Red indicators = Issues need attention
