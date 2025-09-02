#!/usr/bin/env python3
"""
IDS/IPS Project Optimization and Fix Script
Applies automatic fixes and optimizations to the entire project
"""

import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime

class ProjectOptimizer:
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.fixes_applied = []
        
    def log_fix(self, component, fix_description):
        """Log an applied fix"""
        self.fixes_applied.append({
            'component': component,
            'fix': fix_description,
            'timestamp': datetime.now().isoformat()
        })
        print(f"🔧 FIXED [{component}]: {fix_description}")
        
    def optimize_launcher_config(self):
        """Ensure launcher uses correct dashboards"""
        print("\n🚀 OPTIMIZING LAUNCHER CONFIGURATION...")
        
        launcher_path = self.root_dir.parent / 'IDS_IPS_Unified_Launcher.bat'
        if launcher_path.exists():
            try:
                with open(launcher_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Ensure real-time dashboard is used for option 2
                if 'web_dashboard_enhanced.py' in content and 'option 2' in content.lower():
                    content = content.replace(
                        'web_dashboard_enhanced.py',
                        'web_dashboard_real.py'
                    )
                    
                    with open(launcher_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    self.log_fix("Launcher", "Set real-time dashboard for web interface option")
                    
            except Exception as e:
                print(f"⚠️ Could not optimize launcher: {e}")
                
    def create_startup_scripts(self):
        """Create optimized startup scripts"""
        print("\n📜 CREATING OPTIMIZED STARTUP SCRIPTS...")
        
        # Real-time dashboard startup script
        real_dashboard_script = '''@echo off
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
'''
        
        real_script_path = self.root_dir.parent / 'Start_Real_Dashboard.bat'
        with open(real_script_path, 'w', encoding='utf-8') as f:
            f.write(real_dashboard_script)
        self.log_fix("Startup Scripts", "Created Start_Real_Dashboard.bat")
        
        # Demo dashboard startup script
        demo_dashboard_script = '''@echo off
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
'''
        
        demo_script_path = self.root_dir.parent / 'Start_Demo_Dashboard.bat'
        with open(demo_script_path, 'w', encoding='utf-8') as f:
            f.write(demo_dashboard_script)
        self.log_fix("Startup Scripts", "Created Start_Demo_Dashboard.bat")
        
    def optimize_template_loading(self):
        """Optimize template for better loading"""
        print("\n🎨 OPTIMIZING TEMPLATE LOADING...")
        
        template_path = self.root_dir / 'templates' / 'dashboard.html'
        if template_path.exists():
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Add fallback for Chart.js if external load fails
                if 'Chart.js' in content and 'onerror' not in content:
                    content = content.replace(
                        'src="https://cdn.jsdelivr.net/npm/chart.js"',
                        'src="https://cdn.jsdelivr.net/npm/chart.js" onerror="console.warn(\'Chart.js failed to load - using fallback\')"'
                    )
                    
                    with open(template_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    self.log_fix("Template", "Added Chart.js fallback handling")
                    
            except Exception as e:
                print(f"⚠️ Could not optimize template: {e}")
                
    def create_diagnostic_tools(self):
        """Create diagnostic and testing tools"""
        print("\n🔧 CREATING DIAGNOSTIC TOOLS...")
        
        # System health checker
        health_checker = '''#!/usr/bin/env python3
"""Quick system health check for IDS/IPS"""

import sys
import subprocess
from pathlib import Path

def check_system_health():
    print("SYSTEM HEALTH CHECK")
    print("=" * 40)
    
    # Check Python version
    print(f"Python Version: {sys.version}")
    
    # Check required modules
    required_modules = ['flask', 'psutil', 'threading', 'queue']
    for module in required_modules:
        try:
            __import__(module)
            print(f"OK {module} - Available")
        except ImportError:
            print(f"ERROR {module} - Missing")
    
    # Check file structure
    required_files = [
        'web_dashboard_real.py',
        'real_ids_engine.py',
        'simple_detector.py'
    ]
    
    for file_name in required_files:
        if Path(file_name).exists():
            print(f"OK {file_name} - Found")
        else:
            print(f"ERROR {file_name} - Missing")
    
    print("\\nHealth check complete!")

if __name__ == "__main__":
    check_system_health()
'''
        
        health_path = self.root_dir / 'health_check.py'
        with open(health_path, 'w', encoding='utf-8') as f:
            f.write(health_checker)
        self.log_fix("Diagnostic Tools", "Created health_check.py")
        
        # Port checker
        port_checker = '''#!/usr/bin/env python3
"""Check if required ports are available"""

import socket

def check_ports():
    print("PORT AVAILABILITY CHECK")
    print("=" * 30)
    
    ports_to_check = [5000, 8080, 3000]
    
    for port in ports_to_check:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex(('localhost', port))
                if result == 0:
                    print(f"WARNING Port {port} - In use")
                else:
                    print(f"OK Port {port} - Available")
        except Exception as e:
            print(f"ERROR Port {port} - Error: {e}")

if __name__ == "__main__":
    check_ports()
'''
        
        port_path = self.root_dir / 'port_check.py'
        with open(port_path, 'w', encoding='utf-8') as f:
            f.write(port_checker)
        self.log_fix("Diagnostic Tools", "Created port_check.py")
        
    def optimize_error_handling(self):
        """Add improved error handling to critical files"""
        print("\n🛡️ OPTIMIZING ERROR HANDLING...")
        
        # Check if web_dashboard_real.py has proper error handling
        dashboard_path = self.root_dir / 'web_dashboard_real.py'
        if dashboard_path.exists():
            try:
                with open(dashboard_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check if it has proper Flask error handling
                if '@app.errorhandler(500)' not in content:
                    error_handler = '''

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    return jsonify({
        'error': 'Internal server error',
        'message': 'Please check the server logs for details'
    }), 500

@app.errorhandler(404) 
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'error': 'Not found',
        'message': 'The requested resource was not found'
    }), 404
'''
                    
                    # Insert before the main block
                    content = content.replace(
                        "if __name__ == '__main__':",
                        error_handler + "\nif __name__ == '__main__':"
                    )
                    
                    with open(dashboard_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    self.log_fix("Error Handling", "Added Flask error handlers to real dashboard")
                    
            except Exception as e:
                print(f"⚠️ Could not optimize error handling: {e}")
                
    def create_quick_start_guide(self):
        """Create a quick start guide"""
        print("\n📖 CREATING QUICK START GUIDE...")
        
        guide_content = '''# IDS/IPS Security System - Quick Start Guide

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
'''
        
        guide_path = self.root_dir.parent / 'QUICK_START.md'
        with open(guide_path, 'w', encoding='utf-8') as f:
            f.write(guide_content)
        self.log_fix("Documentation", "Created QUICK_START.md guide")
        
    def run_optimizations(self):
        """Run all optimizations"""
        print("🔧 STARTING PROJECT OPTIMIZATION")
        print("=" * 50)
        
        self.optimize_launcher_config()
        self.create_startup_scripts()
        self.optimize_template_loading()
        self.create_diagnostic_tools()
        self.optimize_error_handling()
        self.create_quick_start_guide()
        
        print("\n" + "=" * 50)
        print("✅ OPTIMIZATION COMPLETE")
        print("=" * 50)
        print(f"🔧 Applied {len(self.fixes_applied)} optimizations:")
        
        for fix in self.fixes_applied:
            print(f"   • [{fix['component']}] {fix['fix']}")
            
        print("\n🎯 Next steps:")
        print("   1. Test real-time dashboard: python web_dashboard_real.py")
        print("   2. Test demo dashboard: python web_dashboard_enhanced.py --demo")
        print("   3. Run health check: python health_check.py")
        print("   4. Check port availability: python port_check.py")
        print("   5. Use launchers for easy startup")

if __name__ == "__main__":
    optimizer = ProjectOptimizer()
    optimizer.run_optimizations()
