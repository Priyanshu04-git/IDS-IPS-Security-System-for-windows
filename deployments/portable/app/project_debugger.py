#!/usr/bin/env python3
"""
IDS/IPS Project-Wide Debugging Script
Comprehensive diagnostics for the entire security system
"""

import os
import sys
import json
import traceback
from pathlib import Path
from datetime import datetime
import importlib.util
import subprocess

class ProjectDebugger:
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.issues = []
        self.warnings = []
        self.success = []
        
    def log_issue(self, component, issue, details=""):
        """Log a critical issue"""
        self.issues.append({
            'component': component,
            'issue': issue,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        print(f"❌ ISSUE [{component}]: {issue}")
        if details:
            print(f"   Details: {details}")
            
    def log_warning(self, component, warning, details=""):
        """Log a warning"""
        self.warnings.append({
            'component': component,
            'warning': warning,
            'details': details,
            'timestamp': datetime.now().isoformat()
        })
        print(f"⚠️ WARNING [{component}]: {warning}")
        if details:
            print(f"   Details: {details}")
            
    def log_success(self, component, message):
        """Log a success"""
        self.success.append({
            'component': component,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
        print(f"✅ SUCCESS [{component}]: {message}")

    def check_file_structure(self):
        """Check if all required files exist"""
        print("\n🔍 CHECKING FILE STRUCTURE...")
        
        required_files = [
            'web_dashboard_real.py',
            'web_dashboard_enhanced.py', 
            'web_dashboard.py',
            'real_ids_engine.py',
            'simple_detector.py',
            'working_ids.py',
            'packet_capture/packet_sniffer.py',
            'templates/dashboard.html'
        ]
        
        for file_path in required_files:
            full_path = self.root_dir / file_path
            if full_path.exists():
                self.log_success("File Structure", f"{file_path} exists")
            else:
                self.log_issue("File Structure", f"Missing file: {file_path}")
                
    def check_python_imports(self):
        """Check if all Python modules can be imported"""
        print("\n🐍 CHECKING PYTHON IMPORTS...")
        
        modules_to_test = [
            ('flask', 'Flask web framework'),
            ('psutil', 'System monitoring'),
            ('threading', 'Multi-threading support'),
            ('queue', 'Queue management'),
            ('json', 'JSON handling'),
            ('logging', 'Logging system'),
            ('datetime', 'Date/time utilities')
        ]
        
        for module_name, description in modules_to_test:
            try:
                __import__(module_name)
                self.log_success("Python Imports", f"{module_name} - {description}")
            except ImportError as e:
                self.log_issue("Python Imports", f"Failed to import {module_name}", str(e))
                
    def check_dashboard_imports(self):
        """Check if dashboard modules can be imported"""
        print("\n📊 CHECKING DASHBOARD MODULES...")
        
        dashboard_files = [
            'web_dashboard_real.py',
            'web_dashboard_enhanced.py',
            'web_dashboard.py'
        ]
        
        for dashboard_file in dashboard_files:
            dashboard_path = self.root_dir / dashboard_file
            if dashboard_path.exists():
                try:
                    # Try to load the module spec
                    spec = importlib.util.spec_from_file_location("dashboard_test", dashboard_path)
                    if spec:
                        self.log_success("Dashboard Imports", f"{dashboard_file} can be loaded")
                    else:
                        self.log_warning("Dashboard Imports", f"{dashboard_file} spec creation failed")
                except Exception as e:
                    self.log_issue("Dashboard Imports", f"{dashboard_file} import error", str(e))
            else:
                self.log_issue("Dashboard Imports", f"{dashboard_file} not found")
                
    def check_ids_components(self):
        """Check IDS/IPS components"""
        print("\n🛡️ CHECKING IDS/IPS COMPONENTS...")
        
        components = [
            'real_ids_engine.py',
            'simple_detector.py',
            'working_ids.py'
        ]
        
        for component in components:
            component_path = self.root_dir / component
            if component_path.exists():
                try:
                    with open(component_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Check for common issues
                    if 'def __init__' in content:
                        self.log_success("IDS Components", f"{component} has __init__ method")
                    else:
                        self.log_warning("IDS Components", f"{component} missing __init__ method")
                        
                    if 'class ' in content:
                        self.log_success("IDS Components", f"{component} contains class definitions")
                    else:
                        self.log_warning("IDS Components", f"{component} no class definitions found")
                        
                except Exception as e:
                    self.log_issue("IDS Components", f"Error reading {component}", str(e))
            else:
                self.log_issue("IDS Components", f"{component} not found")
                
    def check_launcher_configuration(self):
        """Check launcher configuration"""
        print("\n🚀 CHECKING LAUNCHER CONFIGURATION...")
        
        launcher_path = self.root_dir.parent / 'IDS_IPS_Unified_Launcher.bat'
        if launcher_path.exists():
            try:
                with open(launcher_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Check which dashboard is being called
                if 'web_dashboard_real.py' in content:
                    self.log_success("Launcher Config", "Configured to use real-time dashboard")
                elif 'web_dashboard_enhanced.py' in content:
                    self.log_warning("Launcher Config", "Configured to use enhanced demo dashboard")
                else:
                    self.log_issue("Launcher Config", "No dashboard configuration found")
                    
                # Check for demo mode configuration
                if '--demo' in content:
                    self.log_success("Launcher Config", "Demo mode properly configured")
                    
            except Exception as e:
                self.log_issue("Launcher Config", "Error reading launcher", str(e))
        else:
            self.log_issue("Launcher Config", "Launcher file not found")
            
    def check_templates(self):
        """Check template files"""
        print("\n🎨 CHECKING TEMPLATES...")
        
        template_path = self.root_dir / 'templates' / 'dashboard.html'
        if template_path.exists():
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Check for essential HTML elements
                if '<html' in content:
                    self.log_success("Templates", "Valid HTML structure")
                else:
                    self.log_issue("Templates", "Invalid HTML structure")
                    
                if 'Chart.js' in content:
                    self.log_warning("Templates", "Uses external Chart.js dependency")
                    
                if 'fetch(' in content:
                    self.log_success("Templates", "Has API fetch calls")
                    
            except Exception as e:
                self.log_issue("Templates", "Error reading template", str(e))
        else:
            self.log_issue("Templates", "Dashboard template not found")
            
    def check_network_interfaces(self):
        """Check available network interfaces"""
        print("\n🌐 CHECKING NETWORK INTERFACES...")
        
        try:
            import psutil
            interfaces = psutil.net_if_addrs()
            
            if interfaces:
                self.log_success("Network", f"Found {len(interfaces)} network interfaces")
                for interface_name in list(interfaces.keys())[:3]:  # Show first 3
                    self.log_success("Network", f"Interface available: {interface_name}")
            else:
                self.log_warning("Network", "No network interfaces found")
                
        except ImportError:
            self.log_issue("Network", "psutil not available for network checking")
        except Exception as e:
            self.log_issue("Network", "Error checking network interfaces", str(e))
            
    def check_port_availability(self):
        """Check if port 5000 is available"""
        print("\n🔌 CHECKING PORT AVAILABILITY...")
        
        import socket
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                result = s.connect_ex(('localhost', 5000))
                if result == 0:
                    self.log_warning("Port Check", "Port 5000 is already in use")
                else:
                    self.log_success("Port Check", "Port 5000 is available")
        except Exception as e:
            self.log_issue("Port Check", "Error checking port availability", str(e))
            
    def generate_debug_report(self):
        """Generate a comprehensive debug report"""
        print("\n📋 GENERATING DEBUG REPORT...")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_issues': len(self.issues),
            'total_warnings': len(self.warnings),
            'total_success': len(self.success),
            'issues': self.issues,
            'warnings': self.warnings,
            'success': self.success
        }
        
        report_path = self.root_dir / 'debug_report.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
            
        self.log_success("Debug Report", f"Report saved to {report_path}")
        return report
        
    def run_full_debug(self):
        """Run all debugging checks"""
        print("🔧 STARTING COMPREHENSIVE PROJECT DEBUG")
        print("=" * 60)
        
        self.check_file_structure()
        self.check_python_imports()
        self.check_dashboard_imports()
        self.check_ids_components()
        self.check_launcher_configuration()
        self.check_templates()
        self.check_network_interfaces()
        self.check_port_availability()
        
        report = self.generate_debug_report()
        
        print("\n" + "=" * 60)
        print("🎯 DEBUG SUMMARY")
        print("=" * 60)
        print(f"✅ Successful checks: {len(self.success)}")
        print(f"⚠️ Warnings: {len(self.warnings)}")
        print(f"❌ Critical issues: {len(self.issues)}")
        
        if self.issues:
            print("\n🚨 CRITICAL ISSUES TO FIX:")
            for issue in self.issues:
                print(f"   • [{issue['component']}] {issue['issue']}")
                
        if self.warnings:
            print("\n⚠️ WARNINGS TO REVIEW:")
            for warning in self.warnings:
                print(f"   • [{warning['component']}] {warning['warning']}")
                
        print("\n🔧 Next steps:")
        if self.issues:
            print("   1. Fix critical issues first")
            print("   2. Address warnings")
            print("   3. Re-run debug to verify fixes")
        else:
            print("   • No critical issues found!")
            print("   • Review warnings if any")
            print("   • System should be operational")
            
        return report

if __name__ == "__main__":
    debugger = ProjectDebugger()
    debugger.run_full_debug()
