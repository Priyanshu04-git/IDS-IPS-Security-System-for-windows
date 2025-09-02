#!/usr/bin/env python3
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
    
    print("\nHealth check complete!")

if __name__ == "__main__":
    check_system_health()
