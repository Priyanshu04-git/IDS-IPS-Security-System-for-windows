"""
Windows-specific entry point for IDS/IPS System
This script handles Windows-specific initialization and provides a clean entry point
"""

import os
import sys
import logging
import platform
from pathlib import Path

def setup_windows_environment():
    """Setup Windows-specific environment and paths"""
    
    # Check if running on Windows
    if platform.system() != 'Windows':
        print("This script is designed for Windows systems")
        return False
    
    # Set up application directories
    app_data = Path(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'))
    app_dir = app_data / 'IDS_IPS_System'
    
    # Create directories if they don't exist
    (app_dir / 'logs').mkdir(parents=True, exist_ok=True)
    (app_dir / 'config').mkdir(parents=True, exist_ok=True)
    (app_dir / 'data').mkdir(parents=True, exist_ok=True)
    
    # Set environment variables
    os.environ['IDS_IPS_LOG_DIR'] = str(app_dir / 'logs')
    os.environ['IDS_IPS_CONFIG_DIR'] = str(app_dir / 'config')
    os.environ['IDS_IPS_DATA_DIR'] = str(app_dir / 'data')
    
    return True

def check_admin_privileges():
    """Check if running with administrator privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    """Main entry point for Windows executable"""
    
    print("IDS/IPS Security System - Windows Edition")
    print("=" * 50)
    
    # Setup Windows environment
    if not setup_windows_environment():
        input("Press Enter to exit...")
        sys.exit(1)
    
    # Check for admin privileges
    if not check_admin_privileges():
        print("WARNING: Not running as administrator!")
        print("Some features (like packet capture) may not work properly.")
        print("For full functionality, please run as administrator.")
        print()
        
        response = input("Continue anyway? (y/N): ").lower().strip()
        if response != 'y':
            sys.exit(1)
    
    # Add current directory to Python path
    current_dir = Path(__file__).parent
    sys.path.insert(0, str(current_dir))
    
    try:
        # Import and run the main IDS engine
        from real_ids_engine import RealIDSEngine, main as ids_main
        
        print("Starting IDS/IPS System...")
        print(f"Logs directory: {os.environ.get('IDS_IPS_LOG_DIR')}")
        print(f"Config directory: {os.environ.get('IDS_IPS_CONFIG_DIR')}")
        print()
        
        # Start the main application
        ids_main()
        
    except ImportError as e:
        print(f"Error importing required modules: {e}")
        print("Please ensure all dependencies are installed.")
        print("Run: pip install -r requirements.txt")
        input("Press Enter to exit...")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting IDS/IPS System: {e}")
        logging.exception("Startup error")
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()
