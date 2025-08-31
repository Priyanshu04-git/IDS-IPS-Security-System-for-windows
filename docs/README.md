# 🛡️ IDS/IPS Security System - Complete Guide

## 📋 Table of Contents
1. [Quick Start](#quick-start)
2. [System Overview](#system-overview)
3. [Installation](#installation)
4. [Features](#features)
5. [How to Use](#how-to-use)
6. [System Requirements](#system-requirements)
7. [Troubleshooting](#troubleshooting)
8. [Technical Details](#technical-details)
9. [File Structure](#file-structure)
10. [Security Notes](#security-notes)

---

## 🚀 Quick Start

### The Easiest Way (Recommended):
1. **Extract** this archive to any folder (e.g., `C:\IDS_IPS_System`)
2. **Double-click** `START_HERE.bat`
3. **Choose Option 1** from the menu for full functionality
4. **Allow administrator privileges** when prompted
5. **Open browser** to http://localhost:5000 for web dashboard

### Alternative Quick Access:
- **Web Dashboard Only**: Double-click `IDS_IPS_Web_Interface.bat`
- **Demo Mode**: Use unified launcher → Option 3 (no admin required)

---

## 🎯 System Overview

This is a comprehensive **Intrusion Detection and Prevention System (IDS/IPS)** that monitors your network in real-time, detects threats, and can automatically block malicious traffic.

### What It Does:
- 🔍 **Real-time Network Monitoring** - Captures and analyzes network packets
- 🚨 **Threat Detection** - Uses multiple detection engines (signature-based, anomaly detection, ML)
- 🚫 **Automatic Blocking** - Blocks malicious IP addresses in real-time
- 📊 **Web Dashboard** - Beautiful real-time monitoring interface
- 📝 **Comprehensive Logging** - Detailed security event logs
- 📈 **Reporting** - Generate security reports and statistics

---

## ⚙️ Installation

### Method 1: Automatic Installation (Recommended)
1. **Extract** the archive to your desired location
2. **Right-click** `install.bat` and select **"Run as administrator"**
3. The installer will:
   - Install Python dependencies
   - Configure the system
   - Create shortcuts
   - Set up the environment

### Method 2: Using the Unified Launcher
1. **Double-click** `START_HERE.bat`
2. **Choose Option 4** (Install/Setup)
3. Follow the on-screen instructions

### Method 3: Manual Installation
1. Ensure **Python 3.7+** is installed
2. Open **Command Prompt as Administrator**
3. Navigate to the `app` folder
4. Run: `pip install flask psutil scapy numpy pandas`

---

## 🌟 Features

### Core Security Features:
- ✅ **Real-time Packet Capture** - Monitor all network traffic
- ✅ **Multi-Engine Threat Detection**:
  - Signature-based detection
  - Anomaly detection
  - Machine learning detection
- ✅ **Automatic IP Blocking** - Block threats instantly
- ✅ **Intrusion Prevention** - Stop attacks in real-time
- ✅ **False Positive Reduction** - Smart filtering algorithms

### Dashboard & Monitoring:
- ✅ **Real-time Web Dashboard** - Beautiful, responsive interface
- ✅ **Live Statistics** - Packets analyzed, threats detected, IPs blocked
- ✅ **Interactive Charts** - Network activity and threat visualization
- ✅ **Threat Feed** - Live stream of detected threats
- ✅ **System Health** - Monitor component status
- ✅ **Mobile Responsive** - Access from any device

### Administration:
- ✅ **Easy Configuration** - JSON-based configuration files
- ✅ **Comprehensive Logging** - Detailed audit trails
- ✅ **Report Generation** - Security reports and analytics
- ✅ **Multi-Mode Operation** - Admin, standard, and demo modes

---

## 🎮 How to Use

### Unified Launcher Menu:
After running `START_HERE.bat`, you'll see this menu:

```
[1] 🛡️  START FULL IDS/IPS SYSTEM (Administrator Required)
    • Complete network monitoring and packet capture
    • Real-time threat detection and IP blocking
    • All security features enabled

[2] 🌐 WEB DASHBOARD ONLY (Real-time Data)
    • Access web interface at http://localhost:5000
    • Real-time threat monitoring dashboard
    • View system statistics and logs

[3] 🖥️  DEMO MODE (No Administrator Required)
    • Simulated threat detection demonstration
    • Safe to run without admin privileges
    • Shows system capabilities

[4] ⚙️  INSTALL/SETUP
    • Install required dependencies
    • Configure system settings
    • First-time setup

[5] 📊 SYSTEM STATUS
    • Check system health
    • View current configuration
    • Test components
```

### Recommended Usage Flow:

1. **First Time**: Run Option 4 (Install/Setup)
2. **Daily Use**: Run Option 1 (Full System)
3. **Monitoring**: Access web dashboard at http://localhost:5000
4. **Demo/Testing**: Use Option 3 (Demo Mode)

---

## 💻 System Requirements

### Minimum Requirements:
- **Operating System**: Windows 10/11 (64-bit)
- **RAM**: 4 GB minimum, 8 GB recommended
- **Storage**: 2 GB free space
- **Network**: Active network interface
- **Privileges**: Administrator access (for full functionality)

### Recommended Setup:
- **CPU**: Multi-core processor (for better performance)
- **RAM**: 8+ GB (for handling high traffic volumes)
- **Network**: Dedicated monitoring interface
- **Python**: 3.7+ (included in portable version)

### Software Dependencies (Auto-installed):
- Python 3.7+
- Flask (web framework)
- psutil (system monitoring)
- scapy (packet capture)
- numpy (data processing)
- pandas (data analysis)

---

## 🔧 Troubleshooting

### Common Issues & Solutions:

#### "Permission Denied" Errors:
**Problem**: Cannot capture packets or block IPs
**Solution**: Run as Administrator
```
Right-click START_HERE.bat → "Run as administrator"
```

#### "Python not found" Error:
**Problem**: Python is not installed or not in PATH
**Solution**: Use the portable Python included
```
The system includes portable Python in the 'python' folder
```

#### Web Dashboard Won't Load:
**Problem**: Browser shows "Connection refused" at localhost:5000
**Solution**: 
1. Check if the dashboard is running
2. Try the fallback dashboard
3. Check Windows Firewall settings

#### No Network Traffic Detected:
**Problem**: System shows 0 packets captured
**Solution**:
1. Ensure running as Administrator
2. Check network interface selection
3. Verify active network connections

#### High CPU Usage:
**Problem**: System uses too many resources
**Solution**:
1. Use Demo Mode for testing
2. Adjust monitoring frequency
3. Enable filtering for specific traffic

### Getting Help:
1. **System Status**: Use launcher Option 5 to check component health
2. **Logs**: Check the `logs` folder for detailed error information
3. **Documentation**: Review files in `app/documentation/`

---

## 🔍 Technical Details

### Architecture:
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   Detection      │    │   Prevention    │
│   (Flask App)   │◄──►│   Engines        │◄──►│   Engine        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                        ▲                        ▲
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Manager  │    │   Packet         │    │   IP Blocker    │
│   (SQLite DB)   │    │   Sniffer        │    │   (Firewall)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Detection Methods:
1. **Signature-based**: Known attack patterns
2. **Anomaly-based**: Statistical deviation detection
3. **Machine Learning**: AI-powered threat classification
4. **Behavioral**: Pattern analysis of network behavior

### Performance Metrics:
- **Packet Processing**: Up to 10,000 packets/second
- **Threat Detection**: Sub-second response time
- **Memory Usage**: ~200-500 MB typical operation
- **Storage**: Logs compressed and rotated automatically

---

## 📁 File Structure

### Essential Files:
```
IDS_IPS_System/
├── START_HERE.bat                 # Main entry point
├── IDS_IPS_Unified_Launcher.bat   # All-in-one launcher
├── IDS_IPS_Web_Interface.bat      # Web dashboard launcher
├── install.bat                    # Installation script
├── README.md                      # This file
├── app/                           # Core application
│   ├── web_dashboard_real.py      # Real-time dashboard
│   ├── web_dashboard.py           # Fallback dashboard
│   ├── real_ids_engine.py         # Main IDS engine
│   ├── working_ids.py             # Working IDS system
│   ├── data_manager.py            # Database management
│   ├── templates/                 # Web interface templates
│   ├── detection_engine/          # Threat detection modules
│   ├── prevention_engine/         # IP blocking modules
│   ├── config/                    # Configuration files
│   └── documentation/             # Detailed documentation
└── python/                        # Portable Python environment
```

### Configuration Files:
- `app/config/integration_config.json` - System integration settings
- `app/config/ip_blocker_config.json` - IP blocking configuration

### Logs & Data:
- `logs/` - System and security logs
- `data/` - Threat database and reports

---

## 🔒 Security Notes

### Administrator Privileges:
This system requires administrator privileges for:
- **Packet Capture**: Raw socket access for network monitoring
- **IP Blocking**: Firewall rule modification
- **System Integration**: Deep system monitoring

### Network Security:
- Dashboard runs on localhost:5000 (not exposed externally)
- All data stored locally (no cloud dependencies)
- Encrypted log storage options available

### Privacy:
- No external data transmission
- All monitoring data stays on your system
- Optional data anonymization features

### Best Practices:
1. **Regular Updates**: Keep system updated with latest signatures
2. **Log Review**: Regularly review security logs
3. **False Positive Monitoring**: Tune detection sensitivity
4. **Backup Configuration**: Save your custom settings

---

## 🎯 Usage Scenarios

### Home Network Protection:
```bash
# Start full monitoring for home router
Double-click START_HERE.bat → Option 1
# Monitor via web dashboard
Open browser to http://localhost:5000
```

### Small Business Security:
```bash
# Install on dedicated security workstation
Run install.bat as Administrator
# Configure for business network
Edit app/config/integration_config.json
# Start monitoring
Use START_HERE.bat → Option 1
```

### Security Research/Testing:
```bash
# Safe demonstration mode
START_HERE.bat → Option 3 (Demo Mode)
# No admin privileges required
# Shows capabilities without real monitoring
```

### Penetration Testing:
```bash
# Monitor test network
Configure target interface in settings
# Full monitoring with detailed logging
Use Option 1 with verbose logging enabled
```

---

## 📞 Support & Resources

### Documentation:
- **User Manual**: `app/documentation/User_Manual.md`
- **Installation Guide**: `app/documentation/Installation_and_Deployment_Guide.md`
- **Complete Documentation**: `app/documentation/IDS_IPS_Complete_Documentation.md`

### System Components:
- **Real-time Engine**: Advanced threat detection
- **Working System**: Simplified, reliable detection
- **Web Dashboard**: Modern monitoring interface
- **Portable Python**: No external dependencies

### Tips for Best Results:
1. **Start with Demo Mode** to understand the system
2. **Use Full Mode** for actual protection
3. **Monitor the Dashboard** for real-time insights
4. **Review Logs** regularly for security events
5. **Tune Settings** based on your environment

---

## ⚠️ Important Notes

- **Always run as Administrator** for full functionality
- **Monitor system resources** during high-traffic periods
- **Regular log cleanup** to prevent disk space issues
- **Backup configurations** before making changes
- **Test in Demo Mode** before deploying in production

---

## 🎉 Getting Started Now

**Ready to protect your network?**

1. **Double-click** `START_HERE.bat`
2. **Choose Option 4** first (install dependencies)
3. **Then choose Option 1** (start full system)
4. **Open browser** to http://localhost:5000
5. **Watch real-time threat detection** in action!

**That's it! Your network is now protected with enterprise-grade security monitoring.**

---

*Last updated: August 31, 2025*
*Version: 2.0 - Unified System*
