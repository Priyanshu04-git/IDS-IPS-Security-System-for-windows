#!/usr/bin/env python3
"""
Simulate Network Activity to Test Threat Detection
Creates some network connections that might trigger threat detection
"""

import socket
import time
import threading
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_port_scan_simulation():
    """Simulate port scanning activity"""
    print("🔍 Simulating port scan activity...")
    
    # Try to connect to various ports on localhost (this will trigger suspicious port detection)
    suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389]  # These are flagged as suspicious
    
    for port in suspicious_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            print(f"   Tested port {port}: {'Open' if result == 0 else 'Closed/Filtered'}")
        except Exception as e:
            print(f"   Port {port}: Error - {e}")
    
    time.sleep(1)

def test_multiple_connections():
    """Create multiple connections to trigger connection count detection"""
    print("🔍 Creating multiple connections to trigger detection...")
    
    def make_connection(target):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex(target)
            time.sleep(0.5)  # Keep connection briefly
            sock.close()
        except:
            pass
    
    # Create multiple connections (this should trigger "Multiple Connections" detection)
    targets = [
        ('8.8.8.8', 53),      # Google DNS
        ('1.1.1.1', 53),      # Cloudflare DNS
        ('127.0.0.1', 80),    # Localhost
        ('127.0.0.1', 443),   # Localhost HTTPS
    ]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        for _ in range(15):  # Create 15 connections to trigger the threshold
            for target in targets:
                executor.submit(make_connection, target)
    
    time.sleep(2)

def test_threat_detection():
    """Run the threat detection test after creating suspicious activity"""
    print("\n🔍 Running threat detection after suspicious activity...")
    
    try:
        from real_data_collector import get_current_data
        
        data = get_current_data()
        threats = data.get('threats', [])
        
        print(f"🚨 Threats detected: {len(threats)}")
        
        if threats:
            print("   Active Threats:")
            for i, threat in enumerate(threats, 1):
                print(f"   {i}. [{threat.get('severity', 'UNKNOWN')}] {threat.get('threat_type', 'Unknown')} from {threat.get('source_ip', 'Unknown IP')}")
        else:
            print("   ℹ️  No threats detected yet (this is normal for a clean system)")
            
        return len(threats)
        
    except Exception as e:
        print(f"❌ Error testing threat detection: {e}")
        return 0

def main():
    print("🔍 IDS/IPS Threat Detection Trigger Test")
    print("=" * 60)
    print("📝 This test creates network activity that should trigger threat detection")
    print("⚠️  This is for testing purposes only on localhost")
    print()
    
    # Baseline check
    print("📊 Baseline threat check...")
    baseline_threats = test_threat_detection()
    print()
    
    # Run suspicious activities
    test_port_scan_simulation()
    print()
    
    test_multiple_connections()
    print()
    
    # Check for new threats
    print("🔍 Checking for newly detected threats...")
    final_threats = test_threat_detection()
    
    print("\n" + "=" * 60)
    print(f"📊 Summary:")
    print(f"   Baseline threats: {baseline_threats}")
    print(f"   Final threats: {final_threats}")
    print(f"   New threats detected: {final_threats - baseline_threats}")
    
    if final_threats > baseline_threats:
        print("✅ Threat detection is working! New threats were detected.")
    else:
        print("ℹ️  No new threats detected. This could mean:")
        print("   - Your system is secure and activity wasn't flagged as suspicious")
        print("   - The detection thresholds weren't met")
        print("   - The system is filtering out localhost connections as safe")
    
    print("\n🔍 Test completed")

if __name__ == "__main__":
    main()
