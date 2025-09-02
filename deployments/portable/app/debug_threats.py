#!/usr/bin/env python3
"""
Debug Threat Detection - Check what the real data collector is finding
"""

import sys
import os
import json

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from real_data_collector import RealDataCollector
    print("✅ Successfully imported RealDataCollector")
except ImportError as e:
    print(f"❌ Failed to import RealDataCollector: {e}")
    sys.exit(1)

def main():
    print("🔍 Debug: Testing Threat Detection System")
    print("=" * 50)
    
    # Initialize the data collector
    try:
        collector = RealDataCollector()
        print("✅ RealDataCollector initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize RealDataCollector: {e}")
        return
    
    # Test threat detection
    print("\n🔍 Testing threat detection...")
    try:
        threats = collector.get_threats()
        print(f"📊 Threats found: {len(threats)}")
        
        if threats:
            print("\n🚨 Active Threats:")
            for i, threat in enumerate(threats, 1):
                print(f"  {i}. {threat}")
        else:
            print("ℹ️  No threats currently detected")
            
    except Exception as e:
        print(f"❌ Error getting threats: {e}")
    
    # Test network activity
    print("\n🌐 Testing network activity detection...")
    try:
        network_activity = collector.get_network_activity()
        print(f"📊 Network activities found: {len(network_activity)}")
        
        if network_activity:
            print("\n🔗 Recent Network Activity:")
            for i, activity in enumerate(network_activity[:5], 1):  # Show first 5
                print(f"  {i}. {activity}")
        else:
            print("ℹ️  No network activity detected")
            
    except Exception as e:
        print(f"❌ Error getting network activity: {e}")
    
    # Test suspicious connection detection
    print("\n🔍 Testing suspicious connection detection...")
    try:
        suspicious = collector.detect_suspicious_connections()
        print(f"📊 Suspicious connections found: {len(suspicious)}")
        
        if suspicious:
            print("\n⚠️  Suspicious Connections:")
            for i, conn in enumerate(suspicious, 1):
                print(f"  {i}. {conn}")
        else:
            print("ℹ️  No suspicious connections detected")
            
    except Exception as e:
        print(f"❌ Error detecting suspicious connections: {e}")
    
    # Test system stats
    print("\n📊 Testing system statistics...")
    try:
        stats = collector.get_system_stats()
        print("📈 System Stats:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
            
    except Exception as e:
        print(f"❌ Error getting system stats: {e}")
    
    print("\n" + "=" * 50)
    print("🔍 Debug testing completed")

if __name__ == "__main__":
    main()
