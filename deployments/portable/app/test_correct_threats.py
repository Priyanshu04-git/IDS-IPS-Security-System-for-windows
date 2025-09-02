#!/usr/bin/env python3
"""
Test Threat Detection System - Correct Method
"""

import sys
import os
import json

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from real_data_collector import get_current_data, is_using_real_data, get_data_source_info
    print("✅ Successfully imported real_data_collector functions")
except ImportError as e:
    print(f"❌ Failed to import real_data_collector: {e}")
    sys.exit(1)

def main():
    print("🔍 Testing IDS/IPS Threat Detection System")
    print("=" * 60)
    
    # Check data source
    print(f"📊 Data Source: {get_data_source_info()}")
    print(f"🔍 Using Real Data: {'Yes' if is_using_real_data() else 'No'}")
    print()
    
    # Get current data
    try:
        print("🔍 Collecting current security data...")
        data = get_current_data()
        
        if data:
            print("✅ Data collection successful!")
            print()
            
            # Display threats
            threats = data.get('threats', [])
            print(f"🚨 Current Threats: {len(threats)}")
            if threats:
                print("   Active Threats:")
                for i, threat in enumerate(threats, 1):
                    print(f"   {i}. [{threat.get('severity', 'UNKNOWN')}] {threat.get('threat_type', 'Unknown')} from {threat.get('source_ip', 'Unknown IP')}")
            else:
                print("   ℹ️  No active threats detected")
            print()
            
            # Display network stats
            network_stats = data.get('network_stats', {})
            print("🌐 Network Statistics:")
            for key, value in network_stats.items():
                print(f"   {key}: {value}")
            print()
            
            # Display system performance
            system_perf = data.get('system_performance', {})
            print("📊 System Performance:")
            for key, value in system_perf.items():
                if isinstance(value, float):
                    print(f"   {key}: {value:.2f}")
                else:
                    print(f"   {key}: {value}")
            print()
            
            print(f"📡 Data Source Type: {data.get('data_source', 'Unknown')}")
            print(f"🔍 Real Data Mode: {'Yes' if data.get('is_real_data', False) else 'No'}")
            
        else:
            print("❌ No data returned from collector")
            
    except Exception as e:
        print(f"❌ Error collecting data: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("🔍 Threat detection test completed")

if __name__ == "__main__":
    main()
