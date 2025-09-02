#!/usr/bin/env python3
"""
Debug Network Connections to understand threat detection
"""

import psutil
from collections import defaultdict

def debug_connections():
    print("🔍 Debugging Network Connections")
    print("=" * 50)
    
    try:
        connections = psutil.net_connections()
        print(f"📊 Total connections found: {len(connections)}")
        print()
        
        # Analyze connections
        ip_counts = defaultdict(int)
        port_usage = defaultdict(int)
        connection_types = defaultdict(int)
        
        print("🔗 Active Connections:")
        for i, conn in enumerate(connections):
            conn_type = f"{conn.family.name}-{conn.type.name}" if hasattr(conn.family, 'name') else "Unknown"
            connection_types[conn_type] += 1
            
            if conn.raddr:  # Remote address exists (outbound)
                ip = conn.raddr.ip
                port = conn.raddr.port
                
                ip_counts[ip] += 1
                port_usage[port] += 1
                
                print(f"  {i+1}. {conn.laddr} -> {conn.raddr} [{conn.status}] PID:{conn.pid}")
                
                # Check if this would be flagged
                if ip_counts[ip] > 10:
                    print(f"       ⚠️  FLAGGED: Multiple connections from {ip} ({ip_counts[ip]} total)")
                
                if port in [22, 23, 135, 139, 445, 1433, 3389]:
                    print(f"       🚨 FLAGGED: Suspicious port {port}")
            
            elif conn.laddr:  # Only local address (listening)
                print(f"  {i+1}. Listening on {conn.laddr} [{conn.status}] PID:{conn.pid}")
        
        print(f"\n📊 Connection Types:")
        for conn_type, count in connection_types.items():
            print(f"  {conn_type}: {count}")
        
        print(f"\n📊 Remote IP Connection Counts:")
        for ip, count in ip_counts.items():
            flag = " ⚠️ SUSPICIOUS" if count > 10 else ""
            print(f"  {ip}: {count} connections{flag}")
        
        print(f"\n📊 Remote Port Usage:")
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389]
        for port, count in port_usage.items():
            flag = " 🚨 SUSPICIOUS" if port in suspicious_ports else ""
            print(f"  Port {port}: {count} connections{flag}")
            
        # Now test the actual suspicious detection
        print(f"\n🔍 Testing Suspicious Connection Detection:")
        suspicious = []
        
        for conn in connections:
            if conn.raddr:
                ip = conn.raddr.ip
                port = conn.raddr.port
                
                # Flag IPs with many connections
                if ip_counts[ip] > 10:
                    suspicious.append({
                        'type': 'Multiple Connections',
                        'source_ip': ip,
                        'connection_count': ip_counts[ip],
                        'severity': 'MEDIUM' if ip_counts[ip] < 20 else 'HIGH'
                    })
                
                # Flag unusual ports
                if port in [22, 23, 135, 139, 445, 1433, 3389]:
                    suspicious.append({
                        'type': 'Suspicious Port Access',
                        'source_ip': ip,
                        'target_port': port,
                        'severity': 'HIGH'
                    })
        
        print(f"🚨 Suspicious activities detected: {len(suspicious)}")
        if suspicious:
            for i, activity in enumerate(suspicious, 1):
                print(f"  {i}. {activity}")
        else:
            print("  ℹ️  No suspicious activities detected")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_connections()
