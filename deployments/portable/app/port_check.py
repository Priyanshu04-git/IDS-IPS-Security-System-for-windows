#!/usr/bin/env python3
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
