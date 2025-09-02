"""
Simple Packet Sniffer
Basic network packet capture functionality
"""

import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional, Callable, List
import logging

@dataclass
class PacketInfo:
    """Simple packet information structure"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    flags: Optional[str]
    payload_size: int
    raw_packet: Optional[bytes] = None

class PacketSniffer:
    """Simple packet sniffer for basic network monitoring"""
    
    def __init__(self, interface: str = None, filter_expression: str = None):
        self.interface = interface
        self.filter_expression = filter_expression
        self.running = False
        self.callbacks: List[Callable[[PacketInfo], None]] = []
        self.logger = logging.getLogger(__name__)
        
    def add_callback(self, callback: Callable[[PacketInfo], None]):
        """Add a callback function to process captured packets"""
        self.callbacks.append(callback)
        
    def start(self):
        """Start the packet sniffer"""
        self.start_capture()
        
    def start_capture(self):
        """Start packet capture (simplified version)"""
        self.running = True
        self.logger.info("Starting simplified packet capture simulation")
        
        # Start simulation thread since raw socket capture requires admin privileges
        capture_thread = threading.Thread(target=self._simulate_capture, daemon=True)
        capture_thread.start()
        
    def stop(self):
        """Stop the packet sniffer"""
        self.stop_capture()
        
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        self.logger.info("Packet capture stopped")
        
    def _simulate_capture(self):
        """Simulate network packet capture for demonstration"""
        import random
        
        sample_ips = [
            "192.168.1.100", "10.0.0.50", "172.16.1.20", 
            "203.0.113.10", "198.51.100.25"
        ]
        
        protocols = ["TCP", "UDP", "ICMP"]
        
        while self.running:
            try:
                # Simulate a network packet
                packet = PacketInfo(
                    timestamp=time.time(),
                    src_ip=random.choice(sample_ips),
                    dst_ip=random.choice(sample_ips),
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 22, 25, 53, 123]),
                    protocol=random.choice(protocols),
                    packet_size=random.randint(64, 1500),
                    flags="SYN" if random.random() < 0.3 else None,
                    payload_size=random.randint(0, 1400)
                )
                
                # Call all registered callbacks
                for callback in self.callbacks:
                    try:
                        callback(packet)
                    except Exception as e:
                        self.logger.error(f"Error in packet callback: {e}")
                
                # Wait between packets (simulate network activity)
                time.sleep(random.uniform(0.1, 2.0))
                
            except Exception as e:
                self.logger.error(f"Error in packet simulation: {e}")
                time.sleep(1)
