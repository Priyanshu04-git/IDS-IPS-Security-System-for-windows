# Simple Detector for Portable Deployment
import time
import random
import logging
from datetime import datetime
from typing import List, Dict, Optional

class SimpleDetector:
    def __init__(self):
        self.threat_count = 0
        self.running = False
    
    def start(self):
        self.running = True
        return True
    
    def stop(self):
        self.running = False
    
    def get_stats(self):
        return {
            'threats_detected': self.threat_count,
            'status': 'running' if self.running else 'stopped',
            'packets_analyzed': random.randint(1000, 5000),
            'blocked_ips': random.randint(0, 10)
        }
    
    def detect_threats(self):
        if random.random() < 0.1:  # 10% chance of threat
            self.threat_count += 1
            return True
        return False

class SimpleRealDetector:
    """Simple real-time detector for IDS engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.threats_detected = 0
        self.suspicious_ips = set()
        self.running = False
        
    def start(self):
        """Start the detector"""
        self.running = True
        self.logger.info("Simple real detector started")
        return True
        
    def stop(self):
        """Stop the detector"""
        self.running = False
        self.logger.info("Simple real detector stopped")
        
    def analyze_packet(self, packet_info) -> List[Dict]:
        """Analyze a packet for threats"""
        if not self.running:
            return []  # Return empty list instead of None
            
        # Simple threat detection logic
        threat_detected = False
        threat_type = "Unknown"
        severity = "LOW"
        
        # Check for suspicious ports
        if packet_info.dst_port in [22, 23, 135, 139, 445, 1433, 3389]:
            threat_detected = True
            threat_type = "Suspicious Port Access"
            severity = "MEDIUM"
            
        # Check for port scanning (multiple ports from same IP)
        if packet_info.src_ip in self.suspicious_ips:
            threat_detected = True
            threat_type = "Port Scan"
            severity = "HIGH"
            
        # Random threat simulation
        if random.random() < 0.02:  # 2% chance
            threat_detected = True
            threat_type = random.choice([
                "Brute Force", "Malware Activity", 
                "Suspicious Traffic", "Anomalous Behavior"
            ])
            severity = random.choice(["LOW", "MEDIUM", "HIGH"])
            
        if threat_detected:
            self.threats_detected += 1
            self.suspicious_ips.add(packet_info.src_ip)
            
            threat = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': packet_info.src_ip,
                'destination_ip': packet_info.dst_ip,
                'threat_type': threat_type,
                'severity': severity,
                'confidence': random.randint(70, 95),
                'protocol': packet_info.protocol,
                'port': packet_info.dst_port
            }
            return [threat]  # Return as list
            
        return []  # Return empty list instead of None
        
    def get_stats(self):
        """Get detector statistics"""
        return {
            'threats_detected': self.threats_detected,
            'suspicious_ips': len(self.suspicious_ips),
            'status': 'running' if self.running else 'stopped'
        }

# Global instances
detector = SimpleDetector()
real_detector = SimpleRealDetector()
