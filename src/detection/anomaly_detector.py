"""
Anomaly-Based Detection Engine for IDS/IPS System
Detects threats using statistical analysis and behavioral patterns
"""

import time
import json
import logging
import threading
import statistics
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
import math

@dataclass
class AnomalyResult:
    """Data class representing an anomaly detection result"""
    anomaly_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    anomaly_score: float
    baseline_value: float
    observed_value: float
    description: str
    confidence: float = 1.0
    additional_info: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}

class NetworkBaseline:
    """Maintains baseline statistics for network behavior"""
    
    def __init__(self, window_size: int = 1000, learning_period: int = 3600):
        self.window_size = window_size
        self.learning_period = learning_period  # seconds
        self.start_time = time.time()
        
        # Traffic volume baselines
        self.packet_counts = deque(maxlen=window_size)
        self.byte_counts = deque(maxlen=window_size)
        self.connection_counts = deque(maxlen=window_size)
        
        # Protocol distribution baselines
        self.protocol_stats = defaultdict(lambda: deque(maxlen=window_size))
        
        # Port usage baselines
        self.port_stats = defaultdict(lambda: deque(maxlen=window_size))
        
        # IP address baselines
        self.ip_stats = defaultdict(lambda: {
            'packet_counts': deque(maxlen=window_size),
            'byte_counts': deque(maxlen=window_size),
            'connection_counts': deque(maxlen=window_size),
            'first_seen': time.time(),
            'last_seen': time.time()
        })
        
        # Time-based patterns
        self.hourly_stats = defaultdict(lambda: {
            'packet_counts': [],
            'byte_counts': [],
            'connection_counts': []
        })
        
        self.logger = logging.getLogger(__name__)
        self._lock = threading.RLock()
    
    def update(self, packet_info):
        """Update baseline statistics with new packet information"""
        with self._lock:
            current_time = time.time()
            current_hour = datetime.fromtimestamp(current_time).hour
            
            # Update traffic volume baselines
            self.packet_counts.append(1)
            self.byte_counts.append(packet_info.packet_size)
            
            # Update protocol statistics
            self.protocol_stats[packet_info.protocol].append(1)
            
            # Update port statistics
            if packet_info.dst_port:
                self.port_stats[packet_info.dst_port].append(1)
            if packet_info.src_port:
                self.port_stats[packet_info.src_port].append(1)
            
            # Update IP statistics
            for ip in [packet_info.src_ip, packet_info.dst_ip]:
                if ip != "Unknown":
                    ip_stat = self.ip_stats[ip]
                    ip_stat['packet_counts'].append(1)
                    ip_stat['byte_counts'].append(packet_info.packet_size)
                    ip_stat['last_seen'] = current_time
            
            # Update hourly statistics
            hour_stat = self.hourly_stats[current_hour]
            hour_stat['packet_counts'].append(1)
            hour_stat['byte_counts'].append(packet_info.packet_size)
    
    def get_packet_rate_stats(self) -> Dict[str, float]:
        """Get packet rate statistics"""
        if len(self.packet_counts) < 10:
            return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
        
        counts = list(self.packet_counts)
        return {
            'mean': statistics.mean(counts),
            'std': statistics.stdev(counts) if len(counts) > 1 else 0,
            'min': min(counts),
            'max': max(counts)
        }
    
    def get_byte_rate_stats(self) -> Dict[str, float]:
        """Get byte rate statistics"""
        if len(self.byte_counts) < 10:
            return {'mean': 0, 'std': 0, 'min': 0, 'max': 0}
        
        counts = list(self.byte_counts)
        return {
            'mean': statistics.mean(counts),
            'std': statistics.stdev(counts) if len(counts) > 1 else 0,
            'min': min(counts),
            'max': max(counts)
        }
    
    def get_protocol_distribution(self) -> Dict[str, float]:
        """Get protocol distribution statistics"""
        total_packets = sum(len(counts) for counts in self.protocol_stats.values())
        if total_packets == 0:
            return {}
        
        distribution = {}
        for protocol, counts in self.protocol_stats.items():
            distribution[protocol] = len(counts) / total_packets
        
        return distribution
    
    def get_port_usage_stats(self) -> Dict[int, int]:
        """Get port usage statistics"""
        port_usage = {}
        for port, counts in self.port_stats.items():
            port_usage[port] = len(counts)
        
        return port_usage
    
    def get_ip_stats(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get statistics for a specific IP address"""
        if ip not in self.ip_stats:
            return None
        
        ip_stat = self.ip_stats[ip]
        packet_counts = list(ip_stat['packet_counts'])
        byte_counts = list(ip_stat['byte_counts'])
        
        if not packet_counts:
            return None
        
        return {
            'packet_count': len(packet_counts),
            'byte_count': sum(byte_counts),
            'avg_packet_size': sum(byte_counts) / len(packet_counts),
            'first_seen': ip_stat['first_seen'],
            'last_seen': ip_stat['last_seen'],
            'duration': ip_stat['last_seen'] - ip_stat['first_seen']
        }
    
    def is_learning_complete(self) -> bool:
        """Check if the learning period is complete"""
        return (time.time() - self.start_time) >= self.learning_period

class AnomalyDetector:
    """Main anomaly detection engine"""
    
    def __init__(self, learning_period: int = 3600):
        self.baseline = NetworkBaseline(learning_period=learning_period)
        self.logger = logging.getLogger(__name__)
        
        # Detection thresholds (in standard deviations)
        self.thresholds = {
            'packet_rate': {'medium': 2.0, 'high': 3.0, 'critical': 4.0},
            'byte_rate': {'medium': 2.0, 'high': 3.0, 'critical': 4.0},
            'connection_rate': {'medium': 2.5, 'high': 3.5, 'critical': 5.0},
            'port_scan': {'medium': 10, 'high': 20, 'critical': 50},  # unique ports
            'protocol_anomaly': {'medium': 0.1, 'high': 0.05, 'critical': 0.01}  # deviation
        }
        
        # Detection state tracking
        self.detection_state = {
            'port_scan_tracking': defaultdict(lambda: {
                'ports': set(),
                'start_time': time.time(),
                'packet_count': 0
            }),
            'connection_tracking': defaultdict(lambda: {
                'connections': set(),
                'start_time': time.time()
            }),
            'rate_tracking': defaultdict(lambda: {
                'packets': deque(maxlen=100),
                'bytes': deque(maxlen=100),
                'timestamps': deque(maxlen=100)
            })
        }
        
        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'anomalies_detected': 0,
            'learning_mode': True,
            'start_time': time.time()
        }
        
        # Cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def analyze_packet(self, packet_info) -> List[AnomalyResult]:
        """Analyze a packet for anomalies"""
        self.stats['packets_analyzed'] += 1
        anomalies = []
        
        # Update baseline
        self.baseline.update(packet_info)
        
        # Check if we're still in learning mode
        if not self.baseline.is_learning_complete():
            self.stats['learning_mode'] = True
            return anomalies
        
        self.stats['learning_mode'] = False
        
        # Perform various anomaly checks
        anomalies.extend(self._check_traffic_volume_anomalies(packet_info))
        anomalies.extend(self._check_port_scan_anomalies(packet_info))
        anomalies.extend(self._check_protocol_anomalies(packet_info))
        anomalies.extend(self._check_connection_anomalies(packet_info))
        anomalies.extend(self._check_behavioral_anomalies(packet_info))
        
        self.stats['anomalies_detected'] += len(anomalies)
        return anomalies
    
    def _check_traffic_volume_anomalies(self, packet_info) -> List[AnomalyResult]:
        """Check for traffic volume anomalies"""
        anomalies = []
        current_time = time.time()
        
        # Update rate tracking
        src_ip = packet_info.src_ip
        rate_data = self.detection_state['rate_tracking'][src_ip]
        rate_data['packets'].append(1)
        rate_data['bytes'].append(packet_info.packet_size)
        rate_data['timestamps'].append(current_time)
        
        # Calculate current rates (packets/second, bytes/second)
        if len(rate_data['timestamps']) >= 10:
            time_window = 60  # 1 minute window
            recent_timestamps = [t for t in rate_data['timestamps'] if current_time - t <= time_window]
            
            if len(recent_timestamps) >= 5:
                packet_rate = len(recent_timestamps) / time_window
                byte_rate = sum(rate_data['bytes'][-len(recent_timestamps):]) / time_window
                
                # Get baseline statistics
                packet_stats = self.baseline.get_packet_rate_stats()
                byte_stats = self.baseline.get_byte_rate_stats()
                
                # Check packet rate anomaly
                if packet_stats['std'] > 0:
                    packet_z_score = abs(packet_rate - packet_stats['mean']) / packet_stats['std']
                    severity = self._get_severity_from_zscore(packet_z_score, self.thresholds['packet_rate'])
                    
                    if severity:
                        anomalies.append(AnomalyResult(
                            anomaly_type="HIGH_PACKET_RATE",
                            severity=severity,
                            timestamp=current_time,
                            src_ip=src_ip,
                            dst_ip=packet_info.dst_ip,
                            src_port=packet_info.src_port,
                            dst_port=packet_info.dst_port,
                            protocol=packet_info.protocol,
                            anomaly_score=packet_z_score,
                            baseline_value=packet_stats['mean'],
                            observed_value=packet_rate,
                            description=f"Unusually high packet rate: {packet_rate:.2f} pps (baseline: {packet_stats['mean']:.2f} pps)",
                            confidence=min(packet_z_score / 5.0, 1.0)
                        ))
                
                # Check byte rate anomaly
                if byte_stats['std'] > 0:
                    byte_z_score = abs(byte_rate - byte_stats['mean']) / byte_stats['std']
                    severity = self._get_severity_from_zscore(byte_z_score, self.thresholds['byte_rate'])
                    
                    if severity:
                        anomalies.append(AnomalyResult(
                            anomaly_type="HIGH_BYTE_RATE",
                            severity=severity,
                            timestamp=current_time,
                            src_ip=src_ip,
                            dst_ip=packet_info.dst_ip,
                            src_port=packet_info.src_port,
                            dst_port=packet_info.dst_port,
                            protocol=packet_info.protocol,
                            anomaly_score=byte_z_score,
                            baseline_value=byte_stats['mean'],
                            observed_value=byte_rate,
                            description=f"Unusually high byte rate: {byte_rate:.2f} Bps (baseline: {byte_stats['mean']:.2f} Bps)",
                            confidence=min(byte_z_score / 5.0, 1.0)
                        ))
        
        return anomalies
    
    def _check_port_scan_anomalies(self, packet_info) -> List[AnomalyResult]:
        """Check for port scanning anomalies"""
        anomalies = []
        current_time = time.time()
        
        # Only check TCP SYN packets for port scans
        if packet_info.protocol != "TCP" or not packet_info.flags or "SYN" not in packet_info.flags:
            return anomalies
        
        src_ip = packet_info.src_ip
        dst_port = packet_info.dst_port
        
        if not dst_port:
            return anomalies
        
        # Update port scan tracking
        scan_data = self.detection_state['port_scan_tracking'][src_ip]
        scan_data['ports'].add(dst_port)
        scan_data['packet_count'] += 1
        
        # Check if this looks like a port scan
        time_window = 60  # 1 minute window
        if current_time - scan_data['start_time'] > time_window:
            unique_ports = len(scan_data['ports'])
            
            # Determine severity based on number of unique ports
            severity = None
            if unique_ports >= self.thresholds['port_scan']['critical']:
                severity = "CRITICAL"
            elif unique_ports >= self.thresholds['port_scan']['high']:
                severity = "HIGH"
            elif unique_ports >= self.thresholds['port_scan']['medium']:
                severity = "MEDIUM"
            
            if severity:
                anomalies.append(AnomalyResult(
                    anomaly_type="PORT_SCAN",
                    severity=severity,
                    timestamp=current_time,
                    src_ip=src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=dst_port,
                    protocol=packet_info.protocol,
                    anomaly_score=unique_ports,
                    baseline_value=self.thresholds['port_scan']['medium'],
                    observed_value=unique_ports,
                    description=f"Port scan detected: {unique_ports} unique ports scanned in {time_window}s",
                    confidence=min(unique_ports / 100.0, 1.0),
                    additional_info={
                        'scanned_ports': list(scan_data['ports']),
                        'scan_duration': current_time - scan_data['start_time'],
                        'total_packets': scan_data['packet_count']
                    }
                ))
            
            # Reset tracking for next window
            scan_data['ports'].clear()
            scan_data['start_time'] = current_time
            scan_data['packet_count'] = 0
        
        return anomalies
    
    def _check_protocol_anomalies(self, packet_info) -> List[AnomalyResult]:
        """Check for protocol distribution anomalies"""
        anomalies = []
        
        # Get current protocol distribution
        protocol_dist = self.baseline.get_protocol_distribution()
        
        if not protocol_dist:
            return anomalies
        
        # Check if this protocol is unusual
        protocol = packet_info.protocol
        expected_frequency = protocol_dist.get(protocol, 0)
        
        # If protocol frequency is below threshold, it might be anomalous
        if expected_frequency < self.thresholds['protocol_anomaly']['critical']:
            severity = "CRITICAL"
        elif expected_frequency < self.thresholds['protocol_anomaly']['high']:
            severity = "HIGH"
        elif expected_frequency < self.thresholds['protocol_anomaly']['medium']:
            severity = "MEDIUM"
        else:
            severity = None
        
        if severity and expected_frequency < 0.01:  # Less than 1% of traffic
            anomalies.append(AnomalyResult(
                anomaly_type="UNUSUAL_PROTOCOL",
                severity=severity,
                timestamp=packet_info.timestamp,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                protocol=protocol,
                anomaly_score=1.0 - expected_frequency,
                baseline_value=expected_frequency,
                observed_value=1.0,
                description=f"Unusual protocol usage: {protocol} (frequency: {expected_frequency:.4f})",
                confidence=1.0 - expected_frequency
            ))
        
        return anomalies
    
    def _check_connection_anomalies(self, packet_info) -> List[AnomalyResult]:
        """Check for connection-based anomalies"""
        anomalies = []
        current_time = time.time()
        
        # Track unique connections per source IP
        src_ip = packet_info.src_ip
        connection_key = f"{packet_info.dst_ip}:{packet_info.dst_port}"
        
        conn_data = self.detection_state['connection_tracking'][src_ip]
        conn_data['connections'].add(connection_key)
        
        # Check for excessive connections
        time_window = 300  # 5 minute window
        if current_time - conn_data['start_time'] > time_window:
            unique_connections = len(conn_data['connections'])
            
            # Determine severity based on number of unique connections
            severity = None
            if unique_connections >= 100:
                severity = "CRITICAL"
            elif unique_connections >= 50:
                severity = "HIGH"
            elif unique_connections >= 25:
                severity = "MEDIUM"
            
            if severity:
                anomalies.append(AnomalyResult(
                    anomaly_type="EXCESSIVE_CONNECTIONS",
                    severity=severity,
                    timestamp=current_time,
                    src_ip=src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=packet_info.dst_port,
                    protocol=packet_info.protocol,
                    anomaly_score=unique_connections,
                    baseline_value=25,
                    observed_value=unique_connections,
                    description=f"Excessive connections: {unique_connections} unique connections in {time_window}s",
                    confidence=min(unique_connections / 200.0, 1.0),
                    additional_info={
                        'connection_count': unique_connections,
                        'time_window': time_window
                    }
                ))
            
            # Reset tracking
            conn_data['connections'].clear()
            conn_data['start_time'] = current_time
        
        return anomalies
    
    def _check_behavioral_anomalies(self, packet_info) -> List[AnomalyResult]:
        """Check for behavioral anomalies"""
        anomalies = []
        
        # Check for unusual packet sizes
        if packet_info.packet_size > 9000:  # Jumbo frames
            anomalies.append(AnomalyResult(
                anomaly_type="UNUSUAL_PACKET_SIZE",
                severity="MEDIUM",
                timestamp=packet_info.timestamp,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                protocol=packet_info.protocol,
                anomaly_score=packet_info.packet_size / 1500.0,
                baseline_value=1500,
                observed_value=packet_info.packet_size,
                description=f"Unusually large packet: {packet_info.packet_size} bytes",
                confidence=0.7
            ))
        
        # Check for unusual time patterns (simplified)
        current_hour = datetime.fromtimestamp(packet_info.timestamp).hour
        if current_hour < 6 or current_hour > 22:  # Outside business hours
            # This would need more sophisticated baseline comparison
            pass
        
        return anomalies
    
    def _get_severity_from_zscore(self, z_score: float, thresholds: Dict[str, float]) -> Optional[str]:
        """Convert z-score to severity level"""
        if z_score >= thresholds['critical']:
            return "CRITICAL"
        elif z_score >= thresholds['high']:
            return "HIGH"
        elif z_score >= thresholds['medium']:
            return "MEDIUM"
        return None
    
    def _cleanup_worker(self):
        """Background worker to clean up old tracking data"""
        while True:
            try:
                current_time = time.time()
                cleanup_threshold = 3600  # 1 hour
                
                # Clean up port scan tracking
                for src_ip in list(self.detection_state['port_scan_tracking'].keys()):
                    scan_data = self.detection_state['port_scan_tracking'][src_ip]
                    if current_time - scan_data['start_time'] > cleanup_threshold:
                        del self.detection_state['port_scan_tracking'][src_ip]
                
                # Clean up connection tracking
                for src_ip in list(self.detection_state['connection_tracking'].keys()):
                    conn_data = self.detection_state['connection_tracking'][src_ip]
                    if current_time - conn_data['start_time'] > cleanup_threshold:
                        del self.detection_state['connection_tracking'][src_ip]
                
                # Clean up rate tracking
                for src_ip in list(self.detection_state['rate_tracking'].keys()):
                    rate_data = self.detection_state['rate_tracking'][src_ip]
                    if (rate_data['timestamps'] and 
                        current_time - rate_data['timestamps'][-1] > cleanup_threshold):
                        del self.detection_state['rate_tracking'][src_ip]
                
                time.sleep(300)  # Run cleanup every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in cleanup worker: {e}")
                time.sleep(60)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get anomaly detection statistics"""
        current_time = time.time()
        runtime = current_time - self.stats['start_time']
        
        stats = self.stats.copy()
        stats['runtime'] = runtime
        stats['baseline_learning_complete'] = self.baseline.is_learning_complete()
        
        if runtime > 0:
            stats['packets_per_second'] = self.stats['packets_analyzed'] / runtime
            stats['anomalies_per_second'] = self.stats['anomalies_detected'] / runtime
        
        stats['anomaly_rate'] = (
            self.stats['anomalies_detected'] / self.stats['packets_analyzed'] 
            if self.stats['packets_analyzed'] > 0 else 0
        )
        
        # Add tracking state statistics
        stats['active_port_scans'] = len(self.detection_state['port_scan_tracking'])
        stats['active_connections'] = len(self.detection_state['connection_tracking'])
        stats['active_rate_tracking'] = len(self.detection_state['rate_tracking'])
        
        return stats
    
    def reset_stats(self):
        """Reset detection statistics"""
        self.stats = {
            'packets_analyzed': 0,
            'anomalies_detected': 0,
            'learning_mode': True,
            'start_time': time.time()
        }

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create anomaly detector
    detector = AnomalyDetector(learning_period=60)  # 1 minute learning for testing
    
    # Test with sample packet data
    from packet_capture.packet_sniffer import PacketInfo
    
    # Simulate normal traffic for learning
    print("Learning phase - simulating normal traffic...")
    for i in range(100):
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip=f"192.168.1.{i % 10 + 1}",
            dst_ip="10.0.0.1",
            src_port=1000 + i,
            dst_port=80,
            protocol="TCP",
            packet_size=1024 + (i % 500),
            flags="PSH|ACK",
            payload_size=500
        )
        detector.analyze_packet(packet)
        time.sleep(0.01)
    
    # Wait for learning to complete
    time.sleep(2)
    
    # Test with anomalous traffic
    print("\nTesting with anomalous traffic...")
    
    # Port scan simulation
    for port in range(1, 51):
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=port,
            protocol="TCP",
            packet_size=64,
            flags="SYN",
            payload_size=0
        )
        anomalies = detector.analyze_packet(packet)
        if anomalies:
            for anomaly in anomalies:
                print(f"ANOMALY: {anomaly.anomaly_type}")
                print(f"  Severity: {anomaly.severity}")
                print(f"  Score: {anomaly.anomaly_score:.2f}")
                print(f"  Description: {anomaly.description}")
    
    # High traffic rate simulation
    print("\nSimulating high traffic rate...")
    for i in range(200):
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.200",
            dst_ip="10.0.0.1",
            src_port=2000 + i,
            dst_port=80,
            protocol="TCP",
            packet_size=1024,
            flags="PSH|ACK",
            payload_size=500
        )
        anomalies = detector.analyze_packet(packet)
        if anomalies:
            for anomaly in anomalies:
                print(f"ANOMALY: {anomaly.anomaly_type}")
                print(f"  Severity: {anomaly.severity}")
                print(f"  Score: {anomaly.anomaly_score:.2f}")
                print(f"  Description: {anomaly.description}")
        time.sleep(0.001)  # Very fast rate
    
    # Print detector stats
    print("\nAnomaly Detection Stats:")
    print(json.dumps(detector.get_stats(), indent=2))

