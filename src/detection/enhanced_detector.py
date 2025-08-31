"""
Enhanced Detection Engine for IDS/IPS System
Integrates all detection methods with improved reliability and performance
"""

import threading
import time
import json
import sqlite3
import hashlib
import re
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import logging
import queue
import ipaddress
import socket
import struct

# Enhanced packet structure for better analysis
@dataclass
class EnhancedPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_size: int
    flags: List[str]
    payload_hash: str
    payload_snippet: str
    direction: str  # 'inbound', 'outbound', 'internal'
    metadata: Dict[str, Any]

@dataclass
class ThreatDetection:
    detection_id: str
    timestamp: float
    threat_type: str
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    confidence: float  # 0.0 to 1.0
    source_ip: str
    destination_ip: str
    detection_method: str
    description: str
    indicators: List[str]
    recommended_action: str
    metadata: Dict[str, Any]

class EnhancedDetectionEngine:
    """Unified detection engine combining all detection methods"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()
        self.running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.detection_queue = queue.Queue(maxsize=1000)
        
        # Detection statistics
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'processing_time_avg': 0.0,
            'detection_rates': defaultdict(int),
            'start_time': time.time()
        }
        
        # Initialize detection components
        self._init_signature_detection()
        self._init_anomaly_detection()
        self._init_ml_detection()
        self._init_behavioral_detection()
        self._init_threat_intelligence()
        
        # Worker threads
        self.workers = []
        self.detection_callbacks = []
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        
        self.logger.info("Enhanced Detection Engine initialized")
    
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration for the detection engine"""
        return {
            'signature_detection': {
                'enabled': True,
                'signature_file': 'signatures.json',
                'update_interval': 3600
            },
            'anomaly_detection': {
                'enabled': True,
                'threshold': 3.0,
                'window_size': 1000,
                'learning_rate': 0.01
            },
            'ml_detection': {
                'enabled': True,
                'model_path': 'ml_models/',
                'confidence_threshold': 0.7,
                'retrain_interval': 86400
            },
            'behavioral_detection': {
                'enabled': True,
                'session_timeout': 300,
                'pattern_window': 3600
            },
            'threat_intelligence': {
                'enabled': True,
                'feeds': [],
                'update_interval': 1800
            },
            'performance': {
                'max_workers': 4,
                'batch_size': 100,
                'queue_timeout': 1.0
            }
        }
    
    def _init_signature_detection(self):
        """Initialize signature-based detection"""
        self.signatures = {
            'malware': [
                {
                    'id': 'MAL001',
                    'name': 'Generic Trojan Communication',
                    'pattern': rb'MALICIOUS_PAYLOAD',
                    'severity': 'HIGH',
                    'description': 'Known malware communication pattern'
                },
                {
                    'id': 'MAL002', 
                    'name': 'Botnet C2 Communication',
                    'pattern': rb'C2_COMMAND',
                    'severity': 'CRITICAL',
                    'description': 'Command and control communication detected'
                }
            ],
            'exploits': [
                {
                    'id': 'EXP001',
                    'name': 'Buffer Overflow Attempt',
                    'pattern': rb'A' * 100,  # Simple buffer overflow pattern
                    'severity': 'HIGH',
                    'description': 'Potential buffer overflow exploit'
                },
                {
                    'id': 'EXP002',
                    'name': 'SQL Injection',
                    'pattern': rb"(?i)(union|select|insert|delete|drop|exec|script)",
                    'severity': 'HIGH',
                    'description': 'SQL injection attempt detected'
                }
            ],
            'reconnaissance': [
                {
                    'id': 'REC001',
                    'name': 'Port Scan Detection',
                    'pattern': 'port_scan_behavior',
                    'severity': 'MEDIUM',
                    'description': 'Port scanning activity detected'
                },
                {
                    'id': 'REC002',
                    'name': 'Network Enumeration',
                    'pattern': 'network_enum_behavior',
                    'severity': 'MEDIUM',
                    'description': 'Network enumeration detected'
                }
            ]
        }
        
        # Compile regex patterns for better performance
        self.compiled_patterns = {}
        for category, sigs in self.signatures.items():
            self.compiled_patterns[category] = []
            for sig in sigs:
                if isinstance(sig['pattern'], bytes):
                    try:
                        compiled = re.compile(sig['pattern'])
                        self.compiled_patterns[category].append((sig, compiled))
                    except:
                        self.compiled_patterns[category].append((sig, None))
                else:
                    self.compiled_patterns[category].append((sig, None))
    
    def _init_anomaly_detection(self):
        """Initialize statistical anomaly detection"""
        self.anomaly_baselines = {
            'packet_size': {'mean': 0, 'std': 0, 'samples': deque(maxlen=1000)},
            'connection_rate': {'mean': 0, 'std': 0, 'samples': deque(maxlen=1000)},
            'port_distribution': defaultdict(int),
            'protocol_distribution': defaultdict(int),
            'traffic_patterns': defaultdict(lambda: deque(maxlen=100))
        }
        
        self.anomaly_threshold = self.config['anomaly_detection']['threshold']
        self.learning_enabled = True
    
    def _init_ml_detection(self):
        """Initialize machine learning detection"""
        # Simplified ML detection using statistical methods
        # In production, this would use trained models
        self.ml_features = [
            'packet_size', 'inter_arrival_time', 'port_entropy',
            'payload_entropy', 'connection_duration', 'packet_rate'
        ]
        
        self.ml_models = {
            'anomaly_detector': self._create_simple_anomaly_model(),
            'threat_classifier': self._create_simple_classifier()
        }
        
        self.feature_cache = deque(maxlen=1000)
    
    def _create_simple_anomaly_model(self):
        """Create a simple anomaly detection model"""
        return {
            'type': 'isolation_forest',
            'threshold': -0.1,
            'features': self.ml_features,
            'trained': False
        }
    
    def _create_simple_classifier(self):
        """Create a simple threat classification model"""
        return {
            'type': 'random_forest',
            'classes': ['benign', 'malware', 'exploit', 'reconnaissance'],
            'features': self.ml_features,
            'trained': False
        }
    
    def _init_behavioral_detection(self):
        """Initialize behavioral pattern detection"""
        self.behavioral_patterns = {
            'port_scan': {
                'description': 'Multiple port connections from single source',
                'threshold': 10,
                'time_window': 60,
                'severity': 'MEDIUM'
            },
            'brute_force': {
                'description': 'Repeated authentication attempts',
                'threshold': 5,
                'time_window': 300,
                'severity': 'HIGH'
            },
            'data_exfiltration': {
                'description': 'Large data transfers to external hosts',
                'threshold': 10485760,  # 10MB
                'time_window': 3600,
                'severity': 'CRITICAL'
            },
            'lateral_movement': {
                'description': 'Internal network scanning from compromised host',
                'threshold': 5,
                'time_window': 1800,
                'severity': 'HIGH'
            }
        }
        
        self.behavioral_state = defaultdict(lambda: defaultdict(list))
        self.session_tracking = {}
    
    def _init_threat_intelligence(self):
        """Initialize threat intelligence feeds"""
        self.threat_intel = {
            'malicious_ips': set([
                '203.0.113.10', '198.51.100.20', '192.0.2.30',
                '203.0.113.40', '198.51.100.50'
            ]),
            'malicious_domains': set([
                'malicious-site.example.com',
                'bad-actor.example.com',
                'phishing-site.example.com'
            ]),
            'malware_hashes': set([
                'deadbeef' * 8,
                'cafebabe' * 8,
                'feedface' * 8
            ]),
            'suspicious_ports': set([4444, 5555, 6666, 7777, 8888, 9999])
        }
    
    def start(self):
        """Start the detection engine"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker threads
        num_workers = self.config['performance']['max_workers']
        for i in range(num_workers):
            worker = threading.Thread(target=self._detection_worker, args=(i,), daemon=True)
            worker.start()
            self.workers.append(worker)
        
        # Start statistics thread
        stats_thread = threading.Thread(target=self._stats_worker, daemon=True)
        stats_thread.start()
        self.workers.append(stats_thread)
        
        self.logger.info(f"Detection engine started with {num_workers} workers")
    
    def stop(self):
        """Stop the detection engine"""
        self.running = False
        self.logger.info("Detection engine stopped")
    
    def add_detection_callback(self, callback):
        """Add callback function for threat detections"""
        self.detection_callbacks.append(callback)
    
    def process_packet(self, packet: EnhancedPacket):
        """Add packet to processing queue"""
        try:
            self.packet_queue.put(packet, timeout=1.0)
        except queue.Full:
            self.logger.warning("Packet queue full, dropping packet")
    
    def _detection_worker(self, worker_id: int):
        """Worker thread for packet processing"""
        self.logger.info(f"Detection worker {worker_id} started")
        
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1.0)
                start_time = time.time()
                
                # Process packet through all detection methods
                detections = self._analyze_packet(packet)
                
                # Update statistics
                processing_time = time.time() - start_time
                self._update_stats(processing_time, len(detections))
                
                # Handle detections
                for detection in detections:
                    self._handle_detection(detection)
                
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in detection worker {worker_id}: {e}")
    
    def _analyze_packet(self, packet: EnhancedPacket) -> List[ThreatDetection]:
        """Analyze packet using all detection methods"""
        detections = []
        
        # Signature-based detection
        if self.config['signature_detection']['enabled']:
            sig_detections = self._signature_analysis(packet)
            detections.extend(sig_detections)
        
        # Anomaly detection
        if self.config['anomaly_detection']['enabled']:
            anomaly_detections = self._anomaly_analysis(packet)
            detections.extend(anomaly_detections)
        
        # ML detection
        if self.config['ml_detection']['enabled']:
            ml_detections = self._ml_analysis(packet)
            detections.extend(ml_detections)
        
        # Behavioral detection
        if self.config['behavioral_detection']['enabled']:
            behavioral_detections = self._behavioral_analysis(packet)
            detections.extend(behavioral_detections)
        
        # Threat intelligence
        if self.config['threat_intelligence']['enabled']:
            intel_detections = self._threat_intel_analysis(packet)
            detections.extend(intel_detections)
        
        return detections
    
    def _signature_analysis(self, packet: EnhancedPacket) -> List[ThreatDetection]:
        """Perform signature-based detection"""
        detections = []
        
        payload_bytes = packet.payload_snippet.encode() if packet.payload_snippet else b''
        
        for category, patterns in self.compiled_patterns.items():
            for sig, compiled_pattern in patterns:
                match_found = False
                
                if compiled_pattern:
                    # Regex pattern matching
                    if compiled_pattern.search(payload_bytes):
                        match_found = True
                else:
                    # Behavioral pattern matching
                    if sig['pattern'] == 'port_scan_behavior':
                        match_found = self._detect_port_scan_signature(packet)
                    elif sig['pattern'] == 'network_enum_behavior':
                        match_found = self._detect_network_enum_signature(packet)
                
                if match_found:
                    detection = ThreatDetection(
                        detection_id=f"SIG_{sig['id']}_{int(time.time())}",
                        timestamp=packet.timestamp,
                        threat_type=category,
                        severity=sig['severity'],
                        confidence=0.9,
                        source_ip=packet.src_ip,
                        destination_ip=packet.dst_ip,
                        detection_method='signature',
                        description=sig['description'],
                        indicators=[sig['name']],
                        recommended_action='block' if sig['severity'] in ['HIGH', 'CRITICAL'] else 'monitor',
                        metadata={'signature_id': sig['id'], 'pattern': str(sig['pattern'])}
                    )
                    detections.append(detection)
        
        return detections
    
    def _detect_port_scan_signature(self, packet: EnhancedPacket) -> bool:
        """Detect port scanning behavior"""
        # Track connection attempts per source IP
        src_ip = packet.src_ip
        current_time = packet.timestamp
        
        # Clean old entries
        cutoff_time = current_time - 60  # 1 minute window
        if src_ip in self.behavioral_state['port_scan']:
            self.behavioral_state['port_scan'][src_ip] = [
                t for t in self.behavioral_state['port_scan'][src_ip] 
                if t > cutoff_time
            ]
        
        # Add current connection
        self.behavioral_state['port_scan'][src_ip].append(current_time)
        
        # Check threshold
        return len(self.behavioral_state['port_scan'][src_ip]) >= 10
    
    def _detect_network_enum_signature(self, packet: EnhancedPacket) -> bool:
        """Detect network enumeration behavior"""
        # Similar to port scan but tracks different destination IPs
        src_ip = packet.src_ip
        dst_ip = packet.dst_ip
        current_time = packet.timestamp
        
        key = f"{src_ip}_enum"
        if key not in self.behavioral_state:
            self.behavioral_state[key] = set()
        
        self.behavioral_state[key].add(dst_ip)
        
        # Check if scanning multiple IPs
        return len(self.behavioral_state[key]) >= 5
    
    def _anomaly_analysis(self, packet: EnhancedPacket) -> List[ThreatDetection]:
        """Perform statistical anomaly detection"""
        detections = []
        
        # Update baselines if learning is enabled
        if self.learning_enabled:
            self._update_baselines(packet)
        
        # Check for anomalies
        anomalies = []
        
        # Packet size anomaly
        if self._is_packet_size_anomaly(packet):
            anomalies.append('unusual_packet_size')
        
        # Connection rate anomaly
        if self._is_connection_rate_anomaly(packet):
            anomalies.append('unusual_connection_rate')
        
        # Protocol distribution anomaly
        if self._is_protocol_anomaly(packet):
            anomalies.append('unusual_protocol')
        
        # Port distribution anomaly
        if self._is_port_anomaly(packet):
            anomalies.append('unusual_port')
        
        if anomalies:
            detection = ThreatDetection(
                detection_id=f"ANOM_{int(time.time())}",
                timestamp=packet.timestamp,
                threat_type='anomaly',
                severity='MEDIUM',
                confidence=0.7,
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                detection_method='anomaly',
                description=f"Statistical anomalies detected: {', '.join(anomalies)}",
                indicators=anomalies,
                recommended_action='investigate',
                metadata={'anomaly_types': anomalies}
            )
            detections.append(detection)
        
        return detections
    
    def _update_baselines(self, packet: EnhancedPacket):
        """Update statistical baselines with new packet data"""
        # Update packet size baseline
        size_samples = self.anomaly_baselines['packet_size']['samples']
        size_samples.append(packet.payload_size)
        if len(size_samples) > 10:
            self.anomaly_baselines['packet_size']['mean'] = np.mean(size_samples)
            self.anomaly_baselines['packet_size']['std'] = np.std(size_samples)
        
        # Update protocol distribution
        self.anomaly_baselines['protocol_distribution'][packet.protocol] += 1
        
        # Update port distribution
        self.anomaly_baselines['port_distribution'][packet.dst_port] += 1
    
    def _is_packet_size_anomaly(self, packet: EnhancedPacket) -> bool:
        """Check if packet size is anomalous"""
        baseline = self.anomaly_baselines['packet_size']
        if baseline['std'] == 0:
            return False
        
        z_score = abs(packet.payload_size - baseline['mean']) / baseline['std']
        return z_score > self.anomaly_threshold
    
    def _is_connection_rate_anomaly(self, packet: EnhancedPacket) -> bool:
        """Check if connection rate is anomalous"""
        # Simplified connection rate check
        current_time = packet.timestamp
        src_ip = packet.src_ip
        
        # Count connections in last minute
        recent_connections = sum(1 for t in self.behavioral_state['connections'].get(src_ip, [])
                               if current_time - t < 60)
        
        return recent_connections > 50  # Threshold for high connection rate
    
    def _is_protocol_anomaly(self, packet: EnhancedPacket) -> bool:
        """Check if protocol usage is anomalous"""
        total_packets = sum(self.anomaly_baselines['protocol_distribution'].values())
        if total_packets < 100:
            return False
        
        protocol_ratio = self.anomaly_baselines['protocol_distribution'][packet.protocol] / total_packets
        
        # Flag protocols used less than 1% of the time as potentially anomalous
        return protocol_ratio < 0.01 and packet.protocol not in ['TCP', 'UDP', 'ICMP']
    
    def _is_port_anomaly(self, packet: EnhancedPacket) -> bool:
        """Check if port usage is anomalous"""
        # Flag connections to suspicious ports
        return packet.dst_port in self.threat_intel['suspicious_ports']
    
    def _ml_analysis(self, packet: EnhancedPacket) -> List[ThreatDetection]:
        """Perform machine learning-based detection"""
        detections = []
        
        # Extract features
        features = self._extract_ml_features(packet)
        self.feature_cache.append(features)
        
        # Simple ML-like analysis using statistical methods
        if self._ml_anomaly_detection(features):
            detection = ThreatDetection(
                detection_id=f"ML_ANOM_{int(time.time())}",
                timestamp=packet.timestamp,
                threat_type='ml_anomaly',
                severity='MEDIUM',
                confidence=0.8,
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                detection_method='machine_learning',
                description='Machine learning model detected anomalous behavior',
                indicators=['ml_anomaly'],
                recommended_action='investigate',
                metadata={'features': features}
            )
            detections.append(detection)
        
        # Simple threat classification
        threat_class = self._ml_threat_classification(features)
        if threat_class != 'benign':
            detection = ThreatDetection(
                detection_id=f"ML_CLASS_{int(time.time())}",
                timestamp=packet.timestamp,
                threat_type=threat_class,
                severity='HIGH' if threat_class in ['malware', 'exploit'] else 'MEDIUM',
                confidence=0.75,
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                detection_method='machine_learning',
                description=f'ML classifier identified traffic as: {threat_class}',
                indicators=[f'ml_classification_{threat_class}'],
                recommended_action='block' if threat_class in ['malware', 'exploit'] else 'monitor',
                metadata={'classification': threat_class, 'features': features}
            )
            detections.append(detection)
        
        return detections
    
    def _extract_ml_features(self, packet: EnhancedPacket) -> Dict[str, float]:
        """Extract features for ML analysis"""
        features = {
            'packet_size': float(packet.payload_size),
            'inter_arrival_time': 0.0,  # Would calculate from previous packets
            'port_entropy': self._calculate_port_entropy(),
            'payload_entropy': self._calculate_payload_entropy(packet.payload_snippet),
            'connection_duration': 0.0,  # Would track from session data
            'packet_rate': self._calculate_packet_rate(packet.src_ip)
        }
        return features
    
    def _calculate_port_entropy(self) -> float:
        """Calculate entropy of port distribution"""
        ports = list(self.anomaly_baselines['port_distribution'].values())
        if not ports:
            return 0.0
        
        total = sum(ports)
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in ports:
            if count > 0:
                p = count / total
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _calculate_payload_entropy(self, payload: str) -> float:
        """Calculate entropy of payload data"""
        if not payload:
            return 0.0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in payload:
            char_counts[char] += 1
        
        # Calculate entropy
        total_chars = len(payload)
        entropy = 0.0
        for count in char_counts.values():
            p = count / total_chars
            entropy -= p * np.log2(p)
        
        return entropy
    
    def _calculate_packet_rate(self, src_ip: str) -> float:
        """Calculate packet rate for source IP"""
        current_time = time.time()
        recent_packets = [t for t in self.behavioral_state['packet_times'].get(src_ip, [])
                         if current_time - t < 60]
        return len(recent_packets) / 60.0
    
    def _ml_anomaly_detection(self, features: Dict[str, float]) -> bool:
        """Simple ML-like anomaly detection"""
        # Use statistical thresholds as proxy for ML model
        if len(self.feature_cache) < 50:
            return False
        
        # Calculate z-scores for features
        feature_arrays = defaultdict(list)
        for cached_features in self.feature_cache:
            for key, value in cached_features.items():
                feature_arrays[key].append(value)
        
        anomaly_score = 0
        for key, value in features.items():
            if key in feature_arrays and len(feature_arrays[key]) > 10:
                mean_val = np.mean(feature_arrays[key])
                std_val = np.std(feature_arrays[key])
                if std_val > 0:
                    z_score = abs(value - mean_val) / std_val
                    if z_score > 2.0:
                        anomaly_score += 1
        
        return anomaly_score >= 2
    
    def _ml_threat_classification(self, features: Dict[str, float]) -> str:
        """Simple ML-like threat classification"""
        # Rule-based classification as proxy for ML model
        
        # High entropy and large packets might indicate data exfiltration
        if features['payload_entropy'] > 7.0 and features['packet_size'] > 1000:
            return 'data_exfiltration'
        
        # High packet rate might indicate scanning
        if features['packet_rate'] > 10.0:
            return 'reconnaissance'
        
        # Low entropy might indicate malware
        if features['payload_entropy'] < 2.0 and features['packet_size'] > 100:
            return 'malware'
        
        return 'benign'
    
    def _behavioral_analysis(self, packet: EnhancedPacket) -> List[ThreatDetection]:
        """Perform behavioral pattern detection"""
        detections = []
        
        # Track packet for behavioral analysis
        self._update_behavioral_state(packet)
        
        # Check each behavioral pattern
        for pattern_name, pattern_config in self.behavioral_patterns.items():
            if self._check_behavioral_pattern(packet, pattern_name, pattern_config):
                detection = ThreatDetection(
                    detection_id=f"BEH_{pattern_name.upper()}_{int(time.time())}",
                    timestamp=packet.timestamp,
                    threat_type=pattern_name,
                    severity=pattern_config['severity'],
                    confidence=0.8,
                    source_ip=packet.src_ip,
                    destination_ip=packet.dst_ip,
                    detection_method='behavioral',
                    description=pattern_config['description'],
                    indicators=[pattern_name],
                    recommended_action='block' if pattern_config['severity'] == 'CRITICAL' else 'investigate',
                    metadata={'pattern': pattern_name, 'threshold': pattern_config['threshold']}
                )
                detections.append(detection)
        
        return detections
    
    def _update_behavioral_state(self, packet: EnhancedPacket):
        """Update behavioral tracking state"""
        current_time = packet.timestamp
        src_ip = packet.src_ip
        
        # Track connections
        if 'connections' not in self.behavioral_state:
            self.behavioral_state['connections'] = defaultdict(list)
        self.behavioral_state['connections'][src_ip].append(current_time)
        
        # Track packet times
        if 'packet_times' not in self.behavioral_state:
            self.behavioral_state['packet_times'] = defaultdict(list)
        self.behavioral_state['packet_times'][src_ip].append(current_time)
        
        # Track data volumes
        if 'data_volumes' not in self.behavioral_state:
            self.behavioral_state['data_volumes'] = defaultdict(int)
        self.behavioral_state['data_volumes'][src_ip] += packet.payload_size
        
        # Clean old entries
        self._cleanup_behavioral_state(current_time)
    
    def _cleanup_behavioral_state(self, current_time: float):
        """Clean up old behavioral state entries"""
        cutoff_time = current_time - 3600  # 1 hour
        
        for state_type in ['connections', 'packet_times']:
            if state_type in self.behavioral_state:
                for ip in list(self.behavioral_state[state_type].keys()):
                    self.behavioral_state[state_type][ip] = [
                        t for t in self.behavioral_state[state_type][ip] 
                        if t > cutoff_time
                    ]
                    if not self.behavioral_state[state_type][ip]:
                        del self.behavioral_state[state_type][ip]
    
    def _check_behavioral_pattern(self, packet: EnhancedPacket, pattern_name: str, 
                                 pattern_config: Dict[str, Any]) -> bool:
        """Check if behavioral pattern is detected"""
        current_time = packet.timestamp
        src_ip = packet.src_ip
        time_window = pattern_config['time_window']
        threshold = pattern_config['threshold']
        
        if pattern_name == 'port_scan':
            # Already handled in signature detection
            return False
        
        elif pattern_name == 'brute_force':
            # Check for repeated connections to same port
            recent_connections = [
                t for t in self.behavioral_state['connections'].get(src_ip, [])
                if current_time - t < time_window and packet.dst_port in [22, 23, 21, 3389]
            ]
            return len(recent_connections) >= threshold
        
        elif pattern_name == 'data_exfiltration':
            # Check for large data transfers
            recent_data = 0
            cutoff_time = current_time - time_window
            for ip, volume in self.behavioral_state['data_volumes'].items():
                if ip == src_ip:
                    recent_data += volume
            return recent_data >= threshold
        
        elif pattern_name == 'lateral_movement':
            # Check for internal network scanning
            if not self._is_internal_ip(src_ip):
                return False
            
            # Count unique internal destinations
            unique_destinations = set()
            for t in self.behavioral_state['connections'].get(src_ip, []):
                if current_time - t < time_window:
                    unique_destinations.add(packet.dst_ip)
            
            return len(unique_destinations) >= threshold
        
        return False
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _threat_intel_analysis(self, packet: EnhancedPacket) -> List[ThreatDetection]:
        """Perform threat intelligence analysis"""
        detections = []
        
        # Check malicious IPs
        if (packet.src_ip in self.threat_intel['malicious_ips'] or 
            packet.dst_ip in self.threat_intel['malicious_ips']):
            
            detection = ThreatDetection(
                detection_id=f"TI_IP_{int(time.time())}",
                timestamp=packet.timestamp,
                threat_type='malicious_ip',
                severity='HIGH',
                confidence=0.95,
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                detection_method='threat_intelligence',
                description='Communication with known malicious IP address',
                indicators=['malicious_ip'],
                recommended_action='block',
                metadata={'malicious_ip': packet.src_ip if packet.src_ip in self.threat_intel['malicious_ips'] else packet.dst_ip}
            )
            detections.append(detection)
        
        # Check payload hash against malware database
        if packet.payload_hash in self.threat_intel['malware_hashes']:
            detection = ThreatDetection(
                detection_id=f"TI_HASH_{int(time.time())}",
                timestamp=packet.timestamp,
                threat_type='malware',
                severity='CRITICAL',
                confidence=0.98,
                source_ip=packet.src_ip,
                destination_ip=packet.dst_ip,
                detection_method='threat_intelligence',
                description='Known malware hash detected in payload',
                indicators=['malware_hash'],
                recommended_action='block',
                metadata={'malware_hash': packet.payload_hash}
            )
            detections.append(detection)
        
        return detections
    
    def _handle_detection(self, detection: ThreatDetection):
        """Handle a threat detection"""
        # Add to detection queue
        try:
            self.detection_queue.put(detection, timeout=1.0)
        except queue.Full:
            self.logger.warning("Detection queue full, dropping detection")
        
        # Call registered callbacks
        for callback in self.detection_callbacks:
            try:
                callback(detection)
            except Exception as e:
                self.logger.error(f"Error in detection callback: {e}")
        
        # Log detection
        self.logger.warning(f"THREAT DETECTED: {detection.threat_type} from {detection.source_ip} "
                          f"(Severity: {detection.severity}, Confidence: {detection.confidence:.2f})")
    
    def _update_stats(self, processing_time: float, detection_count: int):
        """Update processing statistics"""
        self.stats['packets_processed'] += 1
        self.stats['threats_detected'] += detection_count
        
        # Update average processing time
        current_avg = self.stats['processing_time_avg']
        packet_count = self.stats['packets_processed']
        self.stats['processing_time_avg'] = ((current_avg * (packet_count - 1)) + processing_time) / packet_count
    
    def _stats_worker(self):
        """Worker thread for statistics reporting"""
        while self.running:
            time.sleep(60)  # Report every minute
            
            uptime = time.time() - self.stats['start_time']
            packets_per_second = self.stats['packets_processed'] / uptime if uptime > 0 else 0
            
            self.logger.info(f"Detection Engine Stats - "
                           f"Packets: {self.stats['packets_processed']}, "
                           f"Threats: {self.stats['threats_detected']}, "
                           f"Rate: {packets_per_second:.2f} pps, "
                           f"Avg Processing: {self.stats['processing_time_avg']*1000:.2f}ms")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current detection statistics"""
        uptime = time.time() - self.stats['start_time']
        return {
            'uptime_seconds': uptime,
            'packets_processed': self.stats['packets_processed'],
            'threats_detected': self.stats['threats_detected'],
            'false_positives': self.stats['false_positives'],
            'processing_rate': self.stats['packets_processed'] / uptime if uptime > 0 else 0,
            'average_processing_time_ms': self.stats['processing_time_avg'] * 1000,
            'detection_rates': dict(self.stats['detection_rates']),
            'queue_sizes': {
                'packet_queue': self.packet_queue.qsize(),
                'detection_queue': self.detection_queue.qsize()
            }
        }
    
    def get_recent_detections(self, limit: int = 100) -> List[ThreatDetection]:
        """Get recent threat detections"""
        detections = []
        temp_queue = queue.Queue()
        
        # Extract detections from queue
        while not self.detection_queue.empty() and len(detections) < limit:
            try:
                detection = self.detection_queue.get_nowait()
                detections.append(detection)
                temp_queue.put(detection)
            except queue.Empty:
                break
        
        # Put detections back in queue
        while not temp_queue.empty():
            self.detection_queue.put(temp_queue.get_nowait())
        
        return sorted(detections, key=lambda x: x.timestamp, reverse=True)

# Example usage and testing
if __name__ == "__main__":
    # Initialize enhanced detection engine
    config = {
        'signature_detection': {'enabled': True},
        'anomaly_detection': {'enabled': True, 'threshold': 2.5},
        'ml_detection': {'enabled': True, 'confidence_threshold': 0.7},
        'behavioral_detection': {'enabled': True},
        'threat_intelligence': {'enabled': True},
        'performance': {'max_workers': 2, 'batch_size': 50}
    }
    
    detector = EnhancedDetectionEngine(config)
    
    # Add detection callback
    def detection_callback(detection: ThreatDetection):
        print(f"🚨 ALERT: {detection.threat_type} - {detection.description}")
        print(f"   Source: {detection.source_ip} -> Destination: {detection.destination_ip}")
        print(f"   Severity: {detection.severity}, Confidence: {detection.confidence:.2f}")
        print(f"   Method: {detection.detection_method}")
        print()
    
    detector.add_detection_callback(detection_callback)
    
    # Start detection engine
    detector.start()
    
    # Simulate some packets for testing
    test_packets = [
        EnhancedPacket(
            timestamp=time.time(),
            src_ip="203.0.113.10",  # Malicious IP
            dst_ip="192.168.1.100",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            payload_size=500,
            flags=["SYN"],
            payload_hash="deadbeef" * 8,  # Malicious hash
            payload_snippet="MALICIOUS_PAYLOAD test data",
            direction="inbound",
            metadata={}
        ),
        EnhancedPacket(
            timestamp=time.time(),
            src_ip="192.168.1.50",
            dst_ip="192.168.1.100",
            src_port=54321,
            dst_port=22,
            protocol="TCP",
            payload_size=64,
            flags=["SYN"],
            payload_hash="normaldata123",
            payload_snippet="SSH connection attempt",
            direction="internal",
            metadata={}
        )
    ]
    
    print("🔥 Testing Enhanced Detection Engine")
    print("=" * 50)
    
    # Process test packets
    for i, packet in enumerate(test_packets):
        print(f"Processing test packet {i+1}...")
        detector.process_packet(packet)
        time.sleep(1)
    
    # Wait for processing
    time.sleep(3)
    
    # Get statistics
    stats = detector.get_statistics()
    print("📊 Detection Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Get recent detections
    recent_detections = detector.get_recent_detections(10)
    print(f"\n📋 Recent Detections ({len(recent_detections)}):")
    for detection in recent_detections:
        print(f"   {detection.detection_id}: {detection.threat_type} ({detection.severity})")
    
    # Stop detection engine
    detector.stop()
    print("\n✅ Enhanced Detection Engine test completed!")

