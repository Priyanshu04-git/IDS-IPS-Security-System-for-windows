"""
Threat Scoring System for IDS/IPS
Combines multiple detection methods to provide unified threat assessment
"""

import time
import json
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum
import math

class ThreatLevel(Enum):
    """Threat level enumeration"""
    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatScore:
    """Data class representing a threat score"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    
    # Individual component scores
    signature_score: float = 0.0
    anomaly_score: float = 0.0
    ml_score: float = 0.0
    behavioral_score: float = 0.0
    reputation_score: float = 0.0
    
    # Combined scores
    raw_score: float = 0.0
    normalized_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    confidence: float = 0.0
    
    # Supporting information
    contributing_factors: List[str] = None
    detection_methods: List[str] = None
    risk_factors: Dict[str, float] = None
    mitigation_suggestions: List[str] = None
    
    def __post_init__(self):
        if self.contributing_factors is None:
            self.contributing_factors = []
        if self.detection_methods is None:
            self.detection_methods = []
        if self.risk_factors is None:
            self.risk_factors = {}
        if self.mitigation_suggestions is None:
            self.mitigation_suggestions = []

class ThreatScoringEngine:
    """Main threat scoring engine that combines multiple detection methods"""
    
    def __init__(self, config_file: str = "threat_scoring_config.json"):
        self.logger = logging.getLogger(__name__)
        
        # Scoring weights for different detection methods
        self.weights = {
            'signature': 0.3,
            'anomaly': 0.25,
            'ml': 0.25,
            'behavioral': 0.15,
            'reputation': 0.05
        }
        
        # Threat level thresholds
        self.thresholds = {
            ThreatLevel.LOW: 0.2,
            ThreatLevel.MEDIUM: 0.4,
            ThreatLevel.HIGH: 0.7,
            ThreatLevel.CRITICAL: 0.9
        }
        
        # Severity multipliers
        self.severity_multipliers = {
            'LOW': 0.3,
            'MEDIUM': 0.6,
            'HIGH': 0.8,
            'CRITICAL': 1.0
        }
        
        # Category risk factors
        self.category_risks = {
            'INJECTION': 0.9,
            'EXPLOIT': 0.85,
            'MALWARE': 0.8,
            'BRUTE_FORCE': 0.7,
            'DDOS': 0.75,
            'RECONNAISSANCE': 0.4,
            'SCAN': 0.3,
            'ANOMALY': 0.6
        }
        
        # Historical scoring data
        self.ip_history: Dict[str, Dict] = defaultdict(lambda: {
            'scores': deque(maxlen=100),
            'detections': deque(maxlen=50),
            'first_seen': time.time(),
            'last_seen': time.time(),
            'total_detections': 0,
            'max_score': 0.0,
            'avg_score': 0.0
        })
        
        # Real-time scoring context
        self.scoring_context = {
            'active_attacks': defaultdict(list),
            'ip_reputation': defaultdict(float),
            'port_scan_tracking': defaultdict(set),
            'connection_patterns': defaultdict(list),
            'time_window': 300  # 5 minutes
        }
        
        # Statistics
        self.stats = {
            'total_scores': 0,
            'threat_levels': {level: 0 for level in ThreatLevel},
            'avg_score': 0.0,
            'max_score': 0.0,
            'start_time': time.time()
        }
        
        self._lock = threading.RLock()
        
        # Load configuration if available
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            self.weights.update(config.get('weights', {}))
            
            # Update thresholds
            threshold_config = config.get('thresholds', {})
            for level_name, threshold in threshold_config.items():
                if hasattr(ThreatLevel, level_name):
                    level = getattr(ThreatLevel, level_name)
                    self.thresholds[level] = threshold
            
            self.severity_multipliers.update(config.get('severity_multipliers', {}))
            self.category_risks.update(config.get('category_risks', {}))
            
            self.logger.info(f"Loaded configuration from {self.config_file}")
            
        except FileNotFoundError:
            self.logger.info("No configuration file found, using defaults")
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            config = {
                'weights': self.weights,
                'thresholds': {level.name: threshold for level, threshold in self.thresholds.items()},
                'severity_multipliers': self.severity_multipliers,
                'category_risks': self.category_risks
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            self.logger.info(f"Saved configuration to {self.config_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
    
    def calculate_threat_score(self, packet_info, detections: Dict[str, List] = None) -> ThreatScore:
        """Calculate comprehensive threat score for a packet"""
        
        with self._lock:
            current_time = time.time()
            
            # Initialize threat score
            threat_score = ThreatScore(
                timestamp=current_time,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                protocol=packet_info.protocol
            )
            
            if not detections:
                detections = {}
            
            # Calculate individual component scores
            threat_score.signature_score = self._calculate_signature_score(
                detections.get('signature', [])
            )
            
            threat_score.anomaly_score = self._calculate_anomaly_score(
                detections.get('anomaly', [])
            )
            
            threat_score.ml_score = self._calculate_ml_score(
                detections.get('ml', [])
            )
            
            threat_score.behavioral_score = self._calculate_behavioral_score(
                packet_info, detections.get('behavioral', [])
            )
            
            threat_score.reputation_score = self._calculate_reputation_score(
                packet_info.src_ip
            )
            
            # Calculate weighted combined score
            threat_score.raw_score = (
                threat_score.signature_score * self.weights['signature'] +
                threat_score.anomaly_score * self.weights['anomaly'] +
                threat_score.ml_score * self.weights['ml'] +
                threat_score.behavioral_score * self.weights['behavioral'] +
                threat_score.reputation_score * self.weights['reputation']
            )
            
            # Apply contextual adjustments
            threat_score.raw_score = self._apply_contextual_adjustments(
                threat_score.raw_score, packet_info
            )
            
            # Normalize score (0-1 range)
            threat_score.normalized_score = min(max(threat_score.raw_score, 0.0), 1.0)
            
            # Determine threat level
            threat_score.threat_level = self._determine_threat_level(threat_score.normalized_score)
            
            # Calculate confidence
            threat_score.confidence = self._calculate_confidence(threat_score, detections)
            
            # Add supporting information
            self._add_supporting_information(threat_score, detections)
            
            # Update historical data
            self._update_history(threat_score)
            
            # Update statistics
            self._update_stats(threat_score)
            
            return threat_score
    
    def _calculate_signature_score(self, signature_detections: List) -> float:
        """Calculate score based on signature detections"""
        if not signature_detections:
            return 0.0
        
        max_score = 0.0
        total_weight = 0.0
        
        for detection in signature_detections:
            # Get severity multiplier
            severity = getattr(detection, 'severity', 'MEDIUM')
            severity_mult = self.severity_multipliers.get(severity, 0.6)
            
            # Get category risk factor
            category = getattr(detection, 'category', 'UNKNOWN')
            category_risk = self.category_risks.get(category, 0.5)
            
            # Calculate detection score
            detection_score = severity_mult * category_risk
            
            # Weight by confidence if available
            confidence = getattr(detection, 'confidence', 1.0)
            weighted_score = detection_score * confidence
            
            max_score = max(max_score, weighted_score)
            total_weight += confidence
        
        # Return weighted average with emphasis on highest score
        if total_weight > 0:
            avg_score = sum(
                self.severity_multipliers.get(getattr(d, 'severity', 'MEDIUM'), 0.6) * 
                self.category_risks.get(getattr(d, 'category', 'UNKNOWN'), 0.5) * 
                getattr(d, 'confidence', 1.0)
                for d in signature_detections
            ) / total_weight
            
            return (max_score * 0.7) + (avg_score * 0.3)
        
        return max_score
    
    def _calculate_anomaly_score(self, anomaly_detections: List) -> float:
        """Calculate score based on anomaly detections"""
        if not anomaly_detections:
            return 0.0
        
        scores = []
        for detection in anomaly_detections:
            # Get anomaly score (z-score or similar)
            anomaly_score = getattr(detection, 'anomaly_score', 0.0)
            
            # Normalize z-score to 0-1 range (assuming z-scores up to 5)
            normalized_score = min(anomaly_score / 5.0, 1.0)
            
            # Apply severity multiplier
            severity = getattr(detection, 'severity', 'MEDIUM')
            severity_mult = self.severity_multipliers.get(severity, 0.6)
            
            # Weight by confidence
            confidence = getattr(detection, 'confidence', 1.0)
            
            final_score = normalized_score * severity_mult * confidence
            scores.append(final_score)
        
        # Return maximum score (anomalies are often binary)
        return max(scores) if scores else 0.0
    
    def _calculate_ml_score(self, ml_detections: List) -> float:
        """Calculate score based on ML detections"""
        if not ml_detections:
            return 0.0
        
        scores = []
        for detection in ml_detections:
            prediction = getattr(detection, 'prediction', 'BENIGN')
            confidence = getattr(detection, 'confidence', 0.0)
            
            if prediction in ['MALICIOUS', 'ANOMALY']:
                # Use confidence directly for ML predictions
                scores.append(confidence)
            else:
                # Benign predictions contribute negatively
                scores.append(-confidence * 0.1)
        
        # Return weighted average
        if scores:
            return max(0.0, sum(scores) / len(scores))
        
        return 0.0
    
    def _calculate_behavioral_score(self, packet_info, behavioral_detections: List) -> float:
        """Calculate score based on behavioral analysis"""
        score = 0.0
        
        # Process behavioral detections
        for detection in behavioral_detections:
            severity = getattr(detection, 'severity', 'MEDIUM')
            severity_mult = self.severity_multipliers.get(severity, 0.6)
            confidence = getattr(detection, 'confidence', 1.0)
            
            score = max(score, severity_mult * confidence)
        
        # Add contextual behavioral factors
        src_ip = packet_info.src_ip
        
        # Check for port scanning behavior
        if packet_info.dst_port:
            self.scoring_context['port_scan_tracking'][src_ip].add(packet_info.dst_port)
            unique_ports = len(self.scoring_context['port_scan_tracking'][src_ip])
            
            if unique_ports > 10:
                port_scan_score = min(unique_ports / 50.0, 0.8)
                score = max(score, port_scan_score)
        
        # Check connection patterns
        connection_key = f"{packet_info.dst_ip}:{packet_info.dst_port}"
        self.scoring_context['connection_patterns'][src_ip].append({
            'connection': connection_key,
            'timestamp': packet_info.timestamp
        })
        
        # Clean old connections
        current_time = packet_info.timestamp
        self.scoring_context['connection_patterns'][src_ip] = [
            conn for conn in self.scoring_context['connection_patterns'][src_ip]
            if current_time - conn['timestamp'] < self.scoring_context['time_window']
        ]
        
        # Check for rapid connections
        recent_connections = len(self.scoring_context['connection_patterns'][src_ip])
        if recent_connections > 20:
            rapid_conn_score = min(recent_connections / 100.0, 0.6)
            score = max(score, rapid_conn_score)
        
        return min(score, 1.0)
    
    def _calculate_reputation_score(self, ip_address: str) -> float:
        """Calculate score based on IP reputation"""
        # Get stored reputation
        reputation = self.scoring_context['ip_reputation'].get(ip_address, 0.0)
        
        # Get historical data
        history = self.ip_history[ip_address]
        
        # Factor in historical behavior
        if history['total_detections'] > 0:
            detection_rate = history['total_detections'] / max(len(history['scores']), 1)
            historical_score = min(detection_rate * 0.1, 0.5)
            reputation = max(reputation, historical_score)
        
        # Factor in recent activity
        if history['scores']:
            recent_avg = sum(list(history['scores'])[-10:]) / min(len(history['scores']), 10)
            reputation = max(reputation, recent_avg * 0.3)
        
        return min(reputation, 1.0)
    
    def _apply_contextual_adjustments(self, base_score: float, packet_info) -> float:
        """Apply contextual adjustments to the base score"""
        adjusted_score = base_score
        
        # Time-based adjustments
        current_hour = datetime.fromtimestamp(packet_info.timestamp).hour
        
        # Higher risk during off-hours
        if current_hour < 6 or current_hour > 22:
            adjusted_score *= 1.1
        
        # Protocol-based adjustments
        if packet_info.protocol == 'ICMP':
            adjusted_score *= 0.8  # ICMP is often less critical
        elif packet_info.protocol == 'UDP':
            adjusted_score *= 0.9  # UDP slightly less critical than TCP
        
        # Port-based adjustments
        if packet_info.dst_port:
            # Higher risk for common attack targets
            high_risk_ports = {22, 23, 80, 443, 3389, 1433, 3306}
            if packet_info.dst_port in high_risk_ports:
                adjusted_score *= 1.2
            
            # Lower risk for high-numbered ports
            elif packet_info.dst_port > 49152:
                adjusted_score *= 0.9
        
        # Packet size adjustments
        if packet_info.packet_size > 8000:  # Large packets
            adjusted_score *= 1.1
        elif packet_info.packet_size < 100:  # Very small packets
            adjusted_score *= 1.05
        
        return adjusted_score
    
    def _determine_threat_level(self, normalized_score: float) -> ThreatLevel:
        """Determine threat level based on normalized score"""
        if normalized_score >= self.thresholds[ThreatLevel.CRITICAL]:
            return ThreatLevel.CRITICAL
        elif normalized_score >= self.thresholds[ThreatLevel.HIGH]:
            return ThreatLevel.HIGH
        elif normalized_score >= self.thresholds[ThreatLevel.MEDIUM]:
            return ThreatLevel.MEDIUM
        elif normalized_score >= self.thresholds[ThreatLevel.LOW]:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.BENIGN
    
    def _calculate_confidence(self, threat_score: ThreatScore, detections: Dict) -> float:
        """Calculate confidence in the threat assessment"""
        confidence_factors = []
        
        # Number of detection methods that triggered
        active_methods = sum(1 for score in [
            threat_score.signature_score,
            threat_score.anomaly_score,
            threat_score.ml_score,
            threat_score.behavioral_score
        ] if score > 0.1)
        
        method_confidence = min(active_methods / 4.0, 1.0)
        confidence_factors.append(method_confidence)
        
        # Individual detection confidences
        for detection_list in detections.values():
            if detection_list:
                avg_confidence = sum(
                    getattr(d, 'confidence', 0.5) for d in detection_list
                ) / len(detection_list)
                confidence_factors.append(avg_confidence)
        
        # Historical consistency
        history = self.ip_history[threat_score.src_ip]
        if history['scores']:
            recent_scores = list(history['scores'])[-5:]
            if len(recent_scores) > 1:
                score_consistency = 1.0 - (
                    max(recent_scores) - min(recent_scores)
                )
                confidence_factors.append(max(score_consistency, 0.0))
        
        # Return weighted average
        if confidence_factors:
            return sum(confidence_factors) / len(confidence_factors)
        else:
            return 0.5  # Default confidence
    
    def _add_supporting_information(self, threat_score: ThreatScore, detections: Dict):
        """Add supporting information to threat score"""
        
        # Contributing factors
        if threat_score.signature_score > 0.1:
            threat_score.contributing_factors.append("Signature-based detection")
            threat_score.detection_methods.append("signature")
        
        if threat_score.anomaly_score > 0.1:
            threat_score.contributing_factors.append("Anomaly detection")
            threat_score.detection_methods.append("anomaly")
        
        if threat_score.ml_score > 0.1:
            threat_score.contributing_factors.append("Machine learning detection")
            threat_score.detection_methods.append("ml")
        
        if threat_score.behavioral_score > 0.1:
            threat_score.contributing_factors.append("Behavioral analysis")
            threat_score.detection_methods.append("behavioral")
        
        if threat_score.reputation_score > 0.1:
            threat_score.contributing_factors.append("IP reputation")
            threat_score.detection_methods.append("reputation")
        
        # Risk factors
        threat_score.risk_factors = {
            'signature_risk': threat_score.signature_score,
            'anomaly_risk': threat_score.anomaly_score,
            'ml_risk': threat_score.ml_score,
            'behavioral_risk': threat_score.behavioral_score,
            'reputation_risk': threat_score.reputation_score
        }
        
        # Mitigation suggestions
        if threat_score.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            threat_score.mitigation_suggestions.extend([
                "Block source IP address",
                "Increase monitoring of source IP",
                "Review firewall rules",
                "Investigate potential compromise"
            ])
        elif threat_score.threat_level == ThreatLevel.MEDIUM:
            threat_score.mitigation_suggestions.extend([
                "Monitor source IP closely",
                "Review access logs",
                "Consider rate limiting"
            ])
        elif threat_score.threat_level == ThreatLevel.LOW:
            threat_score.mitigation_suggestions.extend([
                "Log for future reference",
                "Monitor for patterns"
            ])
    
    def _update_history(self, threat_score: ThreatScore):
        """Update historical data for the source IP"""
        src_ip = threat_score.src_ip
        history = self.ip_history[src_ip]
        
        # Update scores
        history['scores'].append(threat_score.normalized_score)
        history['last_seen'] = threat_score.timestamp
        
        # Update detection count
        if threat_score.threat_level != ThreatLevel.BENIGN:
            history['total_detections'] += 1
            history['detections'].append({
                'timestamp': threat_score.timestamp,
                'score': threat_score.normalized_score,
                'level': threat_score.threat_level.name
            })
        
        # Update statistics
        if history['scores']:
            history['max_score'] = max(history['scores'])
            history['avg_score'] = sum(history['scores']) / len(history['scores'])
        
        # Update reputation based on recent behavior
        if len(history['scores']) >= 5:
            recent_avg = sum(list(history['scores'])[-5:]) / 5
            if recent_avg > 0.3:
                self.scoring_context['ip_reputation'][src_ip] = min(
                    self.scoring_context['ip_reputation'][src_ip] + 0.1,
                    1.0
                )
    
    def _update_stats(self, threat_score: ThreatScore):
        """Update global statistics"""
        self.stats['total_scores'] += 1
        self.stats['threat_levels'][threat_score.threat_level] += 1
        
        # Update average score
        current_avg = self.stats['avg_score']
        total_scores = self.stats['total_scores']
        self.stats['avg_score'] = (
            (current_avg * (total_scores - 1) + threat_score.normalized_score) / total_scores
        )
        
        # Update max score
        self.stats['max_score'] = max(self.stats['max_score'], threat_score.normalized_score)
    
    def get_ip_risk_profile(self, ip_address: str) -> Dict[str, Any]:
        """Get comprehensive risk profile for an IP address"""
        history = self.ip_history[ip_address]
        
        profile = {
            'ip_address': ip_address,
            'first_seen': history['first_seen'],
            'last_seen': history['last_seen'],
            'total_detections': history['total_detections'],
            'max_score': history['max_score'],
            'avg_score': history['avg_score'],
            'reputation_score': self.scoring_context['ip_reputation'][ip_address],
            'recent_scores': list(history['scores'])[-10:],
            'recent_detections': list(history['detections'])[-5:],
            'risk_level': 'HIGH' if history['avg_score'] > 0.6 else 
                         'MEDIUM' if history['avg_score'] > 0.3 else 'LOW'
        }
        
        return profile
    
    def get_stats(self) -> Dict[str, Any]:
        """Get threat scoring statistics"""
        current_time = time.time()
        runtime = current_time - self.stats['start_time']
        
        stats = self.stats.copy()
        stats['runtime'] = runtime
        stats['unique_ips'] = len(self.ip_history)
        stats['threat_level_distribution'] = {
            level.name: count for level, count in self.stats['threat_levels'].items()
        }
        
        if runtime > 0:
            stats['scores_per_second'] = self.stats['total_scores'] / runtime
        
        return stats
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'total_scores': 0,
            'threat_levels': {level: 0 for level in ThreatLevel},
            'avg_score': 0.0,
            'max_score': 0.0,
            'start_time': time.time()
        }

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create threat scoring engine
    scoring_engine = ThreatScoringEngine()
    
    # Test with sample packet and detections
    from packet_capture.packet_sniffer import PacketInfo
    from detection_engine.signature_detector import DetectionResult
    from detection_engine.anomaly_detector import AnomalyResult
    
    # Create test packet
    test_packet = PacketInfo(
        timestamp=time.time(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=22,
        protocol="TCP",
        packet_size=64,
        flags="SYN",
        payload_size=0
    )
    
    # Create mock detections
    signature_detection = DetectionResult(
        signature_id="SSH_BRUTE_001",
        signature_name="SSH Brute Force",
        severity="HIGH",
        category="BRUTE_FORCE",
        timestamp=time.time(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=22,
        protocol="TCP",
        matched_content="SSH",
        confidence=0.9
    )
    
    anomaly_detection = AnomalyResult(
        anomaly_type="PORT_SCAN",
        severity="MEDIUM",
        timestamp=time.time(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=22,
        protocol="TCP",
        anomaly_score=3.5,
        baseline_value=1.0,
        observed_value=25.0,
        description="Port scanning detected",
        confidence=0.8
    )
    
    # Test threat scoring
    detections = {
        'signature': [signature_detection],
        'anomaly': [anomaly_detection],
        'ml': [],
        'behavioral': []
    }
    
    print("Calculating threat score...")
    threat_score = scoring_engine.calculate_threat_score(test_packet, detections)
    
    print(f"\nThreat Assessment Results:")
    print(f"Source IP: {threat_score.src_ip}")
    print(f"Threat Level: {threat_score.threat_level.name}")
    print(f"Normalized Score: {threat_score.normalized_score:.3f}")
    print(f"Confidence: {threat_score.confidence:.3f}")
    print(f"\nComponent Scores:")
    print(f"  Signature: {threat_score.signature_score:.3f}")
    print(f"  Anomaly: {threat_score.anomaly_score:.3f}")
    print(f"  ML: {threat_score.ml_score:.3f}")
    print(f"  Behavioral: {threat_score.behavioral_score:.3f}")
    print(f"  Reputation: {threat_score.reputation_score:.3f}")
    print(f"\nContributing Factors:")
    for factor in threat_score.contributing_factors:
        print(f"  - {factor}")
    print(f"\nMitigation Suggestions:")
    for suggestion in threat_score.mitigation_suggestions:
        print(f"  - {suggestion}")
    
    # Test multiple packets to build history
    print("\nBuilding IP history with multiple packets...")
    for i in range(10):
        test_packet.timestamp = time.time()
        test_packet.dst_port = 20 + i  # Different ports for scanning
        
        # Vary detection severity
        if i % 3 == 0:
            signature_detection.severity = "CRITICAL"
        elif i % 3 == 1:
            signature_detection.severity = "HIGH"
        else:
            signature_detection.severity = "MEDIUM"
        
        score = scoring_engine.calculate_threat_score(test_packet, detections)
        time.sleep(0.1)
    
    # Get IP risk profile
    print("\nIP Risk Profile:")
    risk_profile = scoring_engine.get_ip_risk_profile("192.168.1.100")
    for key, value in risk_profile.items():
        if key not in ['recent_scores', 'recent_detections']:
            print(f"  {key}: {value}")
    
    # Print statistics
    print("\nThreat Scoring Statistics:")
    stats = scoring_engine.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Save configuration
    scoring_engine.save_config()

