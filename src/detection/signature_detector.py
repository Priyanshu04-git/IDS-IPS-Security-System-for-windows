"""
Signature-Based Detection Engine for IDS/IPS System
Detects known threats using pattern matching and signature databases
"""

import json
import re
import time
import logging
import threading
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import hashlib

@dataclass
class Signature:
    """Data class representing a detection signature"""
    id: str
    name: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str  # MALWARE, EXPLOIT, RECONNAISSANCE, etc.
    pattern: str
    pattern_type: str  # REGEX, STRING, HEX
    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    direction: str = "ANY"  # INBOUND, OUTBOUND, ANY
    enabled: bool = True
    created_date: str = ""
    updated_date: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if not self.created_date:
            self.created_date = datetime.now().isoformat()
        if not self.updated_date:
            self.updated_date = self.created_date

@dataclass
class DetectionResult:
    """Data class representing a detection result"""
    signature_id: str
    signature_name: str
    severity: str
    category: str
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    matched_content: str
    confidence: float = 1.0
    additional_info: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}

class SignatureDatabase:
    """Manages signature database operations"""
    
    def __init__(self, db_path: str = "signatures.json"):
        self.db_path = Path(db_path)
        self.signatures: Dict[str, Signature] = {}
        self.compiled_patterns: Dict[str, re.Pattern] = {}
        self.last_update = None
        self.logger = logging.getLogger(__name__)
        self._lock = threading.RLock()
        
        # Load signatures if database exists
        if self.db_path.exists():
            self.load_signatures()
        else:
            self._create_default_signatures()
    
    def _create_default_signatures(self):
        """Create default signature database with common attack patterns"""
        default_signatures = [
            # SQL Injection signatures
            Signature(
                id="SQL_001",
                name="SQL Injection - UNION SELECT",
                description="Detects SQL injection attempts using UNION SELECT",
                severity="HIGH",
                category="INJECTION",
                pattern=r"(?i)(union\s+select|union\s+all\s+select)",
                pattern_type="REGEX",
                protocol="TCP",
                dst_port=80
            ),
            Signature(
                id="SQL_002",
                name="SQL Injection - OR 1=1",
                description="Detects SQL injection attempts using OR 1=1",
                severity="HIGH",
                category="INJECTION",
                pattern=r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')",
                pattern_type="REGEX",
                protocol="TCP",
                dst_port=80
            ),
            
            # XSS signatures
            Signature(
                id="XSS_001",
                name="Cross-Site Scripting - Script Tag",
                description="Detects XSS attempts using script tags",
                severity="MEDIUM",
                category="INJECTION",
                pattern=r"(?i)<script[^>]*>.*?</script>",
                pattern_type="REGEX",
                protocol="TCP",
                dst_port=80
            ),
            
            # Command Injection signatures
            Signature(
                id="CMD_001",
                name="Command Injection - System Commands",
                description="Detects command injection attempts",
                severity="HIGH",
                category="INJECTION",
                pattern=r"(?i)(;|\||\&)\s*(cat|ls|pwd|whoami|id|uname|wget|curl)",
                pattern_type="REGEX",
                protocol="TCP"
            ),
            
            # Port Scanning signatures
            Signature(
                id="SCAN_001",
                name="Port Scan - TCP SYN Scan",
                description="Detects TCP SYN port scanning",
                severity="MEDIUM",
                category="RECONNAISSANCE",
                pattern="SYN",
                pattern_type="STRING",
                protocol="TCP"
            ),
            
            # Brute Force signatures
            Signature(
                id="BRUTE_001",
                name="SSH Brute Force",
                description="Detects SSH brute force attempts",
                severity="HIGH",
                category="BRUTE_FORCE",
                pattern="SSH",
                pattern_type="STRING",
                protocol="TCP",
                dst_port=22
            ),
            
            # Malware signatures
            Signature(
                id="MAL_001",
                name="Malware - Suspicious User Agent",
                description="Detects suspicious user agents associated with malware",
                severity="HIGH",
                category="MALWARE",
                pattern=r"(?i)(bot|crawler|spider|wget|curl|python|powershell)",
                pattern_type="REGEX",
                protocol="TCP",
                dst_port=80
            ),
            
            # DDoS signatures
            Signature(
                id="DDOS_001",
                name="DDoS - High Connection Rate",
                description="Detects potential DDoS attacks based on connection patterns",
                severity="HIGH",
                category="DDOS",
                pattern="SYN",
                pattern_type="STRING",
                protocol="TCP"
            ),
            
            # Directory Traversal signatures
            Signature(
                id="TRAV_001",
                name="Directory Traversal",
                description="Detects directory traversal attempts",
                severity="MEDIUM",
                category="INJECTION",
                pattern=r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)",
                pattern_type="REGEX",
                protocol="TCP",
                dst_port=80
            ),
            
            # Buffer Overflow signatures
            Signature(
                id="BOF_001",
                name="Buffer Overflow - Long String",
                description="Detects potential buffer overflow attempts",
                severity="HIGH",
                category="EXPLOIT",
                pattern="A" * 100,  # Long string of A's
                pattern_type="STRING",
                protocol="TCP"
            )
        ]
        
        for sig in default_signatures:
            self.add_signature(sig)
        
        self.save_signatures()
        self.logger.info(f"Created default signature database with {len(default_signatures)} signatures")
    
    def add_signature(self, signature: Signature) -> bool:
        """Add a new signature to the database"""
        with self._lock:
            try:
                # Compile pattern for regex signatures
                if signature.pattern_type == "REGEX":
                    compiled_pattern = re.compile(signature.pattern)
                    self.compiled_patterns[signature.id] = compiled_pattern
                
                self.signatures[signature.id] = signature
                self.last_update = time.time()
                self.logger.info(f"Added signature: {signature.id} - {signature.name}")
                return True
                
            except re.error as e:
                self.logger.error(f"Invalid regex pattern in signature {signature.id}: {e}")
                return False
            except Exception as e:
                self.logger.error(f"Error adding signature {signature.id}: {e}")
                return False
    
    def remove_signature(self, signature_id: str) -> bool:
        """Remove a signature from the database"""
        with self._lock:
            if signature_id in self.signatures:
                del self.signatures[signature_id]
                if signature_id in self.compiled_patterns:
                    del self.compiled_patterns[signature_id]
                self.last_update = time.time()
                self.logger.info(f"Removed signature: {signature_id}")
                return True
            return False
    
    def update_signature(self, signature: Signature) -> bool:
        """Update an existing signature"""
        with self._lock:
            if signature.id in self.signatures:
                signature.updated_date = datetime.now().isoformat()
                return self.add_signature(signature)
            return False
    
    def get_signature(self, signature_id: str) -> Optional[Signature]:
        """Get a signature by ID"""
        return self.signatures.get(signature_id)
    
    def get_signatures_by_category(self, category: str) -> List[Signature]:
        """Get all signatures in a specific category"""
        return [sig for sig in self.signatures.values() if sig.category == category]
    
    def get_enabled_signatures(self) -> List[Signature]:
        """Get all enabled signatures"""
        return [sig for sig in self.signatures.values() if sig.enabled]
    
    def load_signatures(self) -> bool:
        """Load signatures from JSON file"""
        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)
            
            self.signatures.clear()
            self.compiled_patterns.clear()
            
            for sig_data in data.get('signatures', []):
                signature = Signature(**sig_data)
                self.add_signature(signature)
            
            self.last_update = data.get('last_update', time.time())
            self.logger.info(f"Loaded {len(self.signatures)} signatures from {self.db_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading signatures: {e}")
            return False
    
    def save_signatures(self) -> bool:
        """Save signatures to JSON file"""
        try:
            data = {
                'last_update': self.last_update or time.time(),
                'signatures': [asdict(sig) for sig in self.signatures.values()]
            }
            
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Saved {len(self.signatures)} signatures to {self.db_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving signatures: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get signature database statistics"""
        categories = {}
        severities = {}
        enabled_count = 0
        
        for sig in self.signatures.values():
            categories[sig.category] = categories.get(sig.category, 0) + 1
            severities[sig.severity] = severities.get(sig.severity, 0) + 1
            if sig.enabled:
                enabled_count += 1
        
        return {
            'total_signatures': len(self.signatures),
            'enabled_signatures': enabled_count,
            'disabled_signatures': len(self.signatures) - enabled_count,
            'categories': categories,
            'severities': severities,
            'last_update': self.last_update
        }

class SignatureDetector:
    """Main signature-based detection engine"""
    
    def __init__(self, signature_db: SignatureDatabase):
        self.signature_db = signature_db
        self.logger = logging.getLogger(__name__)
        self.stats = {
            'packets_analyzed': 0,
            'detections': 0,
            'false_positives': 0,
            'start_time': time.time()
        }
        
        # Detection caching to prevent duplicate alerts
        self.detection_cache: Dict[str, float] = {}
        self.cache_timeout = 300  # 5 minutes
        
        # Rate limiting for detections
        self.rate_limits: Dict[str, List[float]] = {}
        self.rate_limit_window = 60  # 1 minute
        self.max_detections_per_window = 10
    
    def analyze_packet(self, packet_info) -> List[DetectionResult]:
        """Analyze a packet against all signatures"""
        self.stats['packets_analyzed'] += 1
        detections = []
        
        # Get packet content for analysis
        content = self._extract_content(packet_info)
        if not content:
            return detections
        
        # Check against all enabled signatures
        for signature in self.signature_db.get_enabled_signatures():
            if self._matches_signature_criteria(packet_info, signature):
                detection = self._check_signature_match(packet_info, signature, content)
                if detection:
                    # Check for rate limiting and caching
                    if self._should_report_detection(detection):
                        detections.append(detection)
                        self.stats['detections'] += 1
        
        return detections
    
    def _extract_content(self, packet_info) -> str:
        """Extract content from packet for analysis"""
        content_parts = []
        
        # Add basic packet information
        content_parts.append(f"{packet_info.src_ip}:{packet_info.src_port}")
        content_parts.append(f"{packet_info.dst_ip}:{packet_info.dst_port}")
        content_parts.append(packet_info.protocol)
        
        if packet_info.flags:
            content_parts.append(packet_info.flags)
        
        # If raw packet data is available, include it
        if packet_info.raw_packet:
            try:
                # Try to decode as UTF-8, fallback to hex representation
                decoded = packet_info.raw_packet.decode('utf-8', errors='ignore')
                content_parts.append(decoded)
            except:
                content_parts.append(packet_info.raw_packet.hex())
        
        return " ".join(content_parts)
    
    def _matches_signature_criteria(self, packet_info, signature: Signature) -> bool:
        """Check if packet matches signature criteria (protocol, ports, etc.)"""
        
        # Protocol check
        if signature.protocol and signature.protocol != packet_info.protocol:
            return False
        
        # Source port check
        if signature.src_port and signature.src_port != packet_info.src_port:
            return False
        
        # Destination port check
        if signature.dst_port and signature.dst_port != packet_info.dst_port:
            return False
        
        # Direction check (simplified - would need more context in real implementation)
        # For now, we'll assume all packets match direction criteria
        
        return True
    
    def _check_signature_match(self, packet_info, signature: Signature, content: str) -> Optional[DetectionResult]:
        """Check if content matches signature pattern"""
        try:
            matched_content = ""
            
            if signature.pattern_type == "REGEX":
                pattern = self.signature_db.compiled_patterns.get(signature.id)
                if pattern:
                    match = pattern.search(content)
                    if match:
                        matched_content = match.group(0)
                    else:
                        return None
                else:
                    return None
                    
            elif signature.pattern_type == "STRING":
                if signature.pattern.lower() in content.lower():
                    matched_content = signature.pattern
                else:
                    return None
                    
            elif signature.pattern_type == "HEX":
                hex_pattern = signature.pattern.replace(" ", "").lower()
                if hex_pattern in content.lower():
                    matched_content = hex_pattern
                else:
                    return None
            
            # Create detection result
            detection = DetectionResult(
                signature_id=signature.id,
                signature_name=signature.name,
                severity=signature.severity,
                category=signature.category,
                timestamp=packet_info.timestamp,
                src_ip=packet_info.src_ip,
                dst_ip=packet_info.dst_ip,
                src_port=packet_info.src_port,
                dst_port=packet_info.dst_port,
                protocol=packet_info.protocol,
                matched_content=matched_content[:200],  # Limit content length
                confidence=self._calculate_confidence(signature, matched_content),
                additional_info={
                    'packet_size': packet_info.packet_size,
                    'payload_size': packet_info.payload_size,
                    'flags': packet_info.flags
                }
            )
            
            return detection
            
        except Exception as e:
            self.logger.error(f"Error checking signature {signature.id}: {e}")
            return None
    
    def _calculate_confidence(self, signature: Signature, matched_content: str) -> float:
        """Calculate confidence score for detection"""
        confidence = 1.0
        
        # Adjust confidence based on signature category
        if signature.category in ["RECONNAISSANCE", "SCAN"]:
            confidence *= 0.8
        elif signature.category in ["INJECTION", "EXPLOIT"]:
            confidence *= 0.95
        
        # Adjust confidence based on matched content length
        if len(matched_content) < 10:
            confidence *= 0.9
        
        # Adjust confidence based on severity
        severity_multipliers = {
            "LOW": 0.7,
            "MEDIUM": 0.8,
            "HIGH": 0.9,
            "CRITICAL": 1.0
        }
        confidence *= severity_multipliers.get(signature.severity, 0.8)
        
        return min(confidence, 1.0)
    
    def _should_report_detection(self, detection: DetectionResult) -> bool:
        """Check if detection should be reported (rate limiting and caching)"""
        current_time = time.time()
        
        # Create cache key
        cache_key = f"{detection.signature_id}:{detection.src_ip}:{detection.dst_ip}"
        
        # Check cache
        if cache_key in self.detection_cache:
            if current_time - self.detection_cache[cache_key] < self.cache_timeout:
                return False
        
        # Check rate limiting
        rate_key = f"{detection.signature_id}:{detection.src_ip}"
        if rate_key not in self.rate_limits:
            self.rate_limits[rate_key] = []
        
        # Clean old entries
        self.rate_limits[rate_key] = [
            t for t in self.rate_limits[rate_key] 
            if current_time - t < self.rate_limit_window
        ]
        
        # Check rate limit
        if len(self.rate_limits[rate_key]) >= self.max_detections_per_window:
            return False
        
        # Update cache and rate limit
        self.detection_cache[cache_key] = current_time
        self.rate_limits[rate_key].append(current_time)
        
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection engine statistics"""
        current_time = time.time()
        runtime = current_time - self.stats['start_time']
        
        stats = self.stats.copy()
        stats['runtime'] = runtime
        
        if runtime > 0:
            stats['packets_per_second'] = self.stats['packets_analyzed'] / runtime
            stats['detections_per_second'] = self.stats['detections'] / runtime
        
        stats['detection_rate'] = (
            self.stats['detections'] / self.stats['packets_analyzed'] 
            if self.stats['packets_analyzed'] > 0 else 0
        )
        
        return stats
    
    def reset_stats(self):
        """Reset detection statistics"""
        self.stats = {
            'packets_analyzed': 0,
            'detections': 0,
            'false_positives': 0,
            'start_time': time.time()
        }

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create signature database and detector
    sig_db = SignatureDatabase("test_signatures.json")
    detector = SignatureDetector(sig_db)
    
    # Print database stats
    print("Signature Database Stats:")
    print(json.dumps(sig_db.get_stats(), indent=2))
    
    # Test with sample packet data
    from packet_capture.packet_sniffer import PacketInfo
    
    test_packets = [
        PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packet_size=1024,
            flags="SYN",
            payload_size=0,
            raw_packet=b"GET /admin' OR 1=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ),
        PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.101",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=80,
            protocol="TCP",
            packet_size=512,
            flags="PSH|ACK",
            payload_size=200,
            raw_packet=b"<script>alert('XSS')</script>"
        )
    ]
    
    # Analyze test packets
    for i, packet in enumerate(test_packets):
        print(f"\nAnalyzing test packet {i+1}:")
        detections = detector.analyze_packet(packet)
        
        if detections:
            for detection in detections:
                print(f"DETECTION: {detection.signature_name}")
                print(f"  Severity: {detection.severity}")
                print(f"  Category: {detection.category}")
                print(f"  Confidence: {detection.confidence:.2f}")
                print(f"  Matched: {detection.matched_content}")
        else:
            print("No detections")
    
    # Print detector stats
    print("\nDetection Engine Stats:")
    print(json.dumps(detector.get_stats(), indent=2))

