"""
System Integrator for IDS/IPS Components
Fixes integration issues and provides unified system management
"""

import sys
import os
import threading
import time
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import queue
import hashlib

# Add all component paths
sys.path.append(str(Path(__file__).parent.parent))

# Import all components with error handling
components_loaded = {}

try:
    from detection_engine.enhanced_detector import EnhancedDetectionEngine, EnhancedPacket, ThreatDetection
    components_loaded['enhanced_detector'] = True
except ImportError as e:
    print(f"Warning: Could not import enhanced detector: {e}")
    components_loaded['enhanced_detector'] = False

try:
    from packet_capture.packet_sniffer import PacketSniffer
    components_loaded['packet_sniffer'] = True
except ImportError as e:
    print(f"Warning: Could not import packet sniffer: {e}")
    components_loaded['packet_sniffer'] = False

try:
    from prevention_engine.ip_blocker import IPBlocker
    components_loaded['ip_blocker'] = True
except ImportError as e:
    print(f"Warning: Could not import IP blocker: {e}")
    components_loaded['ip_blocker'] = False

try:
    from logging_system.logger import IDSLogger, LogEntry, Alert, LogLevel, AlertSeverity
    components_loaded['logger'] = True
except ImportError as e:
    print(f"Warning: Could not import logger: {e}")
    components_loaded['logger'] = False

try:
    from reporting_system.report_generator import ReportGenerator, ReportConfig
    components_loaded['report_generator'] = True
except ImportError as e:
    print(f"Warning: Could not import report generator: {e}")
    components_loaded['report_generator'] = False

@dataclass
class SystemStatus:
    running: bool
    uptime_seconds: float
    components_status: Dict[str, bool]
    performance_metrics: Dict[str, Any]
    recent_alerts: List[Dict[str, Any]]
    error_log: List[str]

class IntegratedIDSIPS:
    """Integrated IDS/IPS system with all components working together"""
    
    def __init__(self, config_file: str = None):
        self.config = self._load_config(config_file)
        self.running = False
        self.start_time = time.time()
        self.error_log = []
        
        # Component instances
        self.components = {}
        self.packet_queue = queue.Queue(maxsize=10000)
        self.alert_queue = queue.Queue(maxsize=1000)
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'threats_detected': 0,
            'alerts_generated': 0,
            'ips_blocked': 0,
            'system_errors': 0
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self._initialize_components()
        
        self.logger.info("Integrated IDS/IPS system initialized")
    
    def _load_config(self, config_file: str = None) -> Dict[str, Any]:
        """Load system configuration"""
        default_config = {
            'system': {
                'name': 'Integrated IDS/IPS',
                'version': '1.0.0',
                'debug': False
            },
            'network': {
                'interfaces': ['eth0', 'lo'],
                'capture_buffer_size': 65536,
                'promiscuous_mode': False
            },
            'detection': {
                'signature_detection': {
                    'enabled': True,
                    'signature_file': 'signatures.json',
                    'update_interval': 3600
                },
                'anomaly_detection': {
                    'enabled': True,
                    'threshold': 0.7,
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
                }
            },
            'prevention': {
                'auto_blocking': True,
                'block_duration': 3600,
                'whitelist': ['127.0.0.1', '::1'],
                'block_threshold': 0.8
            },
            'logging': {
                'log_level': 'INFO',
                'log_directory': '/tmp/ids_ips_logs',
                'max_log_size': 100 * 1024 * 1024,
                'retention_days': 30,
                'enable_syslog': False,
                'enable_database': True
            },
            'alerting': {
                'email_enabled': False,
                'webhook_enabled': False,
                'severity_threshold': 'MEDIUM'
            },
            'performance': {
                'max_workers': 4,
                'queue_timeout': 1.0,
                'batch_processing': True,
                'batch_size': 100
            }
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge configurations
                    self._deep_merge(default_config, loaded_config)
            except Exception as e:
                print(f"Error loading config file: {e}, using defaults")
        
        return default_config
    
    def _deep_merge(self, base: Dict, update: Dict):
        """Deep merge configuration dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _initialize_components(self):
        """Initialize all available components"""
        self.logger.info("Initializing system components...")
        
                # Initialize Enhanced Detection Engine
        if components_loaded.get('enhanced_detector', False):
            try:
                detection_config = {
                    **self.config['detection'],
                    'performance': {
                        'max_workers': self.config['performance']['max_workers'],
                        'batch_size': self.config['performance']['batch_size']
                    }
                }
                
                self.components['detector'] = EnhancedDetectionEngine(detection_config)
                self.components['detector'].add_detection_callback(self._handle_threat_detection)
                self.logger.info("✅ Enhanced Detection Engine initialized")
                
            except Exception as e:
                self.error_log.append(f"Failed to initialize detection engine: {e}")
                self.logger.error(f"❌ Detection engine initialization failed: {e}")
                # Create mock detector as fallback
                self.components['detector'] = MockDetectionEngine()
                self.logger.info("✅ Mock Detection Engine initialized as fallback")
        
        # Initialize Packet Sniffer (Mock implementation if not available)
        if components_loaded.get('packet_sniffer', False):
            try:
                # Get first interface from interfaces list, or use 'any' as default
                interface = self.config['network']['interfaces'][0] if self.config['network']['interfaces'] else 'any'
                
                self.components['sniffer'] = PacketSniffer(
                    interface=interface,
                    filter_expression=None  # Can be added later if needed
                )
                self.logger.info("✅ Packet Sniffer initialized")
            except Exception as e:
                self.error_log.append(f"Failed to initialize packet sniffer: {e}")
                self.logger.error(f"❌ Packet sniffer initialization failed: {e}")
                # Create mock packet sniffer as fallback
                self.components['sniffer'] = MockPacketSniffer()
                self.logger.info("✅ Mock Packet Sniffer initialized as fallback")
        else:
            # Create mock packet sniffer
            self.components['sniffer'] = MockPacketSniffer()
            self.logger.info("✅ Mock Packet Sniffer initialized")
        
        # Initialize IP Blocker
        if components_loaded.get('ip_blocker', False):
            try:
                # Create a temporary config file for IPBlocker
                blocker_config = {
                    'max_rules': 10000,
                    'default_block_duration': self.config['prevention']['block_duration'],
                    'whitelist': self.config['prevention']['whitelist'],
                    'enable_automatic_unblock': True,
                    'backup_method': 'hosts_file',
                    'log_all_operations': True,
                    'dry_run_mode': False,
                    'chain_name': 'IDS_IPS_BLOCK',
                    'rule_prefix': 'IDS_IPS'
                }
                
                # Create config file
                blocker_config_path = Path("config/ip_blocker_config.json")
                blocker_config_path.parent.mkdir(exist_ok=True)
                with open(blocker_config_path, 'w') as f:
                    json.dump(blocker_config, f, indent=2)
                
                self.components['blocker'] = IPBlocker(str(blocker_config_path))
                self.logger.info("✅ IP Blocker initialized")
            except Exception as e:
                self.error_log.append(f"Failed to initialize IP blocker: {e}")
                self.logger.error(f"❌ IP blocker initialization failed: {e}")
                # Create mock IP blocker as fallback
                self.components['blocker'] = MockIPBlocker()
                self.logger.info("✅ Mock IP Blocker initialized as fallback")
        else:
            # Create mock IP blocker
            self.components['blocker'] = MockIPBlocker()
            self.logger.info("✅ Mock IP Blocker initialized")
        
        # Initialize Logger
        if components_loaded.get('logger', False):
            try:
                self.components['logger'] = IDSLogger(self.config['logging'])
                self.logger.info("✅ IDS Logger initialized")
            except Exception as e:
                self.error_log.append(f"Failed to initialize logger: {e}")
                self.logger.error(f"❌ Logger initialization failed: {e}")
        else:
            # Create mock logger
            self.components['logger'] = MockLogger()
            self.logger.info("✅ Mock Logger initialized")
        
        # Initialize Report Generator
        if components_loaded.get('report_generator', False):
            try:
                db_path = Path(self.config['logging']['log_directory']) / 'ids_logs.db'
                self.components['reporter'] = ReportGenerator(str(db_path))
                self.logger.info("✅ Report Generator initialized")
            except Exception as e:
                self.error_log.append(f"Failed to initialize report generator: {e}")
                self.logger.error(f"❌ Report generator initialization failed: {e}")
        else:
            # Create mock report generator
            self.components['reporter'] = MockReportGenerator()
            self.logger.info("✅ Mock Report Generator initialized")
        
        # Log component status
        self.logger.info(f"Component initialization complete. Loaded: {sum(1 for c in self.components.values() if c is not None)}/{len(self.components)}")
    
    def start(self):
        """Start the integrated IDS/IPS system"""
        if self.running:
            return {"status": "already_running"}
        
        try:
            self.running = True
            self.start_time = time.time()
            
            # Start detection engine
            if 'detector' in self.components and self.components['detector']:
                self.components['detector'].start()
            
            # Start packet processing thread
            self.packet_thread = threading.Thread(target=self._packet_processing_loop, daemon=True)
            self.packet_thread.start()
            
            # Start alert processing thread
            self.alert_thread = threading.Thread(target=self._alert_processing_loop, daemon=True)
            self.alert_thread.start()
            
            # Start statistics thread
            self.stats_thread = threading.Thread(target=self._statistics_loop, daemon=True)
            self.stats_thread.start()
            
            # Start packet capture simulation
            self.capture_thread = threading.Thread(target=self._packet_capture_loop, daemon=True)
            self.capture_thread.start()
            
            self.logger.info("🚀 Integrated IDS/IPS system started")
            
            # Log system status
            if 'logger' in self.components and self.components['logger']:
                try:
                    self.components['logger'].log(
                        level="INFO",
                        message="IDS/IPS system started successfully",
                        components=list(self.components.keys())
                    )
                except:
                    pass
            
            return {"status": "started", "timestamp": time.time()}
            
        except Exception as e:
            self.running = False
            self.error_log.append(f"Failed to start system: {e}")
            self.logger.error(f"❌ System start failed: {e}")
            return {"status": "error", "message": str(e)}
    
    def stop(self):
        """Stop the integrated IDS/IPS system"""
        if not self.running:
            return {"status": "not_running"}
        
        try:
            self.running = False
            
            # Stop detection engine
            if 'detector' in self.components and self.components['detector']:
                self.components['detector'].stop()
            
            self.logger.info("🛑 Integrated IDS/IPS system stopped")
            
            # Log system status
            if 'logger' in self.components and self.components['logger']:
                try:
                    self.components['logger'].log(
                        level="INFO",
                        message="IDS/IPS system stopped",
                        uptime=time.time() - self.start_time
                    )
                except:
                    pass
            
            return {"status": "stopped", "timestamp": time.time()}
            
        except Exception as e:
            self.error_log.append(f"Failed to stop system: {e}")
            self.logger.error(f"❌ System stop failed: {e}")
            return {"status": "error", "message": str(e)}
    
    def _packet_capture_loop(self):
        """Simulate packet capture for testing"""
        import random
        
        while self.running:
            try:
                # Generate simulated packets
                if random.random() < 0.1:  # 10% chance of generating a packet
                    packet = self._generate_test_packet()
                    self.packet_queue.put(packet, timeout=1.0)
                
                time.sleep(0.1)  # 100ms interval
                
            except Exception as e:
                self.logger.error(f"Error in packet capture loop: {e}")
                time.sleep(1)
    
    def _generate_test_packet(self) -> 'EnhancedPacket':
        """Generate test packet for simulation"""
        import random
        
        # Occasionally generate malicious packets
        if random.random() < 0.2:  # 20% chance of malicious packet
            src_ips = ['203.0.113.10', '198.51.100.20', '192.0.2.30']
            payloads = ['MALICIOUS_PAYLOAD', 'C2_COMMAND', 'EXPLOIT_ATTEMPT']
            
            packet = EnhancedPacket(
                timestamp=time.time(),
                src_ip=random.choice(src_ips),
                dst_ip='192.168.1.100',
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443, 22, 21]),
                protocol='TCP',
                payload_size=random.randint(100, 1500),
                flags=['SYN'],
                payload_hash=hashlib.md5(random.choice(payloads).encode()).hexdigest(),
                payload_snippet=random.choice(payloads),
                direction='inbound',
                metadata={}
            )
        else:
            # Generate normal packet
            packet = EnhancedPacket(
                timestamp=time.time(),
                src_ip=f'192.168.1.{random.randint(10, 200)}',
                dst_ip=f'192.168.1.{random.randint(10, 200)}',
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443, 22, 53]),
                protocol=random.choice(['TCP', 'UDP']),
                payload_size=random.randint(64, 1500),
                flags=['SYN'] if random.choice(['TCP', 'UDP']) == 'TCP' else [],
                payload_hash=hashlib.md5(f'normal_data_{random.randint(1, 1000)}'.encode()).hexdigest(),
                payload_snippet=f'Normal traffic data {random.randint(1, 1000)}',
                direction='internal',
                metadata={}
            )
        
        return packet
    
    def _packet_processing_loop(self):
        """Process packets from the capture queue"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1.0)
                
                # Send packet to detection engine
                if 'detector' in self.components and self.components['detector']:
                    self.components['detector'].process_packet(packet)
                
                self.stats['packets_processed'] += 1
                self.packet_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in packet processing loop: {e}")
                self.stats['system_errors'] += 1
    
    def _alert_processing_loop(self):
        """Process alerts from the detection engine"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=1.0)
                
                # Process the alert
                self._process_alert(alert)
                
                self.stats['alerts_generated'] += 1
                self.alert_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error in alert processing loop: {e}")
                self.stats['system_errors'] += 1
    
    def _statistics_loop(self):
        """Periodic statistics reporting"""
        while self.running:
            try:
                time.sleep(30)  # Report every 30 seconds
                
                uptime = time.time() - self.start_time
                pps = self.stats['packets_processed'] / uptime if uptime > 0 else 0
                
                self.logger.info(f"📊 System Stats - "
                               f"Uptime: {uptime:.0f}s, "
                               f"Packets: {self.stats['packets_processed']}, "
                               f"Threats: {self.stats['threats_detected']}, "
                               f"Alerts: {self.stats['alerts_generated']}, "
                               f"Rate: {pps:.2f} pps")
                
            except Exception as e:
                self.logger.error(f"Error in statistics loop: {e}")
    
    def _handle_threat_detection(self, detection: 'ThreatDetection'):
        """Handle threat detection from detection engine"""
        try:
            self.stats['threats_detected'] += 1
            
            # Create alert
            alert = {
                'id': detection.detection_id,
                'timestamp': detection.timestamp,
                'severity': detection.severity,
                'threat_type': detection.threat_type,
                'source_ip': detection.source_ip,
                'destination_ip': detection.destination_ip,
                'description': detection.description,
                'confidence': detection.confidence,
                'detection_method': detection.detection_method,
                'recommended_action': detection.recommended_action,
                'indicators': detection.indicators,
                'metadata': detection.metadata
            }
            
            # Add to alert queue
            self.alert_queue.put(alert, timeout=1.0)
            
            # Auto-blocking if enabled and confidence is high
            if (self.config['prevention']['auto_blocking'] and 
                detection.confidence >= self.config['prevention']['block_threshold'] and
                detection.severity in ['HIGH', 'CRITICAL']):
                
                self._auto_block_ip(detection.source_ip, detection)
            
        except Exception as e:
            self.logger.error(f"Error handling threat detection: {e}")
    
    def _process_alert(self, alert: Dict[str, Any]):
        """Process a security alert"""
        try:
            # Log the alert
            if 'logger' in self.components and self.components['logger']:
                try:
                    if hasattr(self.components['logger'], 'create_alert'):
                        # Use proper Alert object if available
                        alert_obj = Alert(
                            id=alert['id'],
                            timestamp=str(alert['timestamp']),
                            severity=alert['severity'],
                            title=f"{alert['threat_type']} detected",
                            description=alert['description'],
                            source_ip=alert['source_ip'],
                            destination_ip=alert['destination_ip'],
                            threat_type=alert['threat_type'],
                            action_taken=alert.get('action_taken', 'none'),
                            metadata=alert['metadata']
                        )
                        self.components['logger'].create_alert(alert_obj)
                    else:
                        # Fallback to direct logging
                        self.components['logger'].log(
                            level="WARNING",
                            message=f"ALERT: {alert['threat_type']} from {alert['source_ip']} - {alert['description']}",
                            source_ip=alert['source_ip'],
                            threat_type=alert['threat_type'],
                            severity=alert['severity'],
                            confidence=alert['confidence']
                        )
                except Exception as e:
                    self.logger.error(f"Error logging alert: {e}")
            
            # Additional alert processing can be added here
            self.logger.warning(f"🚨 SECURITY ALERT: {alert['threat_type']} from {alert['source_ip']} "
                              f"(Severity: {alert['severity']}, Confidence: {alert['confidence']:.2f})")
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")
    
    def _auto_block_ip(self, ip_address: str, detection: 'ThreatDetection'):
        """Automatically block malicious IP address"""
        try:
            if 'blocker' in self.components and self.components['blocker']:
                duration = self.config['prevention']['block_duration']
                reason = f"Auto-blocked: {detection.threat_type} (Confidence: {detection.confidence:.2f})"
                
                if hasattr(self.components['blocker'], 'block_ip'):
                    block_result = self.components['blocker'].block_ip(ip_address, reason, detection.severity, duration)
                    
                    # Handle BlockResult object
                    if hasattr(block_result, 'success'):
                        success = block_result.success
                        method = getattr(block_result, 'method', 'unknown')
                        message = getattr(block_result, 'message', '')
                    else:
                        # Fallback for simple boolean return
                        success = bool(block_result)
                        method = 'legacy'
                        message = ''
                    
                    if success and method != 'existing':  # Only log new blocks, not existing ones
                        self.stats['ips_blocked'] += 1
                        self.logger.info(f"🚫 Auto-blocked IP: {ip_address} for {duration}s")
                        
                        # Log the blocking action
                        if 'logger' in self.components and self.components['logger']:
                            try:
                                self.components['logger'].log(
                                    level="INFO",
                                    message=f"IP {ip_address} automatically blocked",
                                    source_ip=ip_address,
                                    action_taken="blocked",
                                    reason=reason,
                                    duration=duration
                                )
                            except:
                                pass
                    elif method == 'existing':
                        # IP already blocked, don't log as new block
                        self.logger.debug(f"IP {ip_address} already blocked, skipping duplicate block")
                    else:
                        self.logger.warning(f"⚠️ Failed to auto-block IP: {ip_address} - {message}")
                
        except Exception as e:
            self.logger.error(f"Error in auto-blocking: {e}")
    
    def get_system_status(self) -> SystemStatus:
        """Get comprehensive system status"""
        uptime = time.time() - self.start_time if self.running else 0
        
        # Get component status
        components_status = {}
        for name, component in self.components.items():
            components_status[name] = component is not None
        
        # Get performance metrics
        performance_metrics = {
            'uptime_seconds': uptime,
            'packets_per_second': self.stats['packets_processed'] / uptime if uptime > 0 else 0,
            'threats_per_hour': self.stats['threats_detected'] / (uptime / 3600) if uptime > 0 else 0,
            'queue_sizes': {
                'packet_queue': self.packet_queue.qsize(),
                'alert_queue': self.alert_queue.qsize()
            }
        }
        
        # Get recent alerts (simplified)
        recent_alerts = []
        if 'detector' in self.components and self.components['detector']:
            try:
                recent_detections = self.components['detector'].get_recent_detections(5)
                for detection in recent_detections:
                    recent_alerts.append({
                        'id': detection.detection_id,
                        'timestamp': detection.timestamp,
                        'severity': detection.severity,
                        'threat_type': detection.threat_type,
                        'source_ip': detection.source_ip
                    })
            except:
                pass
        
        return SystemStatus(
            running=self.running,
            uptime_seconds=uptime,
            components_status=components_status,
            performance_metrics=performance_metrics,
            recent_alerts=recent_alerts,
            error_log=self.error_log[-10:]  # Last 10 errors
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detailed system statistics"""
        status = self.get_system_status()
        
        stats = {
            'system': {
                'running': status.running,
                'uptime_seconds': status.uptime_seconds,
                'components_loaded': sum(1 for loaded in components_loaded.values() if loaded),
                'components_active': sum(1 for active in status.components_status.values() if active),
                'error_count': len(status.error_log)
            },
            'performance': status.performance_metrics,
            'counters': self.stats.copy(),
            'components': status.components_status
        }
        
        # Add component-specific statistics
        if 'detector' in self.components and self.components['detector']:
            try:
                detector_stats = self.components['detector'].get_statistics()
                stats['detection_engine'] = detector_stats
            except:
                pass
        
        return stats

# Mock components for when real components are not available
class MockDetectionEngine:
    def __init__(self, *args, **kwargs):
        pass
    
    def start(self):
        pass
    
    def stop(self):
        pass
    
    def add_detection_callback(self, callback):
        pass
    
    def process_packet(self, packet):
        # Mock packet processing - just return no threats detected
        return []

class MockPacketSniffer:
    def __init__(self, *args, **kwargs):
        pass
    
    def start(self):
        pass
    
    def stop(self):
        pass

class MockIPBlocker:
    def __init__(self, *args, **kwargs):
        self.blocked_ips = {}
    
    def block_ip(self, ip: str, duration: int = 3600, reason: str = ""):
        self.blocked_ips[ip] = {'duration': duration, 'reason': reason, 'timestamp': time.time()}
        return True
    
    def unblock_ip(self, ip: str):
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            return True
        return False
    
    def get_blocked_ips(self):
        return list(self.blocked_ips.keys())

class MockLogger:
    def __init__(self, *args, **kwargs):
        pass
    
    def log(self, entry):
        pass
    
    def create_alert(self, alert):
        pass

class MockReportGenerator:
    def __init__(self, *args, **kwargs):
        pass
    
    def generate_report(self, config):
        return "/tmp/mock_report.pdf"

# Example usage and testing
if __name__ == "__main__":
    print("🔧 Initializing Integrated IDS/IPS System")
    print("=" * 50)
    
    # Create integrated system
    ids_ips = IntegratedIDSIPS()
    
    # Start the system
    start_result = ids_ips.start()
    print(f"Start result: {start_result}")
    
    # Let it run for a bit
    print("\n⏳ Running system for 30 seconds...")
    time.sleep(30)
    
    # Get system status
    status = ids_ips.get_system_status()
    print(f"\n📊 System Status:")
    print(f"   Running: {status.running}")
    print(f"   Uptime: {status.uptime_seconds:.1f}s")
    print(f"   Components: {status.components_status}")
    print(f"   Recent Alerts: {len(status.recent_alerts)}")
    
    # Get detailed statistics
    stats = ids_ips.get_statistics()
    print(f"\n📈 System Statistics:")
    print(f"   Packets Processed: {stats['counters']['packets_processed']}")
    print(f"   Threats Detected: {stats['counters']['threats_detected']}")
    print(f"   Alerts Generated: {stats['counters']['alerts_generated']}")
    print(f"   IPs Blocked: {stats['counters']['ips_blocked']}")
    
    # Stop the system
    stop_result = ids_ips.stop()
    print(f"\n🛑 Stop result: {stop_result}")
    
    print("\n✅ Integrated IDS/IPS System test completed!")

