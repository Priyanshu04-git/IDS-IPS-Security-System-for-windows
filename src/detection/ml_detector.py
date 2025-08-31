"""
Machine Learning-Based Detection Engine for IDS/IPS System
Advanced threat detection using supervised and unsupervised learning algorithms
"""

import os
import time
import json
import pickle
import logging
import threading
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

# Machine Learning imports
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn")

@dataclass
class MLDetectionResult:
    """Data class representing ML detection result"""
    model_name: str
    prediction: str  # BENIGN, MALICIOUS, ANOMALY
    confidence: float
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    features: Dict[str, float]
    anomaly_score: Optional[float] = None
    feature_importance: Optional[Dict[str, float]] = None
    additional_info: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}

class FeatureExtractor:
    """Extracts features from network packets for ML analysis"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Feature statistics for normalization
        self.feature_stats = {
            'packet_size': {'min': 0, 'max': 65535, 'mean': 1024, 'std': 512},
            'payload_size': {'min': 0, 'max': 65535, 'mean': 512, 'std': 256},
            'port_number': {'min': 0, 'max': 65535, 'mean': 32768, 'std': 18918}
        }
        
        # Protocol encoding
        self.protocol_encoder = {
            'TCP': 1, 'UDP': 2, 'ICMP': 3, 'ARP': 4, 'Unknown': 0
        }
        
        # Port categories
        self.well_known_ports = set(range(1, 1024))
        self.registered_ports = set(range(1024, 49152))
        self.dynamic_ports = set(range(49152, 65536))
        
        # Suspicious ports (commonly targeted)
        self.suspicious_ports = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017
        }
    
    def extract_features(self, packet_info, context: Optional[Dict] = None) -> Dict[str, float]:
        """Extract features from packet information"""
        features = {}
        
        # Basic packet features
        features['packet_size'] = float(packet_info.packet_size)
        features['payload_size'] = float(packet_info.payload_size)
        features['payload_ratio'] = (
            packet_info.payload_size / packet_info.packet_size 
            if packet_info.packet_size > 0 else 0
        )
        
        # Protocol features
        features['protocol_tcp'] = 1.0 if packet_info.protocol == 'TCP' else 0.0
        features['protocol_udp'] = 1.0 if packet_info.protocol == 'UDP' else 0.0
        features['protocol_icmp'] = 1.0 if packet_info.protocol == 'ICMP' else 0.0
        features['protocol_other'] = 1.0 if packet_info.protocol not in ['TCP', 'UDP', 'ICMP'] else 0.0
        
        # Port features
        if packet_info.src_port:
            features['src_port'] = float(packet_info.src_port)
            features['src_port_well_known'] = 1.0 if packet_info.src_port in self.well_known_ports else 0.0
            features['src_port_suspicious'] = 1.0 if packet_info.src_port in self.suspicious_ports else 0.0
        else:
            features['src_port'] = 0.0
            features['src_port_well_known'] = 0.0
            features['src_port_suspicious'] = 0.0
        
        if packet_info.dst_port:
            features['dst_port'] = float(packet_info.dst_port)
            features['dst_port_well_known'] = 1.0 if packet_info.dst_port in self.well_known_ports else 0.0
            features['dst_port_suspicious'] = 1.0 if packet_info.dst_port in self.suspicious_ports else 0.0
        else:
            features['dst_port'] = 0.0
            features['dst_port_well_known'] = 0.0
            features['dst_port_suspicious'] = 0.0
        
        # TCP flags features
        if packet_info.flags:
            flags = packet_info.flags.upper()
            features['flag_syn'] = 1.0 if 'SYN' in flags else 0.0
            features['flag_ack'] = 1.0 if 'ACK' in flags else 0.0
            features['flag_fin'] = 1.0 if 'FIN' in flags else 0.0
            features['flag_rst'] = 1.0 if 'RST' in flags else 0.0
            features['flag_psh'] = 1.0 if 'PSH' in flags else 0.0
            features['flag_urg'] = 1.0 if 'URG' in flags else 0.0
            
            # Flag combinations
            features['flag_syn_only'] = 1.0 if flags == 'SYN' else 0.0
            features['flag_syn_ack'] = 1.0 if 'SYN' in flags and 'ACK' in flags else 0.0
        else:
            for flag in ['syn', 'ack', 'fin', 'rst', 'psh', 'urg', 'syn_only', 'syn_ack']:
                features[f'flag_{flag}'] = 0.0
        
        # IP address features (simplified)
        features['src_ip_private'] = 1.0 if self._is_private_ip(packet_info.src_ip) else 0.0
        features['dst_ip_private'] = 1.0 if self._is_private_ip(packet_info.dst_ip) else 0.0
        features['same_subnet'] = 1.0 if self._same_subnet(packet_info.src_ip, packet_info.dst_ip) else 0.0
        
        # Time-based features
        current_time = packet_info.timestamp
        hour = datetime.fromtimestamp(current_time).hour
        features['hour_of_day'] = float(hour)
        features['is_business_hours'] = 1.0 if 9 <= hour <= 17 else 0.0
        features['is_night_time'] = 1.0 if hour < 6 or hour > 22 else 0.0
        
        # Context-based features (if available)
        if context:
            features.update(self._extract_context_features(packet_info, context))
        
        return features
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private range"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are in the same /24 subnet (simplified)"""
        try:
            parts1 = ip1.split('.')
            parts2 = ip2.split('.')
            return parts1[:3] == parts2[:3]
        except:
            return False
    
    def _extract_context_features(self, packet_info, context: Dict) -> Dict[str, float]:
        """Extract context-based features"""
        features = {}
        
        # Connection frequency features
        src_ip = packet_info.src_ip
        if 'connection_counts' in context:
            conn_counts = context['connection_counts']
            features['src_connection_count'] = float(conn_counts.get(src_ip, 0))
            features['src_connection_rate'] = features['src_connection_count'] / max(context.get('time_window', 1), 1)
        
        # Port diversity features
        if 'port_diversity' in context:
            port_div = context['port_diversity']
            features['src_port_diversity'] = float(port_div.get(src_ip, 0))
        
        # Protocol diversity features
        if 'protocol_diversity' in context:
            proto_div = context['protocol_diversity']
            features['src_protocol_diversity'] = float(proto_div.get(src_ip, 0))
        
        return features

class MLModel:
    """Base class for ML models"""
    
    def __init__(self, name: str, model_type: str):
        self.name = name
        self.model_type = model_type  # 'supervised', 'unsupervised'
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.feature_names = []
        self.training_stats = {}
        self.logger = logging.getLogger(__name__)
    
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None, feature_names: List[str] = None):
        """Train the model"""
        raise NotImplementedError
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions (returns predictions and confidence scores)"""
        raise NotImplementedError
    
    def save_model(self, filepath: str):
        """Save model to file"""
        model_data = {
            'name': self.name,
            'model_type': self.model_type,
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained,
            'feature_names': self.feature_names,
            'training_stats': self.training_stats
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        self.logger.info(f"Model {self.name} saved to {filepath}")
    
    def load_model(self, filepath: str):
        """Load model from file"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.name = model_data['name']
        self.model_type = model_data['model_type']
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.is_trained = model_data['is_trained']
        self.feature_names = model_data['feature_names']
        self.training_stats = model_data['training_stats']
        
        self.logger.info(f"Model {self.name} loaded from {filepath}")

class RandomForestModel(MLModel):
    """Random Forest classifier for supervised learning"""
    
    def __init__(self, name: str = "RandomForest"):
        super().__init__(name, "supervised")
        if ML_AVAILABLE:
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            self.scaler = StandardScaler()
    
    def train(self, X: np.ndarray, y: np.ndarray, feature_names: List[str] = None):
        """Train Random Forest model"""
        if not ML_AVAILABLE:
            raise RuntimeError("scikit-learn not available")
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        # Get feature importance
        feature_importance = dict(zip(self.feature_names, self.model.feature_importances_))
        
        self.training_stats = {
            'train_accuracy': train_score,
            'test_accuracy': test_score,
            'feature_importance': feature_importance,
            'n_samples': len(X),
            'n_features': X.shape[1],
            'training_time': time.time()
        }
        
        self.is_trained = True
        self.logger.info(f"Random Forest trained - Train: {train_score:.3f}, Test: {test_score:.3f}")
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions"""
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        # Get confidence as max probability
        confidence = np.max(probabilities, axis=1)
        
        return predictions, confidence

class IsolationForestModel(MLModel):
    """Isolation Forest for unsupervised anomaly detection"""
    
    def __init__(self, name: str = "IsolationForest"):
        super().__init__(name, "unsupervised")
        if ML_AVAILABLE:
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            self.scaler = StandardScaler()
    
    def train(self, X: np.ndarray, y: Optional[np.ndarray] = None, feature_names: List[str] = None):
        """Train Isolation Forest model"""
        if not ML_AVAILABLE:
            raise RuntimeError("scikit-learn not available")
        
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model.fit(X_scaled)
        
        # Get anomaly scores for training data
        anomaly_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        self.training_stats = {
            'n_samples': len(X),
            'n_features': X.shape[1],
            'anomaly_rate': np.sum(predictions == -1) / len(predictions),
            'mean_anomaly_score': np.mean(anomaly_scores),
            'std_anomaly_score': np.std(anomaly_scores),
            'training_time': time.time()
        }
        
        self.is_trained = True
        self.logger.info(f"Isolation Forest trained - Anomaly rate: {self.training_stats['anomaly_rate']:.3f}")
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions"""
        if not self.is_trained:
            raise RuntimeError("Model not trained")
        
        X_scaled = self.scaler.transform(X)
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.decision_function(X_scaled)
        
        # Convert to binary classification (1 = normal, -1 = anomaly)
        binary_predictions = np.where(predictions == 1, 'BENIGN', 'ANOMALY')
        
        # Convert anomaly scores to confidence (higher score = more normal)
        confidence = (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min())
        confidence = np.where(predictions == 1, confidence, 1 - confidence)
        
        return binary_predictions, confidence

class MLDetectionEngine:
    """Main ML-based detection engine"""
    
    def __init__(self, models_dir: str = "ml_models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        
        self.feature_extractor = FeatureExtractor()
        self.models: Dict[str, MLModel] = {}
        self.logger = logging.getLogger(__name__)
        
        # Context tracking for feature extraction
        self.context = {
            'connection_counts': defaultdict(int),
            'port_diversity': defaultdict(set),
            'protocol_diversity': defaultdict(set),
            'time_window': 300,  # 5 minutes
            'last_cleanup': time.time()
        }
        
        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'detections': 0,
            'anomalies': 0,
            'start_time': time.time()
        }
        
        # Initialize models if available
        if ML_AVAILABLE:
            self._initialize_models()
        else:
            self.logger.warning("ML models not available - scikit-learn not installed")
    
    def _initialize_models(self):
        """Initialize ML models"""
        # Add Random Forest for supervised learning
        rf_model = RandomForestModel("RandomForest_Classifier")
        self.models["random_forest"] = rf_model
        
        # Add Isolation Forest for anomaly detection
        if_model = IsolationForestModel("IsolationForest_Anomaly")
        self.models["isolation_forest"] = if_model
        
        # Try to load pre-trained models
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models if available"""
        for model_name, model in self.models.items():
            model_file = self.models_dir / f"{model_name}.pkl"
            if model_file.exists():
                try:
                    model.load_model(str(model_file))
                    self.logger.info(f"Loaded pre-trained model: {model_name}")
                except Exception as e:
                    self.logger.error(f"Error loading model {model_name}: {e}")
    
    def train_models(self, training_data: List[Dict], labels: Optional[List[str]] = None):
        """Train ML models with provided data"""
        if not ML_AVAILABLE:
            self.logger.error("Cannot train models - scikit-learn not available")
            return
        
        if not training_data:
            self.logger.error("No training data provided")
            return
        
        self.logger.info(f"Training models with {len(training_data)} samples")
        
        # Extract features from training data
        features_list = []
        for data in training_data:
            # Convert dict to packet-like object for feature extraction
            packet_info = type('PacketInfo', (), data)()
            features = self.feature_extractor.extract_features(packet_info)
            features_list.append(features)
        
        # Convert to numpy arrays
        feature_names = list(features_list[0].keys())
        X = np.array([[f[name] for name in feature_names] for f in features_list])
        
        # Train supervised models if labels provided
        if labels:
            y = np.array(labels)
            
            # Train Random Forest
            if "random_forest" in self.models:
                try:
                    self.models["random_forest"].train(X, y, feature_names)
                    self._save_model("random_forest")
                except Exception as e:
                    self.logger.error(f"Error training Random Forest: {e}")
        
        # Train unsupervised models
        if "isolation_forest" in self.models:
            try:
                self.models["isolation_forest"].train(X, feature_names=feature_names)
                self._save_model("isolation_forest")
            except Exception as e:
                self.logger.error(f"Error training Isolation Forest: {e}")
    
    def _save_model(self, model_name: str):
        """Save a trained model"""
        if model_name in self.models:
            model_file = self.models_dir / f"{model_name}.pkl"
            self.models[model_name].save_model(str(model_file))
    
    def analyze_packet(self, packet_info) -> List[MLDetectionResult]:
        """Analyze packet using ML models"""
        if not ML_AVAILABLE:
            return []
        
        self.stats['packets_analyzed'] += 1
        results = []
        
        # Update context
        self._update_context(packet_info)
        
        # Extract features
        features = self.feature_extractor.extract_features(packet_info, self.context)
        feature_array = np.array([list(features.values())]).reshape(1, -1)
        
        # Run through all trained models
        for model_name, model in self.models.items():
            if not model.is_trained:
                continue
            
            try:
                predictions, confidence = model.predict(feature_array)
                prediction = predictions[0]
                conf_score = confidence[0]
                
                # Create result
                result = MLDetectionResult(
                    model_name=model_name,
                    prediction=prediction,
                    confidence=conf_score,
                    timestamp=packet_info.timestamp,
                    src_ip=packet_info.src_ip,
                    dst_ip=packet_info.dst_ip,
                    src_port=packet_info.src_port,
                    dst_port=packet_info.dst_port,
                    protocol=packet_info.protocol,
                    features=features
                )
                
                # Add model-specific information
                if model.model_type == "supervised":
                    result.feature_importance = model.training_stats.get('feature_importance', {})
                elif model.model_type == "unsupervised":
                    result.anomaly_score = conf_score
                
                # Only report significant detections
                if (prediction in ['MALICIOUS', 'ANOMALY'] and conf_score > 0.5) or conf_score > 0.8:
                    results.append(result)
                    
                    if prediction in ['MALICIOUS', 'ANOMALY']:
                        self.stats['detections'] += 1
                        if prediction == 'ANOMALY':
                            self.stats['anomalies'] += 1
                
            except Exception as e:
                self.logger.error(f"Error in model {model_name}: {e}")
        
        return results
    
    def _update_context(self, packet_info):
        """Update context information for feature extraction"""
        current_time = time.time()
        src_ip = packet_info.src_ip
        
        # Update connection counts
        self.context['connection_counts'][src_ip] += 1
        
        # Update port diversity
        if packet_info.dst_port:
            self.context['port_diversity'][src_ip].add(packet_info.dst_port)
        
        # Update protocol diversity
        self.context['protocol_diversity'][src_ip].add(packet_info.protocol)
        
        # Cleanup old context data periodically
        if current_time - self.context['last_cleanup'] > self.context['time_window']:
            self._cleanup_context()
            self.context['last_cleanup'] = current_time
    
    def _cleanup_context(self):
        """Clean up old context data"""
        # Reset counters (in a real implementation, you'd want to decay rather than reset)
        self.context['connection_counts'].clear()
        for ip_set in self.context['port_diversity'].values():
            ip_set.clear()
        for ip_set in self.context['protocol_diversity'].values():
            ip_set.clear()
    
    def get_model_info(self) -> Dict[str, Dict]:
        """Get information about loaded models"""
        model_info = {}
        for name, model in self.models.items():
            model_info[name] = {
                'name': model.name,
                'type': model.model_type,
                'trained': model.is_trained,
                'features': len(model.feature_names),
                'training_stats': model.training_stats
            }
        return model_info
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection statistics"""
        current_time = time.time()
        runtime = current_time - self.stats['start_time']
        
        stats = self.stats.copy()
        stats['runtime'] = runtime
        stats['ml_available'] = ML_AVAILABLE
        stats['models_loaded'] = len([m for m in self.models.values() if m.is_trained])
        
        if runtime > 0:
            stats['packets_per_second'] = self.stats['packets_analyzed'] / runtime
            stats['detections_per_second'] = self.stats['detections'] / runtime
        
        stats['detection_rate'] = (
            self.stats['detections'] / self.stats['packets_analyzed'] 
            if self.stats['packets_analyzed'] > 0 else 0
        )
        
        return stats
    
    def generate_training_data(self, packet_data: List, labels: List[str] = None) -> str:
        """Generate training data file from packet data"""
        training_file = self.models_dir / "training_data.json"
        
        training_data = []
        for i, packet in enumerate(packet_data):
            data_point = {
                'packet_info': packet,
                'label': labels[i] if labels and i < len(labels) else 'UNKNOWN'
            }
            training_data.append(data_point)
        
        with open(training_file, 'w') as f:
            json.dump(training_data, f, indent=2)
        
        self.logger.info(f"Generated training data file: {training_file}")
        return str(training_file)

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    if not ML_AVAILABLE:
        print("scikit-learn not available. Install with: pip install scikit-learn")
        exit(1)
    
    # Create ML detection engine
    ml_engine = MLDetectionEngine()
    
    # Generate sample training data
    print("Generating sample training data...")
    
    # Normal traffic samples
    normal_samples = []
    for i in range(100):
        sample = {
            'timestamp': time.time(),
            'src_ip': f"192.168.1.{i % 20 + 1}",
            'dst_ip': "10.0.0.1",
            'src_port': 1000 + i,
            'dst_port': 80,
            'protocol': 'TCP',
            'packet_size': 1024 + (i % 500),
            'payload_size': 500 + (i % 200),
            'flags': 'PSH|ACK'
        }
        normal_samples.append(sample)
    
    # Malicious traffic samples
    malicious_samples = []
    for i in range(50):
        sample = {
            'timestamp': time.time(),
            'src_ip': f"192.168.1.{100 + i}",
            'dst_ip': "10.0.0.1",
            'src_port': 12345,
            'dst_port': i + 1,  # Port scanning
            'protocol': 'TCP',
            'packet_size': 64,
            'payload_size': 0,
            'flags': 'SYN'
        }
        malicious_samples.append(sample)
    
    # Combine and create labels
    all_samples = normal_samples + malicious_samples
    labels = ['BENIGN'] * len(normal_samples) + ['MALICIOUS'] * len(malicious_samples)
    
    # Train models
    print("Training ML models...")
    ml_engine.train_models(all_samples, labels)
    
    # Test with new samples
    print("\nTesting with new samples...")
    
    from packet_capture.packet_sniffer import PacketInfo
    
    test_packets = [
        # Normal packet
        PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=2000,
            dst_port=80,
            protocol="TCP",
            packet_size=1200,
            flags="PSH|ACK",
            payload_size=600
        ),
        # Suspicious packet (port scan)
        PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.200",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=22,
            protocol="TCP",
            packet_size=64,
            flags="SYN",
            payload_size=0
        )
    ]
    
    for i, packet in enumerate(test_packets):
        print(f"\nAnalyzing test packet {i+1}:")
        results = ml_engine.analyze_packet(packet)
        
        if results:
            for result in results:
                print(f"  Model: {result.model_name}")
                print(f"  Prediction: {result.prediction}")
                print(f"  Confidence: {result.confidence:.3f}")
                if result.anomaly_score:
                    print(f"  Anomaly Score: {result.anomaly_score:.3f}")
        else:
            print("  No significant detections")
    
    # Print model information
    print("\nModel Information:")
    model_info = ml_engine.get_model_info()
    for name, info in model_info.items():
        print(f"  {name}:")
        print(f"    Type: {info['type']}")
        print(f"    Trained: {info['trained']}")
        print(f"    Features: {info['features']}")
    
    # Print statistics
    print("\nML Detection Statistics:")
    stats = ml_engine.get_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

