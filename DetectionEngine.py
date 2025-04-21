from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        # Preparing realistic training data for the anomaly detector
        training_array = self.prepare_training_data(normal_traffic_data)
        self.anomaly_detector.fit(training_array)

    def prepare_training_data(self, normal_traffic_data):
        return np.array([
            [d['packet_size'], d['packet_rate'], d['byte_rate']] 
            for d in normal_traffic_data
        ])

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        # Use a dynamic threshold for anomaly detection
        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < -0.3:  # Adjust this threshold value
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats
