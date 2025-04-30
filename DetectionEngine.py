import queue
from sklearn.ensemble import IsolationForest
import numpy as np
import time
from collections import defaultdict, deque


class DetectionEngine:
    def __init__(self):
        self.recent_syns = defaultdict(lambda: defaultdict(
            lambda: 0))  # {dst_ip: {src_ip: count}}
# Example: Detect if we see 3 SYN from different IPs to the same target quickly
        self.syn_flood_threshold = 3
        self.syn_flood_window = 5
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []

        # For improved port scan detection
        self.recent_connections = defaultdict(lambda: deque(
            maxlen=100))  # (dst_port, timestamp) per src_ip

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN flag
                    features['packet_rate'] > 100
                )
            },
            # 'port_scan': {
            #     'condition': lambda features: (
            #         # Increased size threshold
            #         features['packet_size'] < 100 and
            #         # Lowered packet rate threshold
            #         features['packet_rate'] > 50
            #     )
            # }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        training_array = self.prepare_training_data(normal_traffic_data)
        self.anomaly_detector.fit(training_array)

    def prepare_training_data(self, normal_traffic_data):
        return np.array([
            [d['packet_size'], d['packet_rate'], d['byte_rate']]
            for d in normal_traffic_data
        ])

    def collect_normal_traffic(self, duration=30):
        print(f"Collecting normal traffic for {duration} seconds...")
        self.packet_capture.start_capture(self.interface)

        normal_features = []
        start_time = time.time()

        while time.time() - start_time < duration:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)
                if features:
                    normal_features.append(features)
            except queue.Empty:
                continue

        self.packet_capture.stop()
        return normal_features

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        normal_traffic_data = self.collect_normal_traffic(duration=30)
        self.train_anomaly_detector(normal_traffic_data)
        self.packet_capture.start_capture(self.interface)

    def detect_threats(self, features):
        threats = []
        current_time = time.time()
        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        tcp_flags = features.get('tcp_flags')
        dst_port = features.get('dst_port')

        # DEBUG
        print(
            f"DEBUG: tcp_flags={tcp_flags}, src_ip='{src_ip}', dst_ip='{dst_ip}'")

        # --- SYN Flood Detection (Size-Limited Tracking) ---
        if tcp_flags == 2 and src_ip and dst_ip:
            print(f"DST IP for SYN packet: '{dst_ip}'")  # ULTRA DEBUG
            if dst_ip not in self.recent_syns:
                self.recent_syns[dst_ip] = deque(
                    maxlen=self.syn_flood_threshold + 1)  # Keep a history

            if src_ip not in self.recent_syns[dst_ip]:
                self.recent_syns[dst_ip].append(src_ip)

            syn_count = len(self.recent_syns[dst_ip])
            # Debug print
            print(
                f"Processing SYN to {dst_ip} from {src_ip}, count: {syn_count}, recent_syns: {list(self.recent_syns[dst_ip])}")
            if syn_count >= self.syn_flood_threshold:
                print("SYN FLOOD THRESHOLD REACHED!")  # CRITICAL DEBUG PRINT
                threats.append({
                    'type': 'signature',
                    'rule': 'syn_flood',
                    'confidence': 0.8
                })

        # ------------------------
        # Signature-based detection (Other rules)
        # ------------------------
        for rule_name, rule in self.signature_rules.items():
            # Avoid re-evaluating SYN flood
            if rule_name != 'syn_flood' and rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # ------------------------
        # Improved Port Scan Detection
        # ------------------------
        if src_ip and dst_port:
            self.recent_connections[src_ip].append((dst_port, current_time))
            recent_ports = [
                port for port, t in self.recent_connections[src_ip]
                if current_time - t < 10
            ]
            unique_ports = set(recent_ports)
            if len(unique_ports) > 10:
                threats.append({
                    'type': 'signature',
                    'rule': 'port_scan',
                    'confidence': 1.0
                })

        # ------------------------
        # Anomaly-based detection
        # ------------------------
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])
        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < -0.7:
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats
