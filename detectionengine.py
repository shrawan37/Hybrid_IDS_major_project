import re
import json
import joblib
import numpy as np
from scapy.all import IP, TCP, UDP, ARP, DNS, Raw, IPv6
import datetime
from collections import defaultdict
import time

class DetectionEngine:
    def __init__(self):
        """ Load trained Isolation Forest model, scaler, and label encoders for anomaly detection """
        try:
            self.anomaly_detector = joblib.load("isolation_forest.pkl")
            self.scaler = joblib.load("scaler.pkl")
            self.scaler.mean_ = np.load("scaler_mean.npy")
            self.scaler.scale_ = np.load("scaler_scale.npy")
            print("✅ Models Loaded Successfully!")
        except Exception as e:
            print(f"⚠️ Warning: Failed to load trained models - {e}")
            self.anomaly_detector = None
            self.scaler = None  
            self.label_encoders = None  

        self.signature_patterns = self.load_signature_patterns()
        self.packet_data = {}  # Stores packet timestamps for each IP
        self.syn_packets = {} # Stores count of SYN packets per IP
        self.last_time_checked = time.time()  # For periodic checks

    def load_signature_patterns(self):
        """ Load signature-based attack patterns from a JSON file """
        try:
            with open('signatures.json', 'r') as file:
                patterns = json.load(file)
            
            # Convert each attack category into a list of compiled regex patterns
            compiled_patterns = {}
            for attack, pattern_list in patterns.items():
                compiled_patterns[attack] = [re.compile(pattern, re.IGNORECASE) for pattern in pattern_list]

            return compiled_patterns

        except Exception as e:
            print(f"⚠️ Warning: Failed to load signature patterns - {e}")
            return {}

    def detect_threats(self, packet):
        """ Detect threats using Signature-Based Detection with regex patterns and behavioral detection """
        threats = []
        
        # Get Raw Payload
        raw_payload = self.get_payload(packet)
        
        # Log the raw payload for debugging
        raw_payload_decoded = raw_payload.decode(errors='ignore') if raw_payload else ""
        print("Decoded Payload:", raw_payload_decoded)
        
        # If the payload is empty or None, return immediately
        if not raw_payload:
            return threats

        # Check for Signature-Based Threats using regex patterns
        for attack_type, pattern in self.signature_patterns.items():
            for pattern in pattern:
                print(f"Checking for {attack_type} using pattern: {pattern.pattern}")
                match = pattern.search(raw_payload_decoded)
                if match:  # If a pattern match is found
                    print(f"Signature Detected: {attack_type} in payload: {raw_payload_decoded[:100]}...") 
                    threat_info = {
                        'attack': attack_type,
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'source_ip': packet[IP].src if packet.haslayer(IP) else packet[IPv6].src if packet.haslayer(IPv6) else 'Unknown',
                        'destination_ip': packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst if packet.haslayer(IPv6) else 'Unknown',
                        'protocol': packet[IP].proto if packet.haslayer(IP) else 'Unknown',
                        'payload': str(packet[TCP].payload) if packet.haslayer(TCP) else 'None'
                    }
                    self.write_to_log(threat_info)
                    threats.append({'attack': attack_type})

        # Detect Behavioral-Based Attacks (SYN Flood, DDoS)
        behavioral_threats = self.detect_behavioral_attacks(packet)
        if behavioral_threats:
            threats.extend(behavioral_threats)

        return threats

    def detect_behavioral_attacks(self, packet):
        """ Detect SYN Flood and DDoS based on traffic behavior """
        threats = []
        timestamp = time.time()
        src_ip = self.get_source_ip(packet)

        # Initialize dictionaries for new IP addresses
        if src_ip not in self.syn_packets:
            self.syn_packets[src_ip] = 0  # Track SYN packet count for each IP
        if src_ip not in self.packet_data:
            self.packet_data[src_ip] = []  # Track packet timestamps for each IP

        # Check for SYN Flood based on SYN packet count
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            self.syn_packets[src_ip] += 1
            print(f"Detected SYN packet from {src_ip}. Total SYN count: {self.syn_packets[src_ip]}")
            if self.syn_packets[src_ip] > 50:  # Threshold for SYN Flood detection
                print(f"⚠️ SYN Flood detected from {src_ip}")
                threat_info = {
                    'attack': 'SYN Flood',
                    'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'source_ip': src_ip,
                    'destination_ip': self.get_destination_ip(packet),
                    'protocol': self.get_protocol(packet),
                    'payload_preview': self.get_payload(packet).decode(errors='ignore')[:100]
                }
                self.write_to_log(threat_info)
                threats.append({'attack': 'SYN Flood'})

        # DDoS detection based on packet rate per IP
        self.packet_data[src_ip].append(timestamp)

        # Remove outdated packet timestamps (older than 60 seconds)
        self.packet_data[src_ip] = [ts for ts in self.packet_data[src_ip] if timestamp - ts <= 30]

        # Check if the number of packets from the same IP exceeds the DDoS threshold
        if len(self.packet_data[src_ip]) > 100:  # Threshold for DDoS detection
            print(f"⚠️ Potential DDoS attack detected from {src_ip}. Packet count in last 60 seconds: {len(self.packet_data[src_ip])}")
            threat_info = {
                        'attack': 'DDOS',
                        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'source_ip': packet[IP].src if packet.haslayer(IP) else packet[IPv6].src if packet.haslayer(IPv6) else 'Unknown',
                        'destination_ip': packet[IP].dst if packet.haslayer(IP) else packet[IPv6].dst if packet.haslayer(IPv6) else 'Unknown',
                        'protocol': packet[IP].proto if packet.haslayer(IP) else 'Unknown',
                        'payload': str(packet[TCP].payload) if packet.haslayer(TCP) else 'None'
            }
            self.write_to_log(threat_info)
            threats.append({'attack': 'DDoS'})

        return threats

    def get_payload(self, packet):
        """ Safely extract the raw payload from a TCP/UDP packet """
        if packet.haslayer(Raw):
            return bytes(packet[Raw].load)
        return b""

    def get_protocol(self, packet):
        """ Identify the protocol of the captured packet """
        if packet.haslayer(IP):
            if packet.haslayer(TCP):
                return "TCP"
            elif packet.haslayer(UDP):
                return "UDP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(DNS):
            return "DNS"
        return "Unknown"

    def get_source_ip(self, packet):
        """ Extract the source IP address from the packet """
        if packet.haslayer(IP):
            return packet[IP].src
        return "Unknown"

    def get_destination_ip(self, packet):
        """ Extract the destination IP address from the packet """
        if packet.haslayer(IP):
            return packet[IP].dst
        return "Unknown"

    def write_to_log(self, threat_info):
        """ Write detected threat information to a log file """
        try:
            with open('threat_log.txt', 'a') as log_file:
                log_file.write(json.dumps(threat_info) + "\n")
            print(f"✅ Logged: {threat_info['attack']} from {threat_info['source_ip']}")
        except Exception as e:
            print(f"⚠️ Warning: Failed to write to log file - {e}")


    def extract_packet_features(self, packet):
        """ Extract numerical features from a network packet """
        try:
            return [
                len(packet),  # Packet length
                packet[IP].ttl if packet.haslayer(IP) else 0,  # Time-to-live (TTL)
                1 if packet.haslayer(TCP) else 0,  # Is TCP?
                1 if packet.haslayer(UDP) else 0,  # Is UDP?
                packet[TCP].window if packet.haslayer(TCP) and TCP in packet else 0,  # TCP Window size
                packet[IP].tos if packet.haslayer(IP) else 0,  # Type of Service
                len(packet[Raw].load) if packet.haslayer(Raw) else 0,  # Payload length
                packet[TCP].ack if packet.haslayer(TCP) else 0,  # TCP Acknowledgment
                packet[TCP].flags if packet.haslayer(TCP) else 0,  # TCP Flags
            ]
        except Exception as e:
            print(f"⚠️ Feature extraction error: {e}")
            return [0] * 9  # Return a default feature list to prevent crashes

    def detect_anomalies(self, packet):
        """ Detect anomalies using the Isolation Forest model """
        if not self.anomaly_detector or not self.scaler:
            print("⚠️ Models not loaded!")
            return []

        features = self.extract_packet_features(packet)

        if len(features) != 9:
            print(f"⚠️ Feature extraction error: Expected 9, got {len(features)}. Features: {features}")
            return []

        try:
            features_scaled = self.scaler.transform([features])
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)
            print(f"Anomaly Score: {anomaly_score}")

            prediction = self.anomaly_detector.predict(features_scaled)
            print(f"Prediction: {prediction}")  # -1 = Anomaly, 1 = Normal

            if prediction[0] == -1:
                print("🚨 Anomalous packet detected!")
                self.log_anomaly(packet, features)
                return [{'attack': 'Anomaly', 'details': features}]
        except Exception as e:
            print(f"⚠️ Error in anomaly detection: {e}")

        return []
    
    def log_anomaly(self, packet, features):
        """ Log detected anomalies """
        anomaly_info = {
            'attack': 'Anomaly',
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'source_ip': self.get_source_ip(packet),
            'destination_ip': self.get_destination_ip(packet),
            'protocol': self.get_protocol(packet),
            'features': features
        }
        try:
            with open('anomaly_log.json', 'a') as log_file:
                log_file.write(json.dumps(anomaly_info) + "\n")
            print("✅ Anomaly logged successfully!")
        except Exception as e:
            print(f"⚠️ Warning: Failed to write to anomaly log file - {e}")

    