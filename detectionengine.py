import re
import json
import joblib
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw, IPv6, Ether, DHCP
import datetime
import time
from collections import defaultdict


class DetectionEngine:
    def __init__(self):
        # ---- Load ML Models ----
        try:
            self.anomaly_detector = joblib.load("isolation_forest.pkl")
            self.scaler = joblib.load("scaler.pkl")
            self.scaler.mean_ = np.load("scaler_mean.npy")
            self.scaler.scale_ = np.load("scaler_scale.npy")
            print("✅ ML models loaded successfully")
        except Exception as e:
            print(f"⚠️ ML models not loaded: {e}")
            self.anomaly_detector = None
            self.scaler = None

        # ---- Signature Patterns ----
        self.signature_patterns = self.load_signature_patterns()

        # ---- Traffic Tracking for ALL Protocols ----
        self.syn_packets = defaultdict(list)      # TCP SYN floods
        self.udp_packets = defaultdict(list)      # UDP floods  
        self.icmp_packets = defaultdict(list)     # ICMP floods
        self.packet_data = defaultdict(list)      # General DDoS tracking
        self.arp_packets = defaultdict(list)      # ARP spoofing detection
        self.anomaly_count = defaultdict(int)

        # ---- Configuration ----
        self.internal_networks = ("192.168.", "10.", "172.16.")
        self.window_size = 30  # seconds
        self.thresholds = {
            "syn_flood": 200,      # SYNs per window
            "udp_flood": 500,      # UDP packets per window
            "icmp_flood": 100,     # ICMP packets per window  
            "ddos_general": 400,   # Total packets per window
            "arp_spoof": 50,       # ARP packets per window
        }

        # ---- Protocol Statistics ----
        self.protocol_stats = defaultdict(int)
        print("🔄 Detection Engine initialized for ALL protocols")

    # ======================================================
    # Signature Pattern Loader (Updated for all protocols)
    # ======================================================
    def load_signature_patterns(self):
        try:
            with open("models/signatures.json", "r") as f:
                patterns = json.load(f)

            compiled = {}
            for attack, plist in patterns.items():
                compiled[attack] = [
                    re.compile(p, re.IGNORECASE) for p in plist
                ]
            return compiled

        except Exception as e:
            print(f"⚠️ Failed to load signatures: {e}")
            # Return default patterns
            return {
                "SQL Injection": [re.compile(r".*(\%27)|(\')|(\-\-)|(\%23).*", re.IGNORECASE)],
                "XSS Attack": [re.compile(r".*(\<script).*", re.IGNORECASE)],
                "Command Injection": [re.compile(r".*(;|\||\&|`).*(rm|ls|cat|wget|curl).*", re.IGNORECASE)],
            }

    # ======================================================
    # Main Detection Entry - Processes ALL Packets
    # ======================================================
    def detect_threats(self, packet):
        threats = []
        
        # Update protocol statistics
        self.update_protocol_stats(packet)
        
        # Optional: Filter internal traffic (comment out to see all)
        # if self.is_internal_traffic(packet):
        #     return threats
        
        # Detect threats for ALL protocol types
        threats.extend(self.detect_signature_attacks(packet))
        threats.extend(self.detect_behavioral_attacks(packet))
        threats.extend(self.detect_protocol_specific_attacks(packet))
        threats.extend(self.detect_anomalies(packet))
        
        return threats

    # ======================================================
    # Protocol Statistics Tracker
    # ======================================================
    def update_protocol_stats(self, packet):
        """Track what protocols are actually being seen"""
        if packet.haslayer(TCP):
            self.protocol_stats["TCP"] += 1
        if packet.haslayer(UDP):
            self.protocol_stats["UDP"] += 1
        if packet.haslayer(ICMP):
            self.protocol_stats["ICMP"] += 1
        if packet.haslayer(ARP):
            self.protocol_stats["ARP"] += 1
        if packet.haslayer(DNS):
            self.protocol_stats["DNS"] += 1
        if packet.haslayer(DHCP):
            self.protocol_stats["DHCP"] += 1

    def get_protocol_stats(self):
        """Get current protocol statistics"""
        return dict(self.protocol_stats)

    # ======================================================
    # Signature-Based Detection (ALL Protocols)
    # ======================================================
    def detect_signature_attacks(self, packet):
        threats = []
        
        # Check payload for ANY protocol that has payload
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            
            # Skip very small or empty payloads
            if len(payload) < 10:
                return threats
            
            try:
                payload_decoded = payload.decode(errors="ignore")
                
                # Check against all signature patterns
                for attack, patterns in self.signature_patterns.items():
                    for pattern in patterns:
                        if pattern.search(payload_decoded):
                            threat = {
                                "attack": attack,
                                "timestamp": self.timestamp(),
                                "source_ip": self.get_source_ip(packet),
                                "destination_ip": self.get_destination_ip(packet),
                                "protocol": self.get_protocol_name(packet),
                                "payload_preview": payload_decoded[:100]
                            }
                            self.write_to_log(threat)
                            threats.append({"attack": attack})
                            return threats  # Return first match
                            
            except Exception as e:
                # Skip payloads that can't be decoded
                pass
        
        return threats

    # ======================================================
    # Behavioral Detection for ALL Protocols
    # ======================================================
    def detect_behavioral_attacks(self, packet):
        threats = []
        timestamp = time.time()
        
        src_ip = self.get_source_ip(packet)
        dst_ip = self.get_destination_ip(packet)
        protocol = self.get_protocol_name(packet)
        
        # ---- TCP SYN Flood Detection ----
        if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN flag
            self.syn_packets[src_ip].append(timestamp)
            # Clean old entries
            self.syn_packets[src_ip] = [
                t for t in self.syn_packets[src_ip]
                if timestamp - t <= self.window_size
            ]
            
            if len(self.syn_packets[src_ip]) > self.thresholds["syn_flood"]:
                threat = {
                    "attack": "SYN Flood",
                    "timestamp": self.timestamp(),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": "TCP",
                    "packet_count": len(self.syn_packets[src_ip])
                }
                self.write_to_log(threat)
                threats.append({"attack": "SYN Flood"})
        
        # ---- UDP Flood Detection ----
        if packet.haslayer(UDP):
            self.udp_packets[(src_ip, dst_ip)].append(timestamp)
            # Clean old entries
            self.udp_packets[(src_ip, dst_ip)] = [
                t for t in self.udp_packets[(src_ip, dst_ip)]
                if timestamp - t <= self.window_size
            ]
            
            if len(self.udp_packets[(src_ip, dst_ip)]) > self.thresholds["udp_flood"]:
                threat = {
                    "attack": "UDP Flood",
                    "timestamp": self.timestamp(),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": "UDP",
                    "packet_count": len(self.udp_packets[(src_ip, dst_ip)])
                }
                self.write_to_log(threat)
                threats.append({"attack": "UDP Flood"})
        
        # ---- ICMP Flood Detection (Ping Flood) ----
        if packet.haslayer(ICMP):
            self.icmp_packets[(src_ip, dst_ip)].append(timestamp)
            # Clean old entries
            self.icmp_packets[(src_ip, dst_ip)] = [
                t for t in self.icmp_packets[(src_ip, dst_ip)]
                if timestamp - t <= self.window_size
            ]
            
            if len(self.icmp_packets[(src_ip, dst_ip)]) > self.thresholds["icmp_flood"]:
                threat = {
                    "attack": "ICMP Flood (Ping Flood)",
                    "timestamp": self.timestamp(),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": "ICMP",
                    "packet_count": len(self.icmp_packets[(src_ip, dst_ip)])
                }
                self.write_to_log(threat)
                threats.append({"attack": "ICMP Flood"})
        
        # ---- General DDoS Detection (All Protocols) ----
        key = (src_ip, dst_ip, protocol)
        self.packet_data[key].append(timestamp)
        # Clean old entries
        self.packet_data[key] = [
            t for t in self.packet_data[key]
            if timestamp - t <= self.window_size
        ]
        
        if len(self.packet_data[key]) > self.thresholds["ddos_general"]:
            threat = {
                "attack": f"DDoS Attack ({protocol})",
                "timestamp": self.timestamp(),
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": protocol,
                "packet_count": len(self.packet_data[key])
            }
            self.write_to_log(threat)
            threats.append({"attack": "DDoS Attack"})
        
        return threats

    # ======================================================
    # Protocol-Specific Attack Detection
    # ======================================================
    def detect_protocol_specific_attacks(self, packet):
        threats = []
        
        # ---- ARP Spoofing Detection ----
        if packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            # Track ARP packets per source
            key = f"{src_ip}_{src_mac}"
            self.arp_packets[key].append(time.time())
            
            # Clean old entries
            self.arp_packets[key] = [
                t for t in self.arp_packets[key]
                if time.time() - t <= self.window_size
            ]
            
            if len(self.arp_packets[key]) > self.thresholds["arp_spoof"]:
                threat = {
                    "attack": "ARP Spoofing",
                    "timestamp": self.timestamp(),
                    "source_ip": src_ip,
                    "source_mac": src_mac,
                    "protocol": "ARP",
                    "packet_count": len(self.arp_packets[key])
                }
                self.write_to_log(threat)
                threats.append({"attack": "ARP Spoofing"})
        
        # ---- DNS Amplification Detection ----
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            # Check for large DNS responses (amplification attack)
            if len(packet) > 512:  # DNS response larger than typical query
                src_ip = self.get_source_ip(packet)
                dst_ip = self.get_destination_ip(packet)
                
                threat = {
                    "attack": "DNS Amplification Attempt",
                    "timestamp": self.timestamp(),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "protocol": "DNS/UDP",
                    "packet_size": len(packet)
                }
                self.write_to_log(threat)
                threats.append({"attack": "DNS Amplification"})
        
        # ---- Port Scanning Detection ----
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            # Multiple SYN packets to different ports from same source
            if flags & 0x02:  # SYN flag
                src_ip = self.get_source_ip(packet)
                dst_port = packet[TCP].dport
                
                # Track destination ports per source
                if 'port_scan' not in self.packet_data:
                    self.packet_data['port_scan'] = defaultdict(set)
                
                self.packet_data['port_scan'][src_ip].add(dst_port)
                
                # If scanning more than 20 different ports
                if len(self.packet_data['port_scan'][src_ip]) > 20:
                    threat = {
                        "attack": "Port Scanning",
                        "timestamp": self.timestamp(),
                        "source_ip": src_ip,
                        "ports_scanned": len(self.packet_data['port_scan'][src_ip]),
                        "protocol": "TCP"
                    }
                    self.write_to_log(threat)
                    threats.append({"attack": "Port Scanning"})
        
        return threats

    # ======================================================
    # Anomaly Detection (Works for ALL protocols)
    # ======================================================
    def detect_anomalies(self, packet):
        threats = []
        
        if not self.anomaly_detector or not self.scaler:
            return threats
        
        features = self.extract_packet_features(packet)
        
        try:
            scaled = self.scaler.transform([features])
            prediction = self.anomaly_detector.predict(scaled)
            anomaly_score = self.anomaly_detector.decision_function([features])[0]
            
            if prediction[0] == -1:  # Anomaly detected
                src_ip = self.get_source_ip(packet)
                self.anomaly_count[src_ip] += 1
                
                # Only alert after multiple anomalies from same source
                if self.anomaly_count[src_ip] >= 5:
                    self.log_anomaly(packet, features, anomaly_score)
                    threats.append({
                        "attack": "Anomalous Traffic",
                        "score": float(anomaly_score),
                        "protocol": self.get_protocol_name(packet)
                    })
                    self.anomaly_count[src_ip] = 0  # Reset counter
                
        except Exception as e:
            print(f"⚠️ Anomaly detection error: {e}")
        
        return threats

    # ======================================================
    # Feature Extraction for ALL Protocols
    # ======================================================
    def extract_packet_features(self, packet):
        """Extract features suitable for any protocol type"""
        try:
            features = []
            
            # Basic packet features (available for all)
            features.append(len(packet))  # Total length
            
            # IP layer features
            if packet.haslayer(IP):
                features.append(packet[IP].ttl)
                features.append(packet[IP].tos)
                features.append(1 if packet[IP].flags & 0x02 else 0)  # DF flag
                features.append(1 if packet[IP].flags & 0x01 else 0)  # MF flag
            else:
                features.extend([64, 0, 0, 0])  # Default values
            
            # Protocol indicators (one-hot encoded)
            features.append(1 if packet.haslayer(TCP) else 0)
            features.append(1 if packet.haslayer(UDP) else 0)
            features.append(1 if packet.haslayer(ICMP) else 0)
            features.append(1 if packet.haslayer(ARP) else 0)
            features.append(1 if packet.haslayer(DNS) else 0)
            
            # Transport layer features
            if packet.haslayer(TCP):
                features.append(packet[TCP].sport)
                features.append(packet[TCP].dport)
                features.append(packet[TCP].window)
                features.append(int(packet[TCP].flags))
                features.append(1 if packet[TCP].flags & 0x02 else 0)  # SYN
                features.append(1 if packet[TCP].flags & 0x10 else 0)  # ACK
            elif packet.haslayer(UDP):
                features.append(packet[UDP].sport)
                features.append(packet[UDP].dport)
                features.append(0)  # window placeholder
                features.append(0)  # flags placeholder
                features.append(0)  # SYN placeholder
                features.append(0)  # ACK placeholder
            else:
                features.extend([0, 0, 0, 0, 0, 0])
            
            # Payload features
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                features.append(len(payload))
                features.append(1 if any(b < 32 or b > 126 for b in payload[:20]) else 0)  # binary content
            else:
                features.extend([0, 0])
            
            # Ethernet layer (if available)
            if packet.haslayer(Ether):
                features.append(1)  # Has ethernet header
            else:
                features.append(0)
            
            return features
            
        except Exception as e:
            print(f"⚠️ Feature extraction error: {e}")
            # Return zero features of consistent length
            return [0] * 20

    # ======================================================
    # Utility Functions
    # ======================================================
    def get_protocol_name(self, packet):
        """Get human-readable protocol name"""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(DHCP):
            return "DHCP"
        elif packet.haslayer(IPv6):
            return "IPv6"
        elif packet.haslayer(IP):
            return f"IP-{packet[IP].proto}"
        else:
            return "Unknown"

    def is_internal_traffic(self, packet):
        """Check if traffic is from internal network"""
        src_ip = self.get_source_ip(packet)
        return src_ip.startswith(self.internal_networks)

    def get_source_ip(self, packet):
        """Extract source IP from any packet type"""
        if packet.haslayer(IP):
            return packet[IP].src
        elif packet.haslayer(IPv6):
            return packet[IPv6].src
        elif packet.haslayer(ARP):
            return packet[ARP].psrc
        else:
            return "Unknown"

    def get_destination_ip(self, packet):
        """Extract destination IP from any packet type"""
        if packet.haslayer(IP):
            return packet[IP].dst
        elif packet.haslayer(IPv6):
            return packet[IPv6].dst
        elif packet.haslayer(ARP):
            return packet[ARP].pdst
        else:
            return "Unknown"

    def timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ======================================================
    # Logging
    # ======================================================
    def write_to_log(self, threat_info):
        """Log threats to file"""
        try:
            with open("threat_log.txt", "a") as f:
                f.write(json.dumps(threat_info) + "\n")
            print(f"🚨 ALERT: {threat_info['attack']} from {threat_info.get('source_ip', 'Unknown')}")
        except Exception as e:
            print(f"⚠️ Logging error: {e}")

    def log_anomaly(self, packet, features, score):
        """Log anomaly details"""
        anomaly = {
            "attack": "Anomalous Traffic",
            "timestamp": self.timestamp(),
            "source_ip": self.get_source_ip(packet),
            "destination_ip": self.get_destination_ip(packet),
            "protocol": self.get_protocol_name(packet),
            "anomaly_score": float(score),
            "features": features[:10]  # First 10 features
        }
        try:
            with open("anomaly_log.json", "a") as f:
                f.write(json.dumps(anomaly) + "\n")
            print(f"⚠️ Anomaly detected: {anomaly['source_ip']} -> {anomaly['destination_ip']}")
        except Exception as e:
            print(f"⚠️ Anomaly log error: {e}")

    # ======================================================
    # Debug/Diagnostic Methods
    # ======================================================
    def print_protocol_summary(self):
        """Print summary of protocols detected"""
        print("\n" + "="*50)
        print("PROTOCOL DETECTION SUMMARY")
        print("="*50)
        total = sum(self.protocol_stats.values())
        for protocol, count in self.protocol_stats.items():
            percentage = (count / total * 100) if total > 0 else 0
            print(f"{protocol:10} {count:6} packets ({percentage:5.1f}%)")
        print("="*50)

    def debug_packet(self, packet):
        """Debug method to print packet details"""
        print(f"\n📦 PACKET DEBUG:")
        print(f"  Protocol: {self.get_protocol_name(packet)}")
        print(f"  Source: {self.get_source_ip(packet)}")
        print(f"  Dest: {self.get_destination_ip(packet)}")
        print(f"  Length: {len(packet)} bytes")
        
        if packet.haslayer(TCP):
            print(f"  TCP Ports: {packet[TCP].sport} -> {packet[TCP].dport}")
            print(f"  TCP Flags: {packet[TCP].flags}")
        elif packet.haslayer(UDP):
            print(f"  UDP Ports: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif packet.haslayer(ICMP):
            print(f"  ICMP Type: {packet[ICMP].type}")
        
        # Check what threats would be detected
        threats = self.detect_threats(packet)
        if threats:
            print(f"  ⚠️  Threats detected: {threats}")
        else:
            print(f"  ✅ No threats detected")