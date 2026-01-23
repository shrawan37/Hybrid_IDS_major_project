# src/signature.py
from collections import defaultdict
import time
import json
import re
import os
from scapy.all import Raw
from urllib.parse import unquote

class SignatureEngine:
    def __init__(self, syn_threshold=50, scan_port_threshold=30, window=2.0, blacklist=None, signatures_path="models/signatures.json"):
        # Behavioral detection thresholds
        self.syn_counts = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.window = window
        self.syn_threshold = syn_threshold
        self.scan_port_threshold = scan_port_threshold
        self.blacklist = set(blacklist or [])
        
        # Load signature patterns from JSON
        self.signatures = {}
        self.load_signatures(signatures_path)

    def load_signatures(self, signatures_path):
        """Load attack signatures from JSON file"""
        try:
            # Try relative path first
            if not os.path.exists(signatures_path):
                # Try from src directory
                signatures_path = os.path.join(os.path.dirname(__file__), "..", signatures_path)
            
            if os.path.exists(signatures_path):
                with open(signatures_path, 'r') as f:
                    self.signatures = json.load(f)
                print(f"✅ Loaded {len(self.signatures)} attack signatures")
            else:
                print(f"⚠️ Signatures file not found: {signatures_path}")
        except Exception as e:
            print(f"❌ Error loading signatures: {e}")

    def check_payload_signatures(self, payload_str):
        """
        Check payload against all signature patterns.
        Returns (is_malicious: bool, attack_type: str or None, score: float)
        """
        if not payload_str or not self.signatures:
            return (False, None, 0.0)
        
        # Try to decode URL-encoded payloads
        try:
            decoded_payload = unquote(payload_str)
        except:
            decoded_payload = payload_str
        
        # Check both original and decoded payloads
        payloads_to_check = [payload_str, decoded_payload]
        
        # Check each attack pattern
        for attack_type, signature_data in self.signatures.items():
            try:
                # Handle new JSON format: signature_data is dict with "pattern" key
                if isinstance(signature_data, dict):
                    pattern = signature_data.get("pattern", "")
                    severity = signature_data.get("severity", 0.70)
                else:
                    # Handle old format: signature_data is list of patterns
                    pattern = signature_data
                    severity = 0.70
                
                # Check against all payload variations
                if pattern:
                    for payload_check in payloads_to_check:
                        if re.search(pattern, payload_check, re.IGNORECASE):
                            return (True, attack_type, severity)
            except re.error:
                pass
        
        return (False, None, 0.0)

    def check_packet(self, pkt):
        """
        Return (is_malicious: bool, reason: str or None, score: float(0-1))
        Performs both behavioral and payload-based signature detection
        """
        from scapy.layers.inet import TCP, IP
        t = time.time()

        if IP not in pkt:
            return (False, None, 0.0)

        src = pkt[IP].src

        # Blacklist check
        if src in self.blacklist:
            return (True, "blacklisted IP", 1.0)

        # Check payload for attack signatures
        payload_to_check = ""
        
        if Raw in pkt:
            try:
                raw_load = bytes(pkt[Raw].load)
                # Decode to string, ignoring errors
                payload_to_check = raw_load.decode(errors='ignore')
                
                # For HTTP packets, extract the HTTP payload (after headers)
                if b'HTTP' in raw_load or b'GET' in raw_load or b'POST' in raw_load:
                    # Try to get just the request/response part
                    payload_to_check = raw_load.decode(errors='ignore')
                
                is_mal, attack_type, score = self.check_payload_signatures(payload_to_check)
                if is_mal:
                    return (True, f"Signature: {attack_type}", score)
            except Exception as e:
                pass

        # TCP SYN flood detection
        if TCP in pkt:
            tcp = pkt[TCP]
            flags = tcp.flags
            if flags & 0x02:  # SYN bit
                self.syn_counts[src].append(t)
                # prune old
                self.syn_counts[src] = [x for x in self.syn_counts[src] if t - x <= self.window]
                if len(self.syn_counts[src]) >= self.syn_threshold:
                    return (True, "possible SYN flood", 0.9)

            # Port-scan detection (same src hitting many dst ports)
            dst_port = tcp.dport
            key = src
            self.port_scans[key].add(dst_port)
            # naive prune isn't implemented for simplicity; for long running, track timestamped ports
            if len(self.port_scans[key]) >= self.scan_port_threshold:
                return (True, "possible port scan", 0.85)

        # Could add other signature checks (ICMP flood, etc.)
        return (False, None, 0.0)
