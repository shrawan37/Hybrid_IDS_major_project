# src/signature.py
from collections import defaultdict
import time
import json
import re
import os
from scapy.all import Raw
from urllib.parse import unquote

class SignatureEngine:
    def __init__(self, syn_threshold=100, scan_port_threshold=30, window=2.0, blacklist=None, signatures_path="models/signatures.json"):
        # Behavioral detection thresholds
        self.syn_counts = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.window = window
        self.syn_threshold = syn_threshold
        self.scan_port_threshold = scan_port_threshold
        self.blacklist = set(blacklist or [])
        
        # Whitelist internal/trusted networks to reduce false positives
        self.whitelist_ranges = [
            "192.168.0.0/16", 
            "192.168.0.0/24"   # Private network
            "10.0.0.0/8",        # Private network
            "172.16.0.0/12",     # Private network
            # "127.0.0.1/32",      # Removed from whitelist for local testing
            "140.82.112.0/24",   # GitHub
            "140.82.113.0/24",   # GitHub
            "13.64.0.0/11",      # Azure
            "13.96.0.0/13",      # Azure
            "13.104.0.0/14",     # Azure
            "40.64.0.0/10",      # Azure
            "40.128.0.0/9",      # Azure
            "52.160.0.0/11",     # Azure
            "20.0.0.0/8",        # Azure
            # IPv6 local and multicast ranges
            "fe80::/10",         # Link-local
            "ff00::/8",          # Multicast
            "::1/128",           # Loopback
        ]
        
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
                # Silent load - debug output removed to keep UI startup clean
            else:
                print(f"⚠️ Signatures file not found: {signatures_path}")
        except Exception as e:
            print(f"❌ Error loading signatures: {e}")

    def is_whitelisted(self, ip):
        """Check if IP is in whitelist (returns True if whitelisted)"""
        try:
            import ipaddress
            ip_addr = ipaddress.ip_address(ip)
            for range_str in self.whitelist_ranges:
                net = ipaddress.ip_network(range_str, strict=False)
                if ip_addr in net:
                    return True
        except:
            pass
        return False

    def check_payload_signatures(self, payload_str, debug=False):
        """
        Check payload against all signature patterns.
        Returns (is_malicious: bool, attack_type: str or None, score: float)
        """
        if not payload_str or not self.signatures:
            return (False, None, 0.0)
        
        # Convert to lowercase for case-insensitive matching
        payload_lower = payload_str.lower()
        
        # Try to decode URL-encoded payloads
        try:
            decoded_payload = unquote(payload_str).lower()
        except:
            decoded_payload = payload_lower
        
        # Check both original and decoded payloads
        payloads_to_check = [payload_lower, decoded_payload]
        
        # Debug: Show payload being checked
        if debug:
            print(f"[SIGNATURE DEBUG] Checking payload (len={len(payload_str)}): {payload_str[:100]}")
        
        # Check each attack pattern
        for attack_type, signature_data in self.signatures.items():
            try:
                # Handle new JSON format: signature_data is dict with "pattern" key
                if isinstance(signature_data, dict):
                    pattern = signature_data.get("pattern", "")
                    severity = signature_data.get("severity", 0.70)
                    description = signature_data.get("description", attack_type)
                else:
                    # Handle old format: signature_data is list of patterns
                    pattern = signature_data
                    severity = 0.70
                    description = attack_type
                
                # Check against all payload variations
                if pattern:
                    for payload_check in payloads_to_check:
                        try:
                            if re.search(pattern, payload_check, re.IGNORECASE):
                                if debug:
                                    print(f"[SIGNATURE MATCH] {attack_type}: pattern='{pattern[:50]}', severity={severity}")
                                return (True, attack_type, severity)
                        except re.error as regex_err:
                            print(f"[WARN] Invalid regex pattern for {attack_type}: {pattern[:50]} - {regex_err}")
                            pass
            except Exception as e:
                print(f"[WARN] Error checking signature {attack_type}: {e}")
        
        return (False, None, 0.0)

    def check_packet(self, pkt):
        """
        Return (is_malicious: bool, reason: str or None, score: float(0-1))
        Performs both behavioral and payload-based signature detection
        """
        from scapy.layers.inet import TCP, IP, UDP
        t = time.time()

        from scapy.layers.inet6 import IPv6
        if IP not in pkt and IPv6 not in pkt:
            return (False, None, 0.0)

        src = pkt[IP].src if IP in pkt else pkt[IPv6].src

        # NOTE: We DO NOT return early for whitelisted IPs anymore.
        # We want to detect SQLi/XSS even from internal "trusted" users (Insider Threat).
        # Whitelist will ONLY apply to behavioral checks (SYN Flood, Port Scan) below.

        # Blacklist check
        if src in self.blacklist:
            return (True, "blacklisted IP", 1.0)

        # Check payload for attack signatures
        payload_to_check = ""
        
        if Raw in pkt:
            try:
                raw_load = bytes(pkt[Raw].load)
                # Decode to string, ignoring errors
                payload_str = raw_load.decode(errors='ignore')
                
                # Check raw payload first
                is_mal, attack_type, score = self.check_payload_signatures(payload_str)
                if is_mal:
                    return (True, f"Signature: {attack_type}", score)
                
                # For HTTP packets, extract the full payload including URL
                if b'HTTP' in raw_load or b'GET' in raw_load or b'POST' in raw_load or b'PUT' in raw_load or b'DELETE' in raw_load:
                    lines = payload_str.split('\r\n')
                    if lines:
                        request_line = lines[0]  # GET /path?query HTTP/1.1
                        # Check request line for signatures
                        is_mal, attack_type, score = self.check_payload_signatures(request_line)
                        if is_mal:
                            return (True, f"Signature: {attack_type}", score)
                        
                        # Check full payload
                        is_mal, attack_type, score = self.check_payload_signatures(payload_str)
                        if is_mal:
                            return (True, f"Signature: {attack_type}", score)
                        
            except Exception as e:
                pass  # Silent fail for payload extraction

        # TCP SYN flood & Port Scan detection (Only for TCP packets)
        # IMPORTANT: Only enforce behavioral limits on NON-WHITELISTED IPs
        if TCP in pkt and not self.is_whitelisted(src):
            tcp = pkt[TCP]
            flags = tcp.flags
            # SYN flood: multiple packets with only SYN flag from same source
            if flags == 0x02:  # Only SYN flag
                self.syn_counts[src].append(t)
                # Remove old entries outside the window
                self.syn_counts[src] = [x for x in self.syn_counts[src] if t - x <= self.window]
                if len(self.syn_counts[src]) >= self.syn_threshold:
                    return (True, "SYN flood", 0.9)

            # Port-scan detection: only count SYN packets (connection attempts)
            # This prevents server replies to ephemeral ports from being flagged as scans
            if flags == 0x02:  # Only SYN flag
                dst_port = tcp.dport
                key = src
                self.port_scans[key].add(dst_port)
                # Check if port scan threshold reached
                if len(self.port_scans[key]) >= self.scan_port_threshold:
                    return (True, "port scan", 0.85)

        # Could add other signature checks (ICMP flood, etc.)
        return (False, None, 0.0)
