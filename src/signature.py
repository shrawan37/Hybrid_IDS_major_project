# src/signature.py
from collections import defaultdict
import time

class SignatureEngine:
    def __init__(self, syn_threshold=50, scan_port_threshold=30, window=2.0, blacklist=None):
        # syn_threshold: number of SYNs from one src within window -> SYN flood
        self.syn_counts = defaultdict(list)
        self.port_scans = defaultdict(set)
        self.window = window
        self.syn_threshold = syn_threshold
        self.scan_port_threshold = scan_port_threshold
        self.blacklist = set(blacklist or [])

    def check_packet(self, pkt):
        """
        Return (is_malicious: bool, reason: str or None, score: float(0-1))
        """
        from scapy.layers.inet import TCP, IP
        t = time.time()

        if IP not in pkt:
            return (False, None, 0.0)

        src = pkt[IP].src

        # Blacklist check
        if src in self.blacklist:
            return (True, "blacklisted IP", 1.0)

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
