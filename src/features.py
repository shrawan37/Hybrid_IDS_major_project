# src/features.py
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time

class FeatureExtractor:
    def __init__(self):
        # minimal stateful counters for small flow features
        self.last_seen = {}  # track per src,dst tuple
        self.window_size = 2.0  # seconds for small window features

    def extract_packet_features(self, pkt):
        """
        Returns a dict of numeric features for the packet.
        Keep features small (6-12).
        """
        now = time.time()
        feat = {}
        proto = 0
        length = len(pkt)
        src = None
        dst = None
        sport = 0
        dport = 0
        tcp_flags = 0

        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            proto = ip.proto

        if TCP in pkt:
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            tcp_flags = int(tcp.flags)
        elif UDP in pkt:
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
        elif ICMP in pkt:
            proto = 1

        key = (src, dst)
        if key not in self.last_seen:
            self.last_seen[key] = []
        self.last_seen[key].append(now)

        # count packets in short window for src->dst
        window_times = [t for t in self.last_seen[key] if now - t <= self.window_size]
        # prune
        self.last_seen[key] = window_times

        # features: pkt_len, proto, sport, dport, tcp_flags, recent_pkt_count
        feat['pkt_len'] = length
        feat['proto'] = proto
        feat['sport'] = sport
        feat['dport'] = dport
        feat['tcp_flags'] = tcp_flags
        feat['recent_count'] = len(window_times)
        return feat
