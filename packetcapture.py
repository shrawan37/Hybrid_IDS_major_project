import sys
import os
import threading
from queue import Queue

# Ensure src/ is on the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from scapy.all import sniff, conf, IFACES
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Import your feature extractor and engines
from features import FeatureExtractor
from signature import SignatureEngine
from anamoly import AnomalyEngine
from hybridengine import HybridEngine


class PacketCapture:
    """
    Handles interface discovery, starting/stopping Scapy sniffing in a background thread,
    pushing packets into a queue for the UI, and running hybrid detection.
    """

    def __init__(
        self,
        model_path="models/isolation_forest.pkl",
        scaler_path="models/scaler.pkl",
        encoder_path="models/encoder.pkl"
    ):
        # Queue consumed by IDS_UI.update_packet_display()
        self.packet_queue = Queue()

        # Runtime state
        self.running = False
        self.interface = None
        self.interface_map = {}
        self.sniffer_thread = None

        # Scapy config
        conf.sniff_promisc = True  # enable promiscuous mode

        # Initialize detection engines
        self.signature_engine = SignatureEngine()
        self.anomaly_engine = AnomalyEngine(
            model_path=model_path,
            scaler_path=scaler_path,
            encoder_path=encoder_path
        )
        self.hybrid_engine = HybridEngine(self.signature_engine, self.anomaly_engine)

        # Initialize feature extractor
        self.feature_extractor = FeatureExtractor()

    def get_available_interfaces(self):
        """Return a list of human-readable interface names for the UI combobox."""
        interfaces = []
        self.interface_map.clear()

        for iface in IFACES.values():
            display_name = iface.description or iface.name
            if display_name and iface.name:
                self.interface_map[display_name] = iface.name
                interfaces.append(display_name)

        interfaces.sort()
        return interfaces

    def select_interface(self, interface_display_name):
        """Convert UI-selected friendly name to actual NPF device name used by Scapy."""
        if interface_display_name not in self.interface_map:
            raise ValueError(f"Invalid network interface selected: {interface_display_name}")
        self.interface = self.interface_map[interface_display_name]

    def start_capture(self):
        """Start sniffing in a background thread. Requires admin privileges on Windows."""
        if not self.interface:
            raise ValueError("No network interface selected.")

        if self.running:
            return  # already running

        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniffer_thread.start()

    def stop(self):
        """Signal the sniffer to stop."""
        self.running = False

    def _sniff_loop(self):
        """Run Scapy sniff with a stop_filter so it can exit when self.running becomes False."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                promisc=True,
                stop_filter=lambda pkt: not self.running
            )
        except PermissionError as e:
            print(f"[ERROR] Permission denied while sniffing: {e}. Try running as Administrator.")
        except Exception as e:
            print(f"[ERROR] Sniffing failed: {e}")

    def _parse_packet(self, pkt):
        """Extract Source, Destination, Protocol, Length, Info for UI display."""
        src = "Unknown"
        dst = "Unknown"
        proto = "Other"
        info = ""

        # Ethernet layer
        if Ether in pkt:
            src = pkt[Ether].src
            dst = pkt[Ether].dst
            proto = "Ether"

        # ARP layer
        if ARP in pkt:
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            proto = "ARP"
            info = f"ARP op={pkt[ARP].op} hwsrc={pkt[ARP].hwsrc} hwdst={pkt[ARP].hwdst}"

        # IP layer
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "IP"
            if TCP in pkt:
                proto = "TCP"
                info = f"TCP sport={pkt[TCP].sport} dport={pkt[TCP].dport} flags={pkt[TCP].flags}"
            elif UDP in pkt:
                proto = "UDP"
                info = f"UDP sport={pkt[UDP].sport} dport={pkt[UDP].dport}"
            elif ICMP in pkt:
                proto = "ICMP"
                info = f"ICMP type={pkt[ICMP].type} code={pkt[ICMP].code}"

        length = len(pkt)
        return src, dst, proto, length, info

    def _packet_callback(self, packet):
        """Called by Scapy for each packet. Push to queue for UI and run hybrid detection."""
        if not self.running:
            return

        # Parse packet for UI
        src, dst, proto, length, info = self._parse_packet(packet)

        # Push parsed details into queue (instead of raw packet only)
        self.packet_queue.put({
            "packet": packet,
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": length,
            "info": info
        })

        # Extract features for anomaly engine
        try:
            feat_dict = self.feature_extractor.extract_packet_features(packet)
        except Exception as e:
            print(f"[WARN] Feature extraction failed: {e}")
            feat_dict = {}

        # Run hybrid analysis
        try:
            result = self.hybrid_engine.analyze(packet, feat_dict)
            if result.get('malicious'):
                print(f"[ALERT] Malicious packet detected! Reasons: {result.get('reasons')} | "
                      f"Score: {result.get('score'):.2f}")
            else:
                print(f"[INFO] Normal packet | Score: {result.get('score'):.2f}")
        except Exception as e:
            print(f"[ERROR] Hybrid analysis failed: {e}")