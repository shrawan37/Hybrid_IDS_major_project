import sys
import os
import threading
from queue import Queue

# Ensure src/ is on the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from scapy.all import sniff, conf, IFACES
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

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
<<<<<<< HEAD
        self.packet_queue = Queue()
=======
        # Limited size to prevent memory leaks during high traffic
        self.packet_queue = Queue(maxsize=1000)
>>>>>>> main

        # Runtime state
        self.running = False
        self.interface = None
        self.interface_map = {}
        self.sniffer_thread = None

        # Scapy config
        conf.sniff_promisc = True  # enable promiscuous mode

        # Initialize detection engines with robust error handling
        try:
            self.signature_engine = SignatureEngine()
        except Exception as e:
            print(f"[WARN] Signature engine failed: {e}")
            self.signature_engine = None
            
        try:
            self.anomaly_engine = AnomalyEngine(
                model_path=model_path,
                scaler_path=scaler_path,
                encoder_path=encoder_path
            )
        except Exception as e:
            print(f"[WARN] Anomaly engine failed: {e}")
            self.anomaly_engine = None
            
        try:
            if self.signature_engine and self.anomaly_engine:
                self.hybrid_engine = HybridEngine(self.signature_engine, self.anomaly_engine)
            else:
                self.hybrid_engine = None
        except Exception as e:
            print(f"[WARN] Hybrid engine failed: {e}")
            self.hybrid_engine = None

        # Initialize feature extractor
        try:
            self.feature_extractor = FeatureExtractor()
        except Exception as e:
            print(f"[WARN] Feature extractor failed: {e}")
            self.feature_extractor = None

    def get_available_interfaces(self):
        """Return a list of human-readable interface names for the UI combobox."""
        interfaces = []
        self.interface_map.clear()

        try:
            for iface in IFACES.values():
                display_name = iface.description or iface.name
                if display_name and iface.name:
                    self.interface_map[display_name] = iface.name
                    interfaces.append(display_name)

            interfaces.sort()
            
            if not interfaces:
                # Fallback: use basic interface list
                from scapy.all import get_if_list
                basic_interfaces = get_if_list()
                for iface in basic_interfaces:
                    self.interface_map[iface] = iface
                    interfaces.append(iface)
            
            return interfaces
        except Exception as e:
            print(f"[WARNING] Error getting interfaces: {e}")
            # Return empty list so UI doesn't crash
            return []

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
        print("[INFO] Stop signal sent to packet capture...")
        
    def _sniff_loop(self):
        """Run Scapy sniff continuously until stop signal is received."""
        try:
            print(f"[INFO] Starting packet capture on interface: {self.interface}")
            sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                promisc=True,
                stop_filter=lambda pkt: not self.running  # Only stop when self.running becomes False
            )
            print("[INFO] Packet capture stopped.")
        except PermissionError as e:
            print(f"[ERROR] Permission denied: {e}")
            print(f"[ERROR] Make sure you're running as Administrator!")
            self.running = False
        except OSError as e:
            print(f"[ERROR] Interface error: {e}")
            print(f"[ERROR] Interface '{self.interface}' might not exist or Npcap is not installed")
            print(f"[ERROR] Install Npcap from: https://npcap.com/")
            self.running = False
        except Exception as e:
            print(f"[ERROR] Sniffing failed: {e}")
            self.running = False

    def _parse_packet(self, pkt):
        """Extract Source, Destination, Protocol, Length, Info for UI display."""
        src = "Unknown"
        dst = "Unknown"
        proto = "Other"
        info = ""

        # Priority 1: IPv4 Layer
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

        # Priority 2: IPv6 Layer
        elif IPv6 in pkt:
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            proto = "IPv6"
            if TCP in pkt:
                proto = "TCP"
                info = f"TCP {pkt[TCP].sport}->{pkt[TCP].dport} [{pkt[TCP].flags}]"
            elif UDP in pkt:
                proto = "UDP"
                info = f"UDP {pkt[UDP].sport}->{pkt[UDP].dport}"

        # Priority 3: ARP Layer
        elif ARP in pkt:
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst
            proto = "ARP"
            info = f"ARP op={pkt[ARP].op}"

        # Priority 4: Ethernet Layer (Fallback to MAC)
        elif Ether in pkt:
            src = pkt[Ether].src
            dst = pkt[Ether].dst
            proto = "Ether"

        length = len(pkt)
        return src, dst, proto, length, info


    def _packet_callback(self, packet):
        """Called by Scapy for each packet. Push to queue for UI - NO HEAVY PROCESSING HERE!"""
        if not self.running:
            return

        # Parse packet for UI - lightweight operation only
        src, dst, proto, length, info = self._parse_packet(packet)

        # Push parsed details into queue (instead of raw packet only)
        # IMPORTANT: We don't do threat detection here to avoid blocking the sniffer thread
<<<<<<< HEAD
        self.packet_queue.put({
            "packet": packet,
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": length,
            "info": info
        })
=======
        try:
            self.packet_queue.put_nowait({
                "packet": packet,
                "src": src,
                "dst": dst,
                "proto": proto,
                "length": length,
                "info": info
            })
        except:
            # Queue full, drop packet to maintain real-time performance
            pass
>>>>>>> main
        
        # NOTE: Threat detection is now handled by the UI thread's worker
        # This callback must stay very fast to prevent packet loss