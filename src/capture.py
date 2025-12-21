# src/capture.py
from scapy.all import sniff
import threading
import time

class PacketCapture:
    def __init__(self, iface=None, pcap_file=None, packet_callback=None):
        """
        iface: network interface (None -> default)
        pcap_file: if provided, read from pcap instead of live
        packet_callback: function(packet) called for each packet
        """
        self.iface = iface
        self.pcap_file = pcap_file
        self.packet_callback = packet_callback
        self._stopped = threading.Event()

    def _handle_packet(self, pkt):
        if self.packet_callback:
            try:
                self.packet_callback(pkt)
            except Exception as e:
                print("packet callback error:", e)

    def start(self):
        # run sniff in a background thread
        self._stopped.clear()
        t = threading.Thread(target=self._sniff_thread, daemon=True)
        t.start()

    def _sniff_thread(self):
        if self.pcap_file:
            sniff(offline=self.pcap_file, prn=self._handle_packet, stop_filter=lambda x: self._stopped.is_set())
        else:
            sniff(iface=self.iface, prn=self._handle_packet, stop_filter=lambda x: self._stopped.is_set())

    def stop(self):
        self._stopped.set()
        time.sleep(0.1)
