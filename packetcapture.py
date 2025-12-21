import threading
from queue import Queue
from scapy.all import sniff, conf, IFACES

class PacketCapture:
    def __init__(self):
        self.packet_queue = Queue()
        self.running = False
        self.interface = None

        # Store mapping: "Wi-Fi" -> "\Device\NPF_{...}"
        self.interface_map = {}

        conf.sniff_promisc = True

    def get_available_interfaces(self):
        """
        Returns human-readable interface names for UI
        """
        interfaces = []
        self.interface_map.clear()

        for iface in IFACES.values():
            if iface.description and iface.name:
                display_name = iface.description
                self.interface_map[display_name] = iface.name
                interfaces.append(display_name)

        return interfaces

    def select_interface(self, interface):
        """
        Convert UI-selected friendly name to actual NPF device
        """
        if interface not in self.interface_map:
            raise ValueError("Invalid network interface selected.")

        self.interface = self.interface_map[interface]

    def start_capture(self):
        if not self.interface:
            raise ValueError("No network interface selected.")

        self.running = True
        threading.Thread(target=self.capture_packets, daemon=True).start()

    def stop(self):
        self.running = False

    def capture_packets(self):
        sniff(
            iface=self.interface,
            prn=self.packet_callback,
            store=0,
            promisc=True
        )

    def packet_callback(self, packet):
        if self.running:
            self.packet_queue.put(packet)
            print(packet.summary())
