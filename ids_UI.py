import tkinter as tk
from tkinter import messagebox, ttk
from scapy.all import IP, ICMP, TCP, UDP, IPv6
from packetcapture import PacketCapture  
import time
import packet_info  
from detectionengine import DetectionEngine  
import threading
import alert_popup  # Import alert popup module for threat notifications
from threat_log import ThreatLogWindow  # Import ThreatLogWindow from threat_log


class IDSUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System")

        # Initialize Packet Capture & Detection Engine
        self.packet_capture = PacketCapture()
        self.detection_engine = DetectionEngine()  
        self.packet_list = []
        self.threats_detected = []  # Store detected threats

        # Start Detection in Background
        self.detection_thread = threading.Thread(target=self.run_detection, daemon=True)
        self.detection_thread.start()

        # UI Elements
        tk.Label(root, text="Select Network Interface:").pack(pady=10)
        self.interface_dropdown = tk.StringVar()

        # Automatically select the first available interface
        interfaces = self.get_available_interfaces()
        if interfaces:
            self.interface_dropdown.set(interfaces[0])

        self.interface_dropdown_menu = tk.OptionMenu(self.root, self.interface_dropdown, *interfaces)
        self.interface_dropdown_menu.pack(pady=10)

        # Create a frame to hold the buttons in a row
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        # Place buttons inside the frame using 'pack' with side='left' to arrange them horizontally
        tk.Button(button_frame, text="Start Capture", command=self.start_capture).pack(side="left", padx=10)
        tk.Button(button_frame, text="Stop Capture", command=self.stop_capture).pack(side="left", padx=10)
        tk.Button(button_frame, text="Show Threat Log", command=self.show_threat_log).pack(side="left", padx=10)


        self.status_label = tk.Label(root, text="Status: Not capturing")
        self.status_label.pack(pady=20)

        # Treeview for Packet Display
        self.packet_tree = ttk.Treeview(self.root, columns=("S.N", "Time", "Source IP", "Destination IP", "Protocol", "Size", "Info", "Threat"), show="headings")
        for col in ("S.N", "Time", "Source IP", "Destination IP", "Protocol", "Size", "Info", "Threat"):
            self.packet_tree.heading(col, text=col)
        self.packet_tree.pack(pady=20, expand=True, fill=tk.BOTH)
        self.packet_tree.bind("<ButtonRelease-1>", self.on_info_click)

        self.packet_counter = 1

    def get_available_interfaces(self):
        return self.packet_capture.get_available_interfaces()
    
    def run_detection(self):
        """ Continuously check packets for threats in the background. """
        while True:
            if not self.packet_capture.packet_queue.empty():
                packet = self.packet_capture.packet_queue.get() 

                print(f"[DEBUG] Processing packet: {packet.summary()}")  # Debugging

                threats = self.detection_engine.detect_threats(packet)

                print(f"[DEBUG] Detected threats: {threats}")  # Debugging

                # If threats are found, show an alert
                if threats:
                    self.threats_detected.append((packet, threats))
                    self.root.after(0, lambda: alert_popup.show_alert(threats, packet))  # Trigger GUI alert

                # Add threat info to the packet display
                self.root.after(0, self.display_packet, packet, threats)

    def start_capture(self):
        selected_iface = self.interface_dropdown.get()
        if not selected_iface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        try:
            self.packet_capture.select_interface(selected_iface)
            self.packet_capture.start_capture()  # Now calling start_capture without passing packet_queue
            self.status_label.config(text=f"Capturing on {selected_iface}...")
            self.update_live_packets()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {e}")

    def stop_capture(self):
        self.packet_capture.stop()
        self.status_label.config(text="Capture stopped.")

    def display_packet(self, packet, threats=None):
        """ Display captured packet details in the UI and auto-scroll to latest entry. """
        time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        src_ip, dst_ip = (
            packet[IP].src if IP in packet else packet[IPv6].src if IPv6 in packet else "N/A",
            packet[IP].dst if IP in packet else packet[IPv6].dst if IPv6 in packet else "N/A"
        )
        protocol, size, info = self.get_protocol(packet), len(packet), self.get_packet_info(packet)
        

        # ✅ Extract payload safely
        raw_payload = self.extract_payload(packet)
        payload_display = self.format_payload(raw_payload).split("\n")[0]  # Show only first line

        # ✅ Threat Information (Fixed!)
        threat_info = ", ".join([threat['attack'] for threat in threats]) if threats else "None"

        print(f"[DEBUG] Threat Info for {src_ip} -> {dst_ip}: {threat_info}")  # Debugging

        # Insert packet into Treeview and auto-scroll
        self.packet_tree.insert("", "end", 
            values=(self.packet_counter, time_str, src_ip, dst_ip, protocol, size, payload_display, threat_info)
        )
        self.packet_tree.yview_moveto(1.0)  # Auto-scroll to latest packet

        self.packet_list.append(packet)
        self.packet_counter += 1


    def extract_payload(self, packet):
        """ Extracts payload safely from TCP or UDP packets """
        if packet.haslayer(TCP) and hasattr(packet[TCP].payload, "load"):
            return bytes(packet[TCP].payload.load)
        elif packet.haslayer(UDP) and hasattr(packet[UDP].payload, "load"):
            return bytes(packet[UDP].payload.load)
        return b""

    def format_payload(self, raw_payload):
        """ Convert payload to Wireshark-style Hex + ASCII format """
        if not raw_payload:  
            return "No Payload"

        hex_ascii_lines = []
        for i in range(0, len(raw_payload), 16):
            chunk = raw_payload[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_ascii_lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")

        return "\n".join(hex_ascii_lines)

    def get_protocol(self, packet):
        return "ICMP" if packet.haslayer(ICMP) else "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "Unknown"

    def get_packet_info(self, packet):
        """ Extract TCP/UDP-specific details for display """
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            return f"Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}, Flags: {tcp_layer.flags}"
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            return f"Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}"
        return "No additional info"

    def update_live_packets(self):
        """ Update the UI with captured packets every 100ms """
        while not self.packet_capture.packet_queue.empty():
            self.display_packet(self.packet_capture.packet_queue.get())
        self.root.after(100, self.update_live_packets)

    def on_info_click(self, event):
        """ Handle clicking on the 'Info' column """
        region, item, col = self.packet_tree.identify_region(event.x, event.y), self.packet_tree.identify_row(event.y), self.packet_tree.identify_column(event.x)
        if region == 'cell' and col == "#7":
            sn = self.packet_tree.item(item, "values")[0]
            try:
                packet = self.packet_list[int(sn) - 1]
                packet_info.show_packet_info(self.root, packet)
            except IndexError:
                messagebox.showerror("Error", "Invalid packet index.")

    # Add this inside your IDSUI class
    def show_threat_log(self):
        """ Open a new window to show the logged threats. """
        # Import and create the threat log window
        from threat_log import ThreatLogWindow
        threat_log = tk.Toplevel(self.root)  # Create a new top-level window
        ThreatLogWindow(threat_log)  # Pass the detected threats (logged from the file)


   



if __name__ == "__main__":
    root = tk.Tk()
    IDSUI(root)
    root.mainloop()