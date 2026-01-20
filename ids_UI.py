import tkinter as tk
from tkinter import ttk
from packetcapture import PacketCapture
from packet_info import show_packet_info
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS

class IDS_UI:
    def __init__(self, root):
        self.root = root
        self.root.title("Intrusion Detection System ")
        self.root.geometry("1400x800")
        
        # Packet capture instance with the updated implementation
        self.capture = PacketCapture()
        self.capturing = False
        
        # Store packets for display
        self.packets_list = []      # Parsed packet info for display
        self.raw_packets = []       # Store actual Scapy packets for details
        self.display_limit = 100    # Show last 100 packets
        
        # Protocol statistics
        self.protocol_counts = {
            'TCP': 0,
            'UDP': 0, 
            'ICMP': 0,
            'ARP': 0,
            'Other': 0
        }
        
        # Threat counter
        self.threat_count = 0
        
        # Create UI components
        self.create_widgets()
        
    def create_widgets(self):
        # ========== HEADER FRAME ==========
        header_frame = tk.Frame(self.root, bg="#1a1a2e", height=120)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(
            header_frame,
            text="🚨 Intrusion Detection System - Live Packet Capture",
            font=("Consolas", 18, "bold"),
            fg="#00ff9d",
            bg="#1a1a2e"
        )
        title_label.pack(pady=(15, 5))
        
        # Network Interface Info
        interface_info = tk.Label(
            header_frame,
            text="[Module 1@ MITSC] VM: R4.802.11w-PCX-AWx_2  |  [Live Capture Mode]",
            font=("Consolas", 10),
            fg="#8a8aff",
            bg="#1a1a2e"
        )
        interface_info.pack(pady=5)
        
        # Status Bar
        self.status_label = tk.Label(
            header_frame,
            text="Status: Ready | Select interface and click Start Capture",
            font=("Consolas", 9),
            fg="#ffcc00",
            bg="#1a1a2e"
        )
        self.status_label.pack(pady=5)
        
        # ========== CONTROL FRAME ==========
        control_frame = tk.Frame(self.root, bg="#16213e", height=70)
        control_frame.pack(fill=tk.X)
        control_frame.pack_propagate(False)
        
        # Left side - Interface selection
        left_control = tk.Frame(control_frame, bg="#16213e")
        left_control.pack(side=tk.LEFT, padx=20, pady=15)
        
        tk.Label(left_control, text="📡 Network Interface:", 
                bg="#16213e", fg="white", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        self.interface_var = tk.StringVar()
        interfaces = self.capture.get_available_interfaces()
        
        interface_frame = tk.Frame(left_control, bg="#16213e")
        interface_frame.pack(pady=5)
        
        self.interface_combo = ttk.Combobox(
            interface_frame, 
            textvariable=self.interface_var,
            values=interfaces, 
            width=45,
            state="readonly",
            font=("Arial", 10)
        )
        self.interface_combo.pack(side=tk.LEFT)
        
        if interfaces:
            self.interface_combo.set(interfaces[0])
        else:
            self.interface_combo.set("No interfaces found")
            self.interface_combo.config(state="disabled")
        
        # Right side - Buttons
        right_control = tk.Frame(control_frame, bg="#16213e")
        right_control.pack(side=tk.RIGHT, padx=20, pady=15)
        
        self.start_btn = tk.Button(
            right_control, 
            text="▶ START CAPTURE", 
            command=self.start_capture,
            bg="#00b894",
            fg="white",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=5,
            relief=tk.RAISED,
            bd=2
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(
            right_control, 
            text="⏹ STOP CAPTURE", 
            command=self.stop_capture,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 11, "bold"),
            padx=20,
            pady=5,
            relief=tk.RAISED,
            bd=2,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(
            right_control,
            text="🗑 CLEAR",
            command=self.clear_packets,
            bg="#3498db",
            fg="white",
            font=("Arial", 11),
            padx=15,
            pady=5
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # ========== STATISTICS FRAME ==========
        stats_frame = tk.Frame(self.root, bg="#0f3460", height=50)
        stats_frame.pack(fill=tk.X)
        stats_frame.pack_propagate(False)
        
        self.stats_label = tk.Label(
            stats_frame,
            text="📊 Statistics: Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | ARP: 0 | Other: 0 | Threats: 0",
            bg="#0f3460",
            fg="white",
            font=("Consolas", 10, "bold")
        )
        self.stats_label.pack(pady=15)
        
        # ========== PACKET TABLE FRAME ==========
        table_frame = tk.Frame(self.root, bg="#2d3436")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        # Create Treeview (Table) for packet display - WIRESHARK STYLE
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info", "Threat")
        
        style = ttk.Style()
        style.configure("Treeview", 
                       background="#1e272e",
                       foreground="white",
                       fieldbackground="#1e272e",
                       font=("Consolas", 9))
        
        style.configure("Treeview.Heading",
                       background="#2d3436",
                       foreground="#00ff9d",
                       font=("Consolas", 9, "bold"),
                       relief=tk.FLAT)
        
        self.packet_tree = ttk.Treeview(
            table_frame, 
            columns=columns, 
            show="headings", 
            height=20,
            style="Treeview"
        )
        
        # Define column headings with Wireshark-like widths
        column_configs = [
            ("No.", 50, "center"),
            ("Time", 120, "center"),
            ("Source", 180, "w"),
            ("Destination", 180, "w"),
            ("Protocol", 80, "center"),
            ("Length", 70, "center"),
            ("Info", 350, "w"),
            ("Threat", 100, "center")
        ]
        
        for col, width, anchor in column_configs:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=width, anchor=anchor, minwidth=50)
        
        # Add scrollbars
        v_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.packet_tree.yview)
        h_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Grid layout
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        
        # Configure grid weights
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.packet_tree.bind("<Double-1>", self.show_packet_details)
        self.packet_tree.bind("<Button-3>", self.show_context_menu)
        
        # ========== DETECTION LOG FRAME ==========
        log_frame = tk.Frame(self.root, bg="#1a1a2e", height=180)
        log_frame.pack(fill=tk.X)
        log_frame.pack_propagate(False)
        
        log_header = tk.Frame(log_frame, bg="#1a1a2e")
        log_header.pack(fill=tk.X, padx=15, pady=(10, 5))
        
        tk.Label(log_header, text="📋 DETECTION LOG", 
                font=("Arial", 12, "bold"),
                bg="#1a1a2e", fg="#00ff9d").pack(side=tk.LEFT)
        
        tk.Label(log_header, text="[Real-time alerts and system messages]",
                font=("Arial", 9, "italic"),
                bg="#1a1a2e", fg="#8a8aff").pack(side=tk.LEFT, padx=10)
        
        # Log text area with scrollbar
        log_text_frame = tk.Frame(log_frame, bg="#0d1117")
        log_text_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 10))
        
        self.log_text = tk.Text(
            log_text_frame, 
            height=8, 
            bg="#0d1117", 
            fg="#8b949e",
            font=("Consolas", 9),
            wrap=tk.WORD,
            relief=tk.FLAT,
            insertbackground="white"
        )
        
        log_scroll = tk.Scrollbar(log_text_frame, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=log_scroll.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initial log message
        self.add_log("System initialized. Ready to capture packets.")
        self.add_log(f"Found {len(interfaces) if interfaces else 0} network interfaces.")
        
        # ========== START PACKET DISPLAY UPDATE ==========
        self.update_packet_display()
        
    def start_capture(self):
        """Start packet capture"""
        if not self.interface_var.get() or self.interface_var.get() == "No interfaces found":
            self.add_log("❌ ERROR: Please select a valid network interface", "error")
            return
        
        try:
            self.capture.select_interface(self.interface_var.get())
            self.capture.start_capture()
            self.capturing = True
            
            # Update UI state
            self.start_btn.config(state=tk.DISABLED, bg="#7bed9f")
            self.stop_btn.config(state=tk.NORMAL, bg="#ff6b6b")
            self.interface_combo.config(state="disabled")
            self.status_label.config(text=f"Status: Capturing on {self.interface_var.get()} | Packets: 0", fg="#00ff9d")
            
            self.add_log(f"✅ Capture STARTED on interface: {self.interface_var.get()}")
            self.add_log("Listening for network traffic...")
            
        except Exception as e:
            self.add_log(f"❌ ERROR starting capture: {str(e)}", "error")
            self.status_label.config(text=f"Status: Error - {str(e)}", fg="red")
        
    def stop_capture(self):
        """Stop packet capture"""
        try:
            self.capture.stop()
            self.capturing = False
            
            # Update UI state
            self.start_btn.config(state=tk.NORMAL, bg="#00b894")
            self.stop_btn.config(state=tk.DISABLED, bg="#e74c3c")
            self.interface_combo.config(state="readonly")
            
            packet_count = len(self.packets_list)
            self.status_label.config(text=f"Status: Stopped | Total Packets: {packet_count}", fg="#ffcc00")
            
            self.add_log(f"⏹ Capture STOPPED. Total packets captured: {packet_count}")
            
        except Exception as e:
            self.add_log(f"❌ ERROR stopping capture: {str(e)}", "error")
            
    def clear_packets(self):
        """Clear all packets from display"""
        # Clear treeview
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Clear stored packets
        self.packets_list.clear()
        self.raw_packets.clear()
        
        # Reset counters
        self.protocol_counts = {k: 0 for k in self.protocol_counts}
        self.threat_count = 0
        
        # Update UI
        self.update_statistics()
        self.add_log("🧹 All packets cleared from display.")
        
    def add_log(self, message, msg_type="info"):
        """Add message to detection log with color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on message type
        colors = {
            "info": "#8b949e",
            "error": "#ff6b6b",
            "warning": "#ffcc00",
            "success": "#00ff9d",
            "threat": "#ff4757"
        }
        
        color = colors.get(msg_type, "#8b949e")
        
        # Insert with color tag
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        
        # Apply color to the new line
        start_index = f"{self.log_text.index(tk.END).split('.')[0]}.0"
        self.log_text.tag_add(msg_type, f"{float(start_index)-1.0}", start_index)
        self.log_text.tag_config(msg_type, foreground=color)
        
        # Auto-scroll to bottom
        self.log_text.see(tk.END)

    def update_packet_display(self):
        """Periodically update the packet display by consuming from packet_queue"""
        if self.capturing and self.capture.running:
            packets_processed = 0
            
            # Process all available packets in the queue
            while not self.capture.packet_queue.empty():
                try:
                    pkt_info = self.capture.packet_queue.get()
                    
                    # Extract parsed fields from dict (as provided by _parse_packet in packetcapture.py)
                    src = pkt_info.get("src", "Unknown")
                    dst = pkt_info.get("dst", "Unknown")
                    proto = pkt_info.get("proto", "Other")
                    length = pkt_info.get("length", 0)
                    info = pkt_info.get("info", "")
                    packet = pkt_info.get("packet")
                    
                    # Store raw packet for details view
                    self.raw_packets.append(packet)
                    
                    # Parse additional info for display (similar to your original parse_packet)
                    parsed_info = self.parse_packet_for_display(packet)
                    
                    # Update protocol statistics
                    display_proto = parsed_info["protocol"]
                    if display_proto in self.protocol_counts:
                        self.protocol_counts[display_proto] += 1
                    else:
                        self.protocol_counts["Other"] += 1
                    
                    # Threat detection using hybrid engine
                    threat = ""
                    try:
                        # Extract features for anomaly engine
                        feat_dict = self.capture.feature_extractor.extract_packet_features(packet)
                        # Run hybrid analysis
                        result = self.capture.hybrid_engine.analyze(packet, feat_dict)
                        if result.get("malicious"):
                            threat = "⚠ " + ", ".join(result.get("reasons", []))
                            self.threat_count += 1
                            # Log the threat
                            self.add_log(f"🚨 THREAT DETECTED: {threat} from {src}", "threat")
                    except Exception as e:
                        # Fallback to basic threat detection
                        threat = self.basic_threat_detection(packet)
                        if threat:
                            self.threat_count += 1
                            self.add_log(f"🚨 BASIC THREAT: {threat} from {src}", "threat")
                    
                    # Keep only last N packets
                    if len(self.raw_packets) > self.display_limit:
                        self.raw_packets.pop(0)
                        # Remove from Treeview
                        if self.packet_tree.get_children():
                            self.packet_tree.delete(self.packet_tree.get_children()[0])
                    
                    # Insert into Treeview
                    item_id = self.packet_tree.insert(
                        "",
                        tk.END,
                        values=(
                            len(self.packet_tree.get_children()) + 1,
                            datetime.now().strftime("%H:%M:%S.%f")[:-3],
                            src,
                            dst,
                            display_proto,
                            length,
                            parsed_info["info"],
                            threat
                        )
                    )
                    
                    # Color code threats
                    if threat:
                        self.packet_tree.item(item_id, tags=("threat",))
                        self.packet_tree.tag_configure("threat", background="#2d0000", foreground="#ff6b6b")
                    
                    # Color code protocols
                    protocol_color_map = {
                        "TCP": "#3498db",
                        "UDP": "#9b59b6",
                        "ICMP": "#2ecc71",
                        "ARP": "#e67e22",
                        "DNS": "#f1c40f"
                    }
                    
                    if display_proto in protocol_color_map:
                        if not self.packet_tree.item(item_id, "tags"):
                            self.packet_tree.item(item_id, tags=(display_proto,))
                        self.packet_tree.tag_configure(display_proto, foreground=protocol_color_map[display_proto])
                    
                    packets_processed += 1
                    
                except Exception as e:
                    self.add_log(f"❌ Error processing packet: {str(e)}", "error")
            
            # Update status label if packets were processed
            if packets_processed > 0:
                total_packets = len(self.packet_tree.get_children())
                self.status_label.config(
                    text=f"Status: Capturing on {self.interface_var.get()} | "
                         f"Packets: {total_packets} | "
                         f"Last update: +{packets_processed} packets"
                )
        
        # Update statistics
        self.update_statistics()
        
        # Schedule next refresh
        self.root.after(100, self.update_packet_display)
    
    def parse_packet_for_display(self, packet):
        """Parse Scapy packet for display in UI (similar to original parse_packet)"""
        packet_info = {
            "protocol": "Other",
            "info": ""
        }
        
        # TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            packet_info["protocol"] = "TCP"
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            flags_str = ",".join(flags) if flags else ""
            packet_info["info"] = f"[{flags_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
        
        # UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            packet_info["protocol"] = "UDP"
            packet_info["info"] = f"Length: {udp.len}"
            
            # DNS
            if packet.haslayer(DNS):
                dns = packet[DNS]
                packet_info["protocol"] = "DNS"
                if dns.qd:  # DNS query
                    try:
                        qname = dns.qd.qname.decode('utf-8', errors='ignore')
                        packet_info["info"] = f"DNS Query: {qname}"
                    except:
                        packet_info["info"] = "DNS Query"
                elif dns.an:  # DNS answer
                    packet_info["info"] = f"DNS Response: {len(dns.an)} answers"
        
        # ICMP
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            packet_info["protocol"] = "ICMP"
            icmp_types = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                8: "Echo Request",
                11: "Time Exceeded"
            }
            type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
            packet_info["info"] = f"{type_name} Code={icmp.code}"
        
        # ARP
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            packet_info["protocol"] = "ARP"
            op_names = {1: "Request", 2: "Reply"}
            op_name = op_names.get(arp.op, f"Op {arp.op}")
            packet_info["info"] = f"ARP {op_name}"
        
        return packet_info
    
    def basic_threat_detection(self, packet):
        """Basic threat detection as fallback"""
        threat = ""
        
        # Large TCP packets
        if packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[IP].len > 4000:
                threat = "⚠️ Large TCP Packet"
            # SYN flood detection
            elif packet[TCP].flags == 0x02:  # Only SYN flag
                threat = "⚠️ SYN Flood"
        
        # ICMP flood detection
        elif packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Echo request
            threat = "⚠️ ICMP Flood"
        
        # ARP spoofing detection
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 1 and arp.psrc == arp.pdst:
                threat = "⚠️ ARP Spoofing"
        
        return threat
    
    def update_statistics(self):
        """Update packet statistics in the UI"""
        total_packets = len(self.packet_tree.get_children())
        
        stats_text = (
            f"📊 Statistics: "
            f"Packets: {total_packets} | "
            f"TCP: {self.protocol_counts['TCP']} | "
            f"UDP: {self.protocol_counts['UDP']} | "
            f"ICMP: {self.protocol_counts['ICMP']} | "
            f"ARP: {self.protocol_counts['ARP']} | "
            f"Other: {self.protocol_counts['Other']} | "
            f"🚨 Threats: {self.threat_count}"
        )
        
        self.stats_label.config(text=stats_text)
        
    def show_packet_details(self, event):
        """Show detailed packet info when double-clicked"""
        selected = self.packet_tree.selection()
        if selected:
            # Get the selected item index
            item_index = self.packet_tree.index(selected[0])
            
            # Map Treeview index to raw packets index
            if 0 <= item_index < len(self.raw_packets):
                raw_packet = self.raw_packets[item_index]
                
                # Get display values for reference
                display_values = self.packet_tree.item(selected[0], "values")
                packet_num = display_values[0]
                
                self.add_log(f"📖 Showing detailed information for Packet #{packet_num}")
                
                # Open packet details window using your existing function
                try:
                    show_packet_info(self.root, raw_packet)
                except Exception as e:
                    self.add_log(f"❌ Error showing packet details: {str(e)}", "error")
                    
    def show_context_menu(self, event):
        """Show right-click context menu"""
        # Identify the item under cursor
        item = self.packet_tree.identify_row(event.y)
        if item:
            # Select the item
            self.packet_tree.selection_set(item)
            
            # Create context menu
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="View Packet Details", 
                           command=lambda: self.show_packet_details(event))
            menu.add_command(label="Copy Source IP", 
                           command=lambda: self.copy_to_clipboard(self.packet_tree.item(item, "values")[2]))
            menu.add_command(label="Copy Destination IP", 
                           command=lambda: self.copy_to_clipboard(self.packet_tree.item(item, "values")[3]))
            menu.add_separator()
            menu.add_command(label="Mark as Threat", 
                           command=lambda: self.mark_as_threat(item))
            menu.add_command(label="Filter by Source", 
                           command=lambda: self.filter_by_source(self.packet_tree.item(item, "values")[2]))
            
            # Show the menu
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()
                
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.add_log(f"📋 Copied to clipboard: {text[:50]}...")
        
    def mark_as_threat(self, item):
        """Manually mark a packet as threat"""
        values = list(self.packet_tree.item(item, "values"))
        if not values[7]:  # If threat column is empty
            values[7] = "⚠️ Manual Mark"
            self.packet_tree.item(item, values=values)
            self.packet_tree.item(item, tags=("threat",))
            self.threat_count += 1
            self.add_log(f"🔴 Manually marked Packet #{values[0]} as threat", "warning")
            
    def filter_by_source(self, source_ip):
        """Filter packets by source IP"""
        self.add_log(f"🔍 Filtering packets from source: {source_ip}", "info")
        # This would be implemented as a filter function
        # For now, just log the action

# Main application
if __name__ == "__main__":
    root = tk.Tk()
    
    # Set application icon (optional)
    try:
        root.iconbitmap("icon.ico")  # Add your icon file if available
    except:
        pass
    
    app = IDS_UI(root)
    root.mainloop()