import tkinter as tk
from tkinter import ttk, messagebox
from packetcapture import PacketCapture
from packet_info import show_packet_info
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS
import threading
import time
import requests

class IDS_UI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚨 Intrusion Detection System (IDS)")
        self.root.geometry("1400x900")
        self.root.configure(bg="#0f0f1e")
        
        # Packet capture instance
        self.capture = PacketCapture()
        self.capturing = False
        
        # Store packets
        self.packets_list = []
        self.raw_packets = []
        self.display_limit = 100
        
        # Protocol statistics
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        self.threat_count = 0
        self.total_packet_count = 0  # Global counter for S.N
        
        # Alert debounce
        self.last_alert_time = 0
        self.alert_cooldown = 2
        
        # Create UI
        self.create_widgets()
        
    def create_widgets(self):
        """Create simplified UI with better layout"""
        
        # ===== TOP CONTROL BAR =====
        top_frame = tk.Frame(self.root, bg="#1a1a2e", height=100)
        top_frame.pack(fill=tk.X, padx=10, pady=10)
        top_frame.pack_propagate(False)
        
        # Title
        title = tk.Label(
            top_frame,
            text="🚨 Intrusion Detection System - Real-time Network Monitor",
            font=("Arial", 14, "bold"),
            bg="#1a1a2e",
            fg="#00ff9d"
        )
        title.pack(pady=(5, 10))
        
        # Controls Row 1: Interface Selection
        control_row1 = tk.Frame(top_frame, bg="#1a1a2e")
        control_row1.pack(fill=tk.X, padx=10)
        
        tk.Label(control_row1, text="📡 Select Interface:", bg="#1a1a2e", fg="white", 
                font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        # Get interfaces
        try:
            interfaces = self.capture.get_available_interfaces()
        except Exception as e:
            interfaces = []
            messagebox.showerror("Error", f"Failed to get interfaces: {e}")
        
        if not interfaces:
            interfaces = ["No interfaces found"]
        
        self.interface_var = tk.StringVar(value=interfaces[0] if interfaces else "")
        
        # Interface dropdown - SIMPLIFIED
        self.interface_combo = ttk.Combobox(
            control_row1,
            textvariable=self.interface_var,
            values=interfaces,
            state="readonly",
            width=40,
            font=("Arial", 10)
        )
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        # Controls Row 2: Buttons
        control_row2 = tk.Frame(top_frame, bg="#1a1a2e")
        control_row2.pack(fill=tk.X, padx=10, pady=(5, 0))
        
        self.start_btn = tk.Button(
            control_row2,
            text="▶ START",
            command=self.start_capture,
            bg="#00b894",
            fg="white",
            font=("Arial", 10, "bold"),
            width=12,
            cursor="hand2"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(
            control_row2,
            text="⏹ STOP",
            command=self.stop_capture,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 10, "bold"),
            width=12,
            state=tk.DISABLED,
            cursor="hand2"
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        clear_btn = tk.Button(
            control_row2,
            text="🗑 CLEAR",
            command=self.clear_packets,
            bg="#3498db",
            fg="white",
            font=("Arial", 10),
            width=12,
            cursor="hand2"
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Label(control_row2, text="", bg="#1a1a2e").pack(side=tk.LEFT, expand=True)
        
        # Status label
        self.status_label = tk.Label(
            control_row2,
            text="Status: Ready",
            bg="#1a1a2e",
            fg="#ffcc00",
            font=("Arial", 10, "bold")
        )
        self.status_label.pack(side=tk.RIGHT, padx=10)
        
        # ===== STATISTICS BAR =====
        stats_frame = tk.Frame(self.root, bg="#0f3460", height=50)
        stats_frame.pack(fill=tk.X)
        stats_frame.pack_propagate(False)
        
        self.stats_label = tk.Label(
            stats_frame,
            text="📊 Packets: 0 | TCP: 0 | UDP: 0 | ICMP: 0 | ARP: 0 | Other: 0 | 🚨 Threats: 0",
            bg="#0f3460",
            fg="white",
            font=("Consolas", 10, "bold")
        )
        self.stats_label.pack(pady=8)
        
        # ===== MAIN CONTENT: Packet Table =====
        table_frame = tk.Frame(self.root, bg="#2d3436")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        tk.Label(
            table_frame,
            text="📋 Live Packet Capture",
            bg="#2d3436",
            fg="#00ff9d",
            font=("Arial", 11, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        # Treeview for packets
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Threat")
        
        style = ttk.Style()
        style.configure("Treeview", background="#1e272e", foreground="white", 
                       fieldbackground="#1e272e", font=("Consolas", 9))
        style.configure("Treeview.Heading", background="#2d3436", foreground="#00ff9d", 
                       font=("Consolas", 9, "bold"))
        
        tree_frame = tk.Frame(table_frame, bg="#1e272e")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.packet_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15, style="Treeview")
        
        # Configure columns
        col_widths = {"No.": 40, "Time": 100, "Source": 150, "Destination": 150, "Protocol": 70, "Length": 70, "Threat": 150}
        for col, width in col_widths.items():
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=width, anchor="w" if col != "Length" else "center")
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.packet_tree.yview)
        h_scroll = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Grid layout
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.packet_tree.bind("<Double-1>", self.show_packet_details)
        
        # ===== BOTTOM: Detection LOG =====
        log_frame = tk.Frame(self.root, bg="#1a1a2e", height=150)
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        log_frame.pack_propagate(False)
        
        tk.Label(log_frame, text="📋 Detection Log", bg="#1a1a2e", fg="#00ff9d", 
                font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        log_text_frame = tk.Frame(log_frame, bg="#0d1117")
        log_text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = tk.Text(log_text_frame, height=7, bg="#0d1117", fg="#8b949e",
                               font=("Consolas", 9), wrap=tk.WORD, relief=tk.FLAT)
        log_scroll = tk.Scrollbar(log_text_frame, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=log_scroll.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Initial log
        self.add_log("✅ System initialized. Select interface and click START")
        self.add_log(f"✅ Found {len(interfaces)} network interface(s)")
        
        # Start update loop
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
        self.total_packet_count = 0  # Reset counter
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        self.threat_count = 0
        self.add_log("✅ Packet list cleared")
        
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

    def show_threat_alert(self, source_ip, threat_reason, dest_ip):
        """Show a pop-up alert when threat is detected (non-blocking)"""
        # Debounce alerts - don't show too many in quick succession
        current_time = time.time()
        if current_time - self.last_alert_time < self.alert_cooldown:
            return
        
        self.last_alert_time = current_time
        
        # Show alert in a separate thread so it doesn't block the UI
        def show_alert():
            alert_message = f"""🚨 THREAT DETECTED! 🚨

Attack Type: {threat_reason}
Source IP:  {source_ip}
Target IP:  {dest_ip}
Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

⚠️ Take action if this is suspicious!"""
            
            try:
                messagebox.showwarning("🚨 THREAT ALERT 🚨", alert_message)
            except Exception as e:
                print(f"Alert error: {e}")
        
        # Run in separate thread to avoid blocking
        alert_thread = threading.Thread(target=show_alert, daemon=True)
        alert_thread.start()

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
                            # Show alert pop-up
                            self.show_threat_alert(src, threat, dst)
                    except Exception as e:
                        # Fallback to basic threat detection
                        threat = self.basic_threat_detection(packet)
                        if threat:
                            self.threat_count += 1
                            self.add_log(f"🚨 BASIC THREAT: {threat} from {src}", "threat")
                            # Show alert pop-up
                            self.show_threat_alert(src, threat, dst)
                    
                    # Increment global packet counter
                    self.total_packet_count += 1
                    
                    # Keep only last N packets
                    if len(self.raw_packets) > self.display_limit:
                        self.raw_packets.pop(0)
                        # Remove from Treeview
                        if self.packet_tree.get_children():
                            self.packet_tree.delete(self.packet_tree.get_children()[0])
                    
                    # Insert into Treeview (7 columns: No., Time, Source, Destination, Protocol, Length, Threat)
                    item_id = self.packet_tree.insert(
                        "",
                        tk.END,
                        values=(
                            self.total_packet_count,
                            datetime.now().strftime("%H:%M:%S.%f")[:-3],
                            src,
                            dst,
                            display_proto,
                            length,
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

requests.get("http://127.0.0.1:8000/?id=1' OR '1'='1")
print("✓ SQL Injection sent")