import tkinter as tk
from tkinter import ttk, messagebox
from packetcapture import PacketCapture
from packet_info import show_packet_info
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, IPv6
import threading
import time
import requests
import ipaddress
from active_response import ActiveResponse
from notifications import NotificationSystem
from reporting import ReportGenerator
from traffic_logger import TrafficLogger


class IDS_UI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚨 Intrusion Detection System (IDS)")
        self.root.geometry("1400x900")
        self.root.configure(bg="#0f0f1e")
        
        # Whitelist trusted/internal networks to reduce false positives
        self.whitelist_ranges = [
              # Private network
            "192.168.1.0/25",# Private network (Home/Office)
            "10.0.0.0/8",        # Private network (Enterprise)
            "172.16.0.0/12",     # Private network
             # Localhost
            "140.82.112.0/24",   # GitHub
            "140.82.113.0/24",   # GitHub
            "13.64.0.0/11",      # Azure
            "13.96.0.0/13",      # Azure
            "13.104.0.0/14",     # Azure
            "40.64.0.0/10",      # Azure
            "40.128.0.0/9",      # Azure
            "52.160.0.0/11",     # Azure
            "20.0.0.0/8",        # Azure
        ]
        
        # Packet capture instance - delay initialization to prevent freeze
        self.capture = None
        self.capturing = False
        
        # Store packets
        self.packets_list = []
        self.raw_packets = []
        self.display_limit = 10000  # Keep up to 10,000 packets (removes very old ones if memory is needed)
        
        # Protocol statistics
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        self.threat_count = 0
        self.total_packet_count = 0  # Global counter for S.N
        
        # Alert debounce
        self.last_alert_time = 0
        self.alert_cooldown = 2
        
        # Worker thread for threat detection
        self.threat_queue = []
        self.threat_detection_thread = None
        self.stop_threat_worker = False
        
        # Batch display updates
        self.pending_display_updates = []
        self.ui_update_lock = threading.Lock()
        
        # New Modules
        self.active_response = ActiveResponse()
        # NOTE: Email config should ideally be from a settings file. Using placeholders.
        self.notifications = NotificationSystem(
            sender_email="alerts@yourdomain.com", 
            sender_password="yourpassword", 
            admin_email="admin@yourdomain.com"
        )
        self.reporter = ReportGenerator()
        self.traffic_logger = TrafficLogger()
        self.auto_block_var = tk.BooleanVar(value=False)
        
        # Create UI

        self.create_widgets()
        
        # Initialize packet capture after UI is loaded
        self.root.after(1000, self._init_packet_capture)
        
        # Start threat detection worker thread
        self.start_threat_detection_worker()

        # Auto-start if requested (for testing)
        import os
        if os.environ.get("IDS_AUTO_START") == "1":
            self.root.after(3000, self.start_capture)

        
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
        
        # Get interfaces - will be populated after capture is initialized
        self.interface_var = tk.StringVar(value="Loading interfaces...")
        
        # Interface dropdown - SIMPLIFIED
        self.interface_combo = ttk.Combobox(
            control_row1,
            textvariable=self.interface_var,
            values=["Loading interfaces..."],
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
        
        # New Controls
        tk.Checkbutton(control_row2, text="Auto-Block IPs", variable=self.auto_block_var, 
                      bg="#1a1a2e", fg="white", selectcolor="#1a1a2e", activebackground="#1a1a2e", activeforeground="white"
                      ).pack(side=tk.LEFT, padx=10)
        
        report_btn = tk.Button(
            control_row2,
            text="📄 REPORT",
            command=self.generate_report,
            bg="#9b59b6",
            fg="white",
            font=("Arial", 10),
            width=10,
            cursor="hand2"
        )
        report_btn.pack(side=tk.LEFT, padx=5)

        
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
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Details", "Threat")
        
        style = ttk.Style()
        style.configure("Treeview", background="#1e272e", foreground="white", 
                       fieldbackground="#1e272e", font=("Consolas", 9))
        style.configure("Treeview.Heading", background="#2d3436", foreground="#00ff9d", 
                       font=("Consolas", 9, "bold"))
        
        tree_frame = tk.Frame(table_frame, bg="#1e272e")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.packet_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15, style="Treeview")
        
        # Configure columns
        col_widths = {"No.": 40, "Time": 100, "Source": 120, "Destination": 120, "Protocol": 60, "Length": 60, "Details": 250, "Threat": 150}
        for col, width in col_widths.items():
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=width, anchor="w" if col != "Length" and col != "No." else "center")
        
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
        self.add_log("✅ System initialized. Loading network interfaces...")
        
        # Start update loop
        self.update_packet_display()
    
    def _init_packet_capture(self):
        """Initialize packet capture after UI is loaded (prevents freeze)"""
        try:
            self.capture = PacketCapture()
            self.add_log("✅ Packet capture ready")
            
            # Now get available interfaces
            try:
                interfaces = self.capture.get_available_interfaces()
                if interfaces:
                    self.interface_combo.config(values=interfaces, state="readonly")
                    self.interface_var.set(interfaces[0])
                    self.add_log(f"✅ Found {len(interfaces)} network interface(s)")
                else:
                    self.interface_combo.config(values=["No interfaces found"])
                    self.add_log("⚠️ No network interfaces detected", "error")
            except Exception as e:
                self.add_log(f"⚠️ Error getting interfaces: {str(e)}", "error")
                self.interface_combo.config(values=["Error loading interfaces"])
                
        except Exception as e:
            self.add_log(f"⚠️ Packet capture initialization error: {str(e)}", "error")
            self.add_log("ℹ️ Continuing without packet capture. You can still send test attacks.", "info")
            self.capture = None
            self.interface_combo.config(values=["Error - See log"])
        
    def start_capture(self):
        """Start packet capture"""
        if self.capture is None:
            self.add_log("❌ ERROR: Packet capture not initialized", "error")
            return
            
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
            self.add_log("⏹ Stopping capture...", "info")
            self.capture.stop()
            self.capturing = False
            
            # Small delay to let the sniffer thread finish
            time.sleep(0.5)
            
            # Update UI state
            self.start_btn.config(state=tk.NORMAL, bg="#00b894")
            self.stop_btn.config(state=tk.DISABLED, bg="#e74c3c")
            self.interface_combo.config(state="readonly")
            
            packet_count = len(self.packet_tree.get_children())
            self.status_label.config(text=f"Status: Stopped | Total Packets: {packet_count}", fg="#ffcc00")
            
            self.add_log(f"✅ Capture STOPPED. Total packets captured: {packet_count}")
            
        except Exception as e:
            self.add_log(f"❌ ERROR stopping capture: {str(e)}", "error")
            
    def clear_packets(self):
        """Clear all packets from display"""
        # Clear treeview
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Clear stored packets
        self.raw_packets.clear()
        self.total_packet_count = 0  # Reset counter
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0, 'HTTP': 0, 'HTTPS': 0, 'SSH': 0, 'FTP': 0, 'SMTP': 0, 'POP3': 0, 'IMAP': 0}
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
        try:
            print(f"[{timestamp}] {msg_type.upper()}: {message}".encode('ascii', 'ignore').decode())
        except:
            pass



    def show_threat_alert(self, source_ip, threat_reason, dest_ip):
        """Show a non-blocking threat notification"""
        # Debounce alerts - don't show too many in quick succession
        current_time = time.time()
        if current_time - self.last_alert_time < self.alert_cooldown:
            return
        
        self.last_alert_time = current_time
        
        # Show in log and display popup alert
        def show_notification():
            try:
                # Log threat with timestamp
                threat_msg = f"🚨 THREAT DETECTED: {threat_reason} | Source: {source_ip} | Target: {dest_ip}"
                self.root.after(0, lambda: self.add_log(threat_msg, "threat"))
                
                # Show popup alert - this will display a visible warning box
                alert_text = f"🚨 THREAT ALERT 🚨\n\nThreat: {threat_reason}\nSource: {source_ip}\nTarget: {dest_ip}"
                self.root.after(0, lambda: messagebox.showwarning("🚨 THREAT ALERT 🚨", alert_text))
                
            except Exception as e:
                print(f"Alert error: {e}")
        
        # Run in separate thread to avoid blocking UI
        alert_thread = threading.Thread(target=show_notification, daemon=True)
        alert_thread.start()

    def start_threat_detection_worker(self):
        """Start a background worker thread for threat detection to avoid blocking the UI."""
        self.stop_threat_worker = False
        self.threat_detection_thread = threading.Thread(target=self._threat_detection_worker, daemon=True)
        self.threat_detection_thread.start()
    
    def _threat_detection_worker(self):
        """Background worker that processes threat detection without blocking the UI."""
        recent_threats = {}  # Track recent threats to reduce false positive alerts
        threat_cooldown = 5  # seconds between same threat from same IP
        
        while not self.stop_threat_worker:
            try:
                # Process threat queue items slowly to avoid CPU spike
                if self.threat_queue:
                    item = self.threat_queue.pop(0)
                    packet = item.get("packet")
                    src = item.get("src")
                    dst = item.get("dst")
                    pkt_num = item.get("pkt_num")
                    
                    threat = ""
                    try:
                        # Heavy computation: Extract features for anomaly engine
                        if self.capture and self.capture.feature_extractor:
                            feat_dict = self.capture.feature_extractor.extract_packet_features(packet)
                        else:
                            feat_dict = {}
                        
                        # Run hybrid analysis
                        if self.capture and self.capture.hybrid_engine:
                            result = self.capture.hybrid_engine.analyze(packet, feat_dict)
                            if result.get("malicious"):
                                threat = "⚠ " + ", ".join(result.get("reasons", []))
                                with self.ui_update_lock:
                                    self.threat_count += 1
                                    
                                    # Use IP address for alert if possible, fallback to MAC
                                    alert_src = src
                                    if packet.haslayer(IP):
                                        alert_src = packet[IP].src
                                    elif packet.haslayer(IPv6):
                                        alert_src = packet[IPv6].src

                                    # Check if this is a duplicate alert (spam prevention)
                                    threat_key = f"{alert_src}:{threat[:30]}"
                                    current_time = time.time()
                                    should_alert = True
                                    
                                    if threat_key in recent_threats:
                                        if current_time - recent_threats[threat_key] < threat_cooldown:
                                            should_alert = False  # Skip duplicate alert
                                    
                                    recent_threats[threat_key] = current_time
                                    
                                    if should_alert:
                                        # Log and Show Alert
                                        self.root.after(0, lambda: self.add_log(f"🚨 THREAT: {threat} from {alert_src}", "threat"))
                                        self.root.after(0, lambda: self.show_threat_alert(alert_src, threat, dst))

                                        
                                        # Active Response (Auto-Block)
                                        if self.auto_block_var.get():
                                            success, msg = self.active_response.block_ip(src)
                                            self.root.after(0, lambda m=msg: self.add_log(f"🛡️ {m}", "warning" if "already" in m else "success"))
                                        
                                        # Notification
                                        # Only warn for high severity (signature based usually)
                                        if "reasons" in result and "signature" in result["reasons"]:
                                            self.notifications.send_alert(f"High Severity Threat: {threat}", f"Source: {src}\nTarget: {dst}\nThreat: {threat}")

                            # Log Normal Traffic for Training
                            else:
                                self.traffic_logger.log_traffic(feat_dict, is_malicious=False)

                    except Exception as e:
                        pass
                    
                    # Update the treeview with threat info if found
                    if threat and pkt_num is not None:
                        self.root.after(0, lambda t=threat, pn=pkt_num: self._update_threat_display(pn, t))
                
                time.sleep(0.001)  # Process threats quickly
            except Exception as e:
                pass


    def _update_threat_display(self, pkt_num, threat):
        """Update treeview with threat info (called from main thread via after)"""
        try:
            children = self.packet_tree.get_children()
            for item in children:
                values = list(self.packet_tree.item(item, "values"))
                if values[0] == pkt_num:  # Match packet number
                    # Update threat column (index 7 now, was 6)
                    # values = (No, Time, Src, Dst, Proto, Len, Details, Threat)
                    new_values = list(values)
                    new_values[7] = threat 
                    self.packet_tree.item(item, values=new_values)
                    # Red background for threat with bright red text
                    self.packet_tree.item(item, tags=("threat",))
                    self.packet_tree.tag_configure("threat", background="#4d0000", foreground="#ff4444")
                    break
        except:
            pass

    def update_packet_display(self):
        """Periodically update the packet display by consuming from packet_queue"""
        # Check if capture stopped unexpectedly
        if self.capturing and self.capture and not self.capture.running:
            self.add_log("⚠️ WARNING: Packet capture stopped unexpectedly!", "warning")
            self.capturing = False
            self.start_btn.config(state=tk.NORMAL, bg="#00b894")
            self.stop_btn.config(state=tk.DISABLED, bg="#e74c3c")
            self.interface_combo.config(state="readonly")
            return
        
        if self.capturing and self.capture.running:
            packets_processed = 0
            batch_items = []
            
            # Process available packets from queue (limit batch size to prevent lag)
            batch_limit = 50  # Process max 50 packets per update cycle
            
            while not self.capture.packet_queue.empty() and packets_processed < batch_limit:
                try:
                    pkt_info = self.capture.packet_queue.get()
                    
                    # Extract parsed fields
                    src = pkt_info.get("src", "Unknown")
                    dst = pkt_info.get("dst", "Unknown")
                    proto = pkt_info.get("proto", "Other")
                    length = pkt_info.get("length", 0)
                    info = pkt_info.get("info", "")  # Get info field
                    packet = pkt_info.get("packet")
                    
                    # Store raw packet for details view
                    self.raw_packets.append(packet)
                    
                    # Parse additional info for display
                    parsed_info = self.parse_packet_for_display(packet)
                    display_proto = parsed_info["protocol"]
                    
                    # Update protocol statistics
                    with self.ui_update_lock:
                        if display_proto in self.protocol_counts:
                            self.protocol_counts[display_proto] += 1
                        else:
                            self.protocol_counts["Other"] += 1
                        self.total_packet_count += 1
                    
                    # Queue packet for threat detection (non-blocking)
                    self.threat_queue.append({
                        "packet": packet,
                        "src": src,
                        "dst": dst,
                        "pkt_num": self.total_packet_count
                    })
                    
                    # Store display info to batch insert
                    batch_items.append({
                        "num": self.total_packet_count,
                        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                        "src": src,
                        "dst": dst,
                        "proto": display_proto,
                        "length": length,
                        "info": parsed_info["info"] # Use parsed info
                    })
                    
                    packets_processed += 1
                    
                except Exception as e:
                    self.add_log(f"❌ Error processing packet: {str(e)}", "error")
            
            # Batch insert all items into Treeview (much faster)
            for item in batch_items:
                try:
                    item_id = self.packet_tree.insert(
                        "",
                        tk.END,
                        values=(
                            item["num"],
                            item["time"],
                            item["src"],
                            item["dst"],
                            item["proto"],
                            item["length"],
                            item["info"],  # Insert info into Details column
                            ""  # Threat will be filled later by worker
                        )
                    )
                    
                    # Color code protocols - with background and foreground colors
                    protocol_color_map = {
                        "TCP": {"bg": "#0d2f4d", "fg": "#00d4ff"},      # Blue
                        "UDP": {"bg": "#3d0d4d", "fg": "#ff00ff"},       # Magenta
                        "ICMP": {"bg": "#0d4d1f", "fg": "#00ff00"},      # Green
                        "ARP": {"bg": "#4d3d0d", "fg": "#ffaa00"},       # Orange
                        "DNS": {"bg": "#4d4d0d", "fg": "#ffff00"},       # Yellow
                        "HTTP": {"bg": "#1a2a3a", "fg": "#66ccff"},      # Light Blue
                        "HTTPS": {"bg": "#1a3a2a", "fg": "#66ff99"},     # Light Green
                        "SSH": {"bg": "#2a1a3a", "fg": "#cc66ff"},       # Light Purple
                        "FTP": {"bg": "#3a2a1a", "fg": "#ffcc66"},       # Light Orange
                        "SMTP": {"bg": "#3a1a2a", "fg": "#ff6666"},      # Light Red
                        "POP3": {"bg": "#3a2a1a", "fg": "#ffaa88"},      # Light Orange-Red
                        "IMAP": {"bg": "#1a3a3a", "fg": "#88ffcc"},      # Light Cyan
                        "Other": {"bg": "#2a2a2a", "fg": "#cccccc"}      # Gray
                    }
                    
                    proto = item["proto"]
                    if proto in protocol_color_map:
                        colors = protocol_color_map[proto]
                        self.packet_tree.item(item_id, tags=(proto,))
                        self.packet_tree.tag_configure(proto, foreground=colors["fg"], background=colors["bg"])
                    else:
                        # Default for unknown protocols
                        self.packet_tree.item(item_id, tags=("Other",))
                        self.packet_tree.tag_configure("Other", foreground="#cccccc", background="#2a2a2a")
                        
                except Exception as e:
                    pass
            
            # Keep all packets but remove oldest if limit is reached (memory optimization)
            children = self.packet_tree.get_children()
            if len(children) > self.display_limit:
                # Only remove oldest if we exceed the limit
                excess = len(children) - self.display_limit
                for i in range(excess):
                    self.packet_tree.delete(children[i])
                if len(self.raw_packets) > self.display_limit:
                    self.raw_packets = self.raw_packets[-self.display_limit:]
            
            # Update status label if packets were processed
            if packets_processed > 0:
                total_packets = len(self.packet_tree.get_children())
                self.status_label.config(
                    text=f"Status: Capturing on {self.interface_var.get()} | "
                         f"Packets: {total_packets} | "
                         f"Queue: {len(self.threat_queue)} threats pending"
                )
        
        # Update statistics less frequently (every 200ms instead of 100ms)
        self.update_statistics()
        
        # Schedule next refresh at 200ms instead of 100ms to reduce UI load
        self.root.after(200, self.update_packet_display)
    
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
    
    def is_whitelisted(self, ip):
        """Check if IP is in whitelist"""
        try:
            ip_addr = ipaddress.ip_address(ip)
            for range_str in self.whitelist_ranges:
                net = ipaddress.ip_network(range_str, strict=False)
                if ip_addr in net:
                    return True
        except:
            pass
        return False
    
    def basic_threat_detection(self, packet):
        """Basic threat detection as fallback - only for non-whitelisted sources"""
        threat = ""
        
        # Get source IP
        src_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src

        if src_ip and self.is_whitelisted(src_ip):
            return ""
        
        # Large TCP packets
        if packet.haslayer(TCP):
            if packet.haslayer(IP) and packet[IP].len > 4000:
                threat = "⚠️ Large TCP Packet"
            # SYN flood detection
            elif packet[TCP].flags == 0x02:  # Only SYN flag
                threat = "⚠️ SYN Flood"

        
        # ICMP flood detection - DISABLED for home networks
        # (Single ICMP echo requests are normal for ping/network diagnostics)
        # Uncomment below only for enterprise monitoring where ICMP is blocked
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
            menu.add_command(label="⛔ Block Source IP", 
                           command=lambda: self.manual_block_ip(self.packet_tree.item(item, "values")[2]))

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
                
    def manual_block_ip(self, ip):
        """Manually block an IP from context menu"""
        if messagebox.askyesno("Confirm Block", f"Are you sure you want to block IP: {ip}?"):
            success, msg = self.active_response.block_ip(ip)
            self.add_log(f"🛡️ {msg}", "success" if success else "error")

    def generate_report(self):
        """Generate PDF report"""
        self.add_log("📄 Generating session report...")
        # Gather stats
        # Create a simple threat log from treeview items tagged as threat
        threat_log = []
        for item in self.packet_tree.get_children():
            values = self.packet_tree.item(item, "values")
            if self.packet_tree.item(item, "tags") and "threat" in self.packet_tree.item(item, "tags"):
                 threat_log.append({"time": values[1], "src": values[2], "threat": values[6]})
        
        success, msg = self.reporter.generate_report(self.protocol_counts, threat_log)
        if success:
             self.add_log(f"✅ Report created: {msg}", "success")
             try:
                 os.startfile(msg) # Open the PDF
             except:
                 pass
        else:
             self.add_log(f"❌ Report failed: {msg}", "error")

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