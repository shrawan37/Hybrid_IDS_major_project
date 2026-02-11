<<<<<<< HEAD
import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def get_writable_path(filename):
    """Get a writable path for files (like databases) that need to be updated.
    If running as bundled exe, copies the template from _MEIPASS to the app directory if it doesn't exist.
    """
    if getattr(sys, 'frozen', False):
        # Running as bundled exe
        app_dir = os.path.dirname(sys.executable)
        target_path = os.path.join(app_dir, filename)
        
        # If the file doesn't exist in the app directory, copy it from the bundle
        if not os.path.exists(target_path):
            try:
                import shutil
                source_path = resource_path(filename)
                if os.path.exists(source_path):
                    shutil.copy2(source_path, target_path)
            except Exception as e:
                print(f"Error copying {filename} to writable location: {e}")
        return target_path
    
    # Running in development
    return os.path.abspath(filename)

print("Starting IDS UI...")
print(f"Current Directory: {os.getcwd()}")

# Add src directory to path to ensure imports work
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from packetcapture import PacketCapture
from packet_info import show_packet_info
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, IPv6
=======
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import tkinter as tk
from tkinter import ttk, messagebox
from packetcapture import PacketCapture
from packet_info import show_packet_info
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, IPv6, Raw
import scapy.packet
>>>>>>> main
import threading
import time
import requests
import ipaddress
<<<<<<< HEAD
from active_response import ActiveResponse
from notifications import NotificationSystem
from reporting import ReportGenerator
from traffic_logger import TrafficLogger
from db_manager import DatabaseManager
from auth_manager import AuthManager
=======
from collections import deque
from active_response import ActiveResponse
from notifications import NotificationSystem
from reporting import ReportGenerator
# from traffic_logger import TrafficLogger (Disabled as requested)

>>>>>>> main

class IDS_UI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚨 Intrusion Detection System (IDS)")
        self.root.geometry("1400x900")
        self.root.configure(bg="#0f0f1e")
        
<<<<<<< HEAD
        # Initialize database and auth manager
        self.db_manager = DatabaseManager(get_writable_path("users.db"))
        self.auth_manager = AuthManager(self.db_manager)
        self.current_user = None
        
        # Configure styles
        self.configure_styles()
        
        # Whitelist trusted/internal networks to reduce false positives
        self.whitelist_ranges = [
            "192.168.1.0/25", "10.0.0.0/8", "172.16.0.0/12",
            "140.82.112.0/24", "140.82.113.0/24", "13.64.0.0/11",
            "13.96.0.0/13", "13.104.0.0/14", "40.64.0.0/10",
            "40.128.0.0/9", "52.160.0.0/11", "20.0.0.0/8",
=======
        # Whitelist trusted/internal networks to reduce false positives
        self.whitelist_ranges = [
              # Private network
            # Private network (Home/Office)
            "10.0.0.0/8",        # Private network (Enterprise)
            "172.16.0.0/12",     # Private network
             "172.16.9.21/24", #private network
            "140.82.112.0/24",   # GitHub
            "140.82.113.0/24",   # GitHub
            "13.64.0.0/11",      # Azure
            "13.96.0.0/13",      # Azure
            "13.104.0.0/14",     # Azure
            "40.64.0.0/10",      # Azure
            "40.128.0.0/9",      # Azure
            "52.160.0.0/11",     # Azure
            "20.0.0.0/8",        # Azure
>>>>>>> main
        ]
        
        # Packet capture instance - delay initialization to prevent freeze
        self.capture = None
        self.capturing = False
        
<<<<<<< HEAD
        # Store packets
        self.packets_list = []
        self.raw_packets = []
        self.display_limit = 10000
=======
        # Store packets - Using deque with maxlen to prevent memory leaks
        self.display_limit = 1000 # Optimized for better Treeview performance
        self.packets_list = deque(maxlen=self.display_limit)
        self.raw_packets = deque(maxlen=self.display_limit)
        self.tree_item_ids = deque() # Track IDs for O(1) cleanup
>>>>>>> main
        
        # Protocol statistics
        self.protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        self.threat_count = 0
<<<<<<< HEAD
        self.total_packet_count = 0
=======
        self.total_packet_count = 0  # Global counter for S.N
>>>>>>> main
        
        # Alert debounce
        self.last_alert_time = 0
        self.alert_cooldown = 2
        
        # Worker thread for threat detection
<<<<<<< HEAD
        self.threat_queue = []
        self.threat_detection_thread = None
        self.stop_threat_worker = False
        
        self.ui_update_lock = threading.Lock()
        
        # New Modules
        self.active_response = ActiveResponse()
=======
        self.threat_queue = deque(maxlen=5000) # Use deque for O(1) pop(0)
        self.threat_detection_thread = None
        self.stop_threat_worker = False
        
        # Batch display updates
        self.pending_display_updates = []
        self.pending_threat_updates = deque(maxlen=3000) # Use deque for O(1) popleft, capped at 30x display limit
        self.ui_update_lock = threading.Lock()
        self.pkt_to_item = {} # Map packet number to treeview item_id for O(1) lookup
        self.displayed_count = 0 # Track items in treeview without calling get_children()
        
        # Log Batching
        self.log_queue = deque()
        self.root.after(100, self._process_log_queue)
        
        # New Modules
        self.active_response = ActiveResponse()
        # NOTE: Email config should ideally be from a settings file. Using placeholders.
>>>>>>> main
        self.notifications = NotificationSystem(
            sender_email="alerts@yourdomain.com", 
            sender_password="yourpassword", 
            admin_email="admin@yourdomain.com"
        )
        self.reporter = ReportGenerator()
<<<<<<< HEAD
        self.traffic_logger = TrafficLogger()
        self.auto_block_var = tk.BooleanVar(value=False)
        
        # Show login screen initially
        print("Calling show_login_screen...")
        self.show_login_screen()
        print("__init__ complete.")

    def configure_styles(self):
        """Configure application styles"""
        # Set color scheme
        self.bg_color = "#1a1a2e"
        self.secondary_bg = "#16213e"
        self.accent_color = "#0f3460"
        self.button_color = "#e94560"
        self.text_color = "#eee"
        self.input_bg = "#0f3460"
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Button style
        style.configure('Custom.TButton', background=self.button_color, foreground='white', borderwidth=0, focuscolor='none', font=('Segoe UI', 11, 'bold'), padding=10)
        style.map('Custom.TButton', background=[('active', '#d63447')])
        
        # Entry style
        style.configure('Custom.TEntry', fieldbackground=self.input_bg, foreground=self.text_color, borderwidth=2, relief='flat', font=('Segoe UI', 10))

    def clear_screen(self):
        """Clear all widgets from the screen"""
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        """Display the login screen"""
        print("Entering show_login_screen...")
        self.clear_screen()
        print("Screen cleared.")
        self.root.geometry("500x600")
        self.root.configure(bg=self.bg_color)
        
        container = tk.Frame(self.root, bg=self.bg_color)
        container.place(relx=0.5, rely=0.5, anchor='center')
        
        title = tk.Label(container, text="Welcome Back!", font=('Segoe UI', 28, 'bold'), bg=self.bg_color, fg=self.text_color)
        title.pack(pady=(0, 10))
        
        subtitle = tk.Label(container, text="Login to your account", font=('Segoe UI', 12), bg=self.bg_color, fg='#aaa')
        subtitle.pack(pady=(0, 30))
        
        tk.Label(container, text="Username", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.text_color).pack(anchor='w', pady=(0, 5))
        self.login_username = tk.Entry(container, font=('Segoe UI', 11), bg=self.input_bg, fg=self.text_color, insertbackground=self.text_color, relief='flat', width=30, bd=2)
        self.login_username.pack(pady=(0, 20), ipady=8)
        
        tk.Label(container, text="Password", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.text_color).pack(anchor='w', pady=(0, 5))
        self.login_password = tk.Entry(container, font=('Segoe UI', 11), bg=self.input_bg, fg=self.text_color, insertbackground=self.text_color, relief='flat', width=30, show='●', bd=2)
        self.login_password.pack(pady=(0, 30), ipady=8)
        
        login_btn = tk.Button(container, text="LOGIN", font=('Segoe UI', 12, 'bold'), bg=self.button_color, fg='white', relief='flat', cursor='hand2', command=self.handle_login, width=28, bd=0)
        login_btn.pack(pady=(0, 20), ipady=10)
        login_btn.bind('<Enter>', lambda e: login_btn.config(bg='#d63447'))
        login_btn.bind('<Leave>', lambda e: login_btn.config(bg=self.button_color))
        
        signup_frame = tk.Frame(container, bg=self.bg_color)
        signup_frame.pack()
        tk.Label(signup_frame, text="Don't have an account?", font=('Segoe UI', 10), bg=self.bg_color, fg='#aaa').pack(side='left', padx=(0, 5))
        signup_link = tk.Label(signup_frame, text="Sign Up", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.button_color, cursor='hand2')
        signup_link.pack(side='left')
        signup_link.bind('<Button-1>', lambda e: self.show_signup_screen())
        self.login_password.bind('<Return>', lambda e: self.handle_login())

    def show_signup_screen(self):
        """Display the signup screen"""
        self.clear_screen()
        container = tk.Frame(self.root, bg=self.bg_color)
        container.place(relx=0.5, rely=0.5, anchor='center')
        
        tk.Label(container, text="Create Account", font=('Segoe UI', 28, 'bold'), bg=self.bg_color, fg=self.text_color).pack(pady=(0, 10))
        tk.Label(container, text="Sign up to get started", font=('Segoe UI', 12), bg=self.bg_color, fg='#aaa').pack(pady=(0, 30))
        
        tk.Label(container, text="Username", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.text_color).pack(anchor='w', pady=(0, 5))
        self.signup_username = tk.Entry(container, font=('Segoe UI', 11), bg=self.input_bg, fg=self.text_color, insertbackground=self.text_color, relief='flat', width=30, bd=2)
        self.signup_username.pack(pady=(0, 15), ipady=8)
        
        tk.Label(container, text="Email (Optional)", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.text_color).pack(anchor='w', pady=(0, 5))
        self.signup_email = tk.Entry(container, font=('Segoe UI', 11), bg=self.input_bg, fg=self.text_color, insertbackground=self.text_color, relief='flat', width=30, bd=2)
        self.signup_email.pack(pady=(0, 15), ipady=8)
        
        tk.Label(container, text="Password", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.text_color).pack(anchor='w', pady=(0, 5))
        self.signup_password = tk.Entry(container, font=('Segoe UI', 11), bg=self.input_bg, fg=self.text_color, insertbackground=self.text_color, relief='flat', width=30, show='●', bd=2)
        self.signup_password.pack(pady=(0, 15), ipady=8)
        
        tk.Label(container, text="Confirm Password", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.text_color).pack(anchor='w', pady=(0, 5))
        self.signup_confirm = tk.Entry(container, font=('Segoe UI', 11), bg=self.input_bg, fg=self.text_color, insertbackground=self.text_color, relief='flat', width=30, show='●', bd=2)
        self.signup_confirm.pack(pady=(0, 30), ipady=8)
        
        signup_btn = tk.Button(container, text="SIGN UP", font=('Segoe UI', 12, 'bold'), bg=self.button_color, fg='white', relief='flat', cursor='hand2', command=self.handle_signup, width=28, bd=0)
        signup_btn.pack(pady=(0, 20), ipady=10)
        signup_btn.bind('<Enter>', lambda e: signup_btn.config(bg='#d63447'))
        signup_btn.bind('<Leave>', lambda e: signup_btn.config(bg=self.button_color))
        
        login_frame = tk.Frame(container, bg=self.bg_color)
        login_frame.pack()
        tk.Label(login_frame, text="Already have an account?", font=('Segoe UI', 10), bg=self.bg_color, fg='#aaa').pack(side='left', padx=(0, 5))
        login_link = tk.Label(login_frame, text="Login", font=('Segoe UI', 10, 'bold'), bg=self.bg_color, fg=self.button_color, cursor='hand2')
        login_link.pack(side='left')
        login_link.bind('<Button-1>', lambda e: self.show_login_screen())
        self.signup_confirm.bind('<Return>', lambda e: self.handle_signup())

    def handle_login(self):
        """Handle login success"""
        username = self.login_username.get().strip()
        password = self.login_password.get()
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        success, message = self.auth_manager.login_user(username, password)
        if success:
            self.current_user = username
            messagebox.showinfo("Success", f"{message}\n\nLaunching IDS Dashboard...")
            self.start_main_ids_ui()
        else:
            messagebox.showerror("Login Failed", message)

    def handle_signup(self):
        """Handle signup success"""
        username = self.signup_username.get().strip()
        password = self.signup_password.get()
        confirm = self.signup_confirm.get()
        email = self.signup_email.get().strip() or None
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return
        success, message = self.auth_manager.register_user(username, password, email)
        if success:
            messagebox.showinfo("Success", "Account created successfully!")
            self.show_login_screen()
        else:
            messagebox.showerror("Signup Failed", message)

    def start_main_ids_ui(self):
        """Transition from Login to Main IDS UI"""
        self.clear_screen()
        self.root.geometry("1400x900")
        self.root.configure(bg="#0f0f1e")
        
        # Initialize IDS Widgets
        self.create_widgets()
        
        # Initialize packet capture
        self.root.after(1000, self._init_packet_capture)
        
        # Start threat detection worker
        self.start_threat_detection_worker()
        
        # Start display loop
        self.update_packet_display()
=======
        # self.traffic_logger = TrafficLogger() (Disabled as requested)
        self.auto_block_var = tk.BooleanVar(value=False)
        
        # Create UI

        self.create_widgets()
        
        # Initialize packet capture after UI is loaded
        self.root.after(1000, self._init_packet_capture)
        
        # Start threat detection worker thread
        from alert_popup import show_alert
        self.show_alert_func = show_alert
        self.start_threat_detection_worker()

        # Auto-start if requested (for testing)
        import os
        if os.environ.get("IDS_AUTO_START") == "1":
            self.root.after(3000, self.start_capture)
>>>>>>> main

        
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
        
<<<<<<< HEAD
        # ===== MAIN CONTENT: Packet Table =====
        table_frame = tk.Frame(self.root, bg="#2d3436")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
=======
        # ===== MAIN CONTENT: Paned Window for List and Details =====
        self.main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self.main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # --- Top Pane: Packet Table ---
        table_frame = tk.Frame(self.main_pane, bg="#2d3436")
        self.main_pane.add(table_frame, weight=6)
>>>>>>> main
        
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
<<<<<<< HEAD
        col_widths = {"No.": 40, "Time": 100, "Source": 120, "Destination": 120, "Protocol": 60, "Length": 60, "Details": 250, "Threat": 150}
=======
        col_widths = {"No.": 40, "Time": 100, "Source": 120, "Destination": 120, "Protocol": 60, "Length": 60, "Details": 250, "Threat": 250}
>>>>>>> main
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
<<<<<<< HEAD
        self.packet_tree.bind("<Double-1>", self.show_packet_details)
        
        # ===== BOTTOM: Detection LOG =====
        log_frame = tk.Frame(self.root, bg="#1a1a2e", height=150)
=======
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_selected)
        self.packet_tree.bind("<Double-1>", self.show_packet_details)
        
        # --- Bottom Pane: Hierarchical Details ---
        details_frame = tk.Frame(self.main_pane, bg="#2d3436")
        self.main_pane.add(details_frame, weight=1)
        
        tk.Label(
            details_frame,
            text="🔍 Packet Dissection ",
            bg="#2d3436",
            fg="#00ff9d",
            font=("Arial", 11, "bold")
        ).pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        details_tree_frame = tk.Frame(details_frame, bg="#1e272e")
        details_tree_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.details_tree = ttk.Treeview(details_tree_frame, show="tree", style="Treeview")
        self.details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        d_v_scroll = ttk.Scrollbar(details_tree_frame, orient="vertical", command=self.details_tree.yview)
        d_v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.details_tree.configure(yscrollcommand=d_v_scroll.set)
        
        # ===== BOTTOM: Detection LOG =====
        log_frame = tk.Frame(self.root, bg="#1a1a2e", height=220)
>>>>>>> main
        log_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        log_frame.pack_propagate(False)
        
        tk.Label(log_frame, text="📋 Detection Log", bg="#1a1a2e", fg="#00ff9d", 
                font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(5, 0))
        
        log_text_frame = tk.Frame(log_frame, bg="#0d1117")
        log_text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
<<<<<<< HEAD
        self.log_text = tk.Text(log_text_frame, height=7, bg="#0d1117", fg="#8b949e",
=======
        self.log_text = tk.Text(log_text_frame, height=10, bg="#0d1117", fg="#8b949e",
>>>>>>> main
                               font=("Consolas", 9), wrap=tk.WORD, relief=tk.FLAT)
        log_scroll = tk.Scrollbar(log_text_frame, command=self.log_text.yview)
        self.log_text.config(yscrollcommand=log_scroll.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
<<<<<<< HEAD
=======
        # Configure tags ONCE to avoid UI lag
        self.packet_tree.tag_configure("threat", background="#ff3333", foreground="white")
        
        # Protocols coloring tags
        self.protocol_colors = {
            "TCP": {"bg": "#0d2f4d", "fg": "#00d4ff"},
            "UDP": {"bg": "#3d0d4d", "fg": "#ff00ff"},
            "ICMP": {"bg": "#0d4d1f", "fg": "#00ff00"},
            "ARP": {"bg": "#4d3d0d", "fg": "#ffaa00"},
            "DNS": {"bg": "#4d4d0d", "fg": "#ffff00"},
            "HTTP": {"bg": "#1a2a3a", "fg": "#66ccff"},
            "HTTPS": {"bg": "#1a3a2a", "fg": "#66ff99"},
            "SSH": {"bg": "#2a1a3a", "fg": "#cc66ff"},
            "HTTP": {"bg": "#1a2a3a", "fg": "#66ccff"},
            "HTTPS": {"bg": "#1a3a2a", "fg": "#66ff99"},
            "SSH": {"bg": "#2a1a3a", "fg": "#cc66ff"},
            "FTP": {"bg": "#3a2a1a", "fg": "#ffcc66"},
            "SMTP": {"bg": "#3a1a2a", "fg": "#ff6666"},
            "Other": {"bg": "#2a2a2a", "fg": "#cccccc"}
        }
        for proto, colors in self.protocol_colors.items():
            self.packet_tree.tag_configure(proto, foreground=colors["fg"], background=colors["bg"])

        # Pre-configure log tags to avoid UI lag
        self.log_colors = {
            "info": "#8b949e",
            "error": "#ff6b6b",
            "warning": "#ffcc00",
            "success": "#00ff9d",
            "threat": "#ff4757"
        }
        for msg_type, color in self.log_colors.items():
            self.log_text.tag_config(msg_type, foreground=color)

>>>>>>> main
        # Initial log
        self.add_log("✅ System initialized. Loading network interfaces...")
        
        # Start update loop
        self.update_packet_display()
    
    def _init_packet_capture(self):
<<<<<<< HEAD
        """Initialize packet capture after UI is loaded (prevents freeze)"""
        try:
            self.capture = PacketCapture(
                model_path=resource_path("models/isolation_forest.pkl"),
                scaler_path=resource_path("models/scaler.pkl"),
                encoder_path=resource_path("models/encoder.pkl")
            )
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
=======
        """Initialize packet capture in a background thread to prevent UI freeze during model loading."""
        self.add_log("⏳ Loading detection engines and models... Please wait.")
        self.interface_var.set("Loading engines...")
        self.status_label.config(text="Status: Loading engines...", fg="orange")
        self.start_btn.config(state=tk.DISABLED) # Disable until ready
        
        def _bg_init():
            try:
                # This call loads ML models which can be slow
                cap = PacketCapture()
                
                # Now get available interfaces
                interfaces = cap.get_available_interfaces()
                
                # Update UI in main thread
                self.root.after(0, lambda: self._finish_init(cap, interfaces))
                
            except Exception as e:
                self.root.after(0, lambda: self.add_log(f"⚠️ Packet capture init error: {str(e)}", "error"))
                self.root.after(0, lambda: self.interface_var.set("Error loading engines"))
                self.root.after(0, lambda: self.status_label.config(text="Status: Error loading engines", fg="red"))

        threading.Thread(target=_bg_init, daemon=True).start()

    def _finish_init(self, cap, interfaces):
        """Called on main thread after background initialization is complete."""
        self.capture = cap
        self.add_log("✅ Packet capture and ML engines ready")
        
        if interfaces:
            self.interface_combo.config(values=interfaces, state="readonly")
            self.interface_var.set(interfaces[0])
            self.add_log(f"✅ Found {len(interfaces)} network interface(s)")
            self.status_label.config(text="Status: Ready", fg="#ffcc00")
            self.start_btn.config(state=tk.NORMAL) # Re-enable button
        else:
            self.interface_combo.config(values=["No interfaces found"])
            self.interface_var.set("No interfaces found")
            self.add_log("⚠️ No network interfaces detected", "error")
            self.status_label.config(text="Status: No interfaces found", fg="red")
>>>>>>> main
        
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
            
<<<<<<< HEAD
            # Small delay to let the sniffer thread finish
            time.sleep(0.5)
            
            # Update UI state
=======
            # Non-blocking delay to let the sniffer thread finish
            self.root.after(500, self._finalize_stop)
            
        except Exception as e:
            self.add_log(f"❌ ERROR stopping capture: {str(e)}", "error")

    def _finalize_stop(self):
        """Update UI state after capture has fully stopped"""
        try:
>>>>>>> main
            self.start_btn.config(state=tk.NORMAL, bg="#00b894")
            self.stop_btn.config(state=tk.DISABLED, bg="#e74c3c")
            self.interface_combo.config(state="readonly")
            
<<<<<<< HEAD
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
=======
            # Use displayed_count instead of get_children() for speed
            packet_count = self.displayed_count
            self.status_label.config(text=f"Status: Stopped | Total Packets: {packet_count}", fg="#ffcc00")
            
            self.add_log(f"✅ Capture STOPPED. Total packets captured: {packet_count}")
        except Exception:
            pass
            
        
    def add_log(self, message, msg_type="info"):
        """Append message to log queue (Thread-safe for deques)"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_queue.append((timestamp, message, msg_type))

    def _process_log_queue(self):
        """Process log messages in batches to prevent UI freeze"""
        if self.log_queue:
            try:
                # Process larger batches but less often
                batch_limit = 50
                at_bottom = self.log_text.yview()[1] > 0.8
                
                for _ in range(batch_limit):
                    if not self.log_queue: break
                    ts, msg, mtype = self.log_queue.popleft()
                    
                    self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
                    curr_line = self.log_text.index("end-1c linestart")
                    self.log_text.tag_add(mtype, curr_line, "end-1c")
                    
                    # Periodic trimming
                    if self.displayed_count % 100 == 0:
                        count = int(self.log_text.index('end-1c').split('.')[0])
                        if count > 1000:
                            self.log_text.delete('1.0', '50.0')

                if at_bottom:
                    self.log_text.see(tk.END)
            except:
                pass
        
        # Check every 100ms
        self.root.after(100, self._process_log_queue)
>>>>>>> main



    def show_threat_alert(self, source_ip, threat_reason, dest_ip):
        """Show a non-blocking threat notification"""
        # Debounce alerts - don't show too many in quick succession
        current_time = time.time()
        if current_time - self.last_alert_time < self.alert_cooldown:
            return
        
        self.last_alert_time = current_time
        
<<<<<<< HEAD
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
=======
        # Log threat with timestamp
        threat_msg = f"🚨 THREAT DETECTED: {threat_reason} | Source: {source_ip} | Target: {dest_ip}"
        self.root.after(0, lambda: self.add_log(threat_msg, "threat"))
        
        # DISABLED: Blocking popups cause UI freeze during high traffic
        # alert_text = f"🚨 THREAT ALERT 🚨\n\nThreat: {threat_reason}\nSource: {source_ip}\nTarget: {dest_ip}"
        # self.root.after(0, lambda: messagebox.showwarning("🚨 THREAT ALERT 🚨", alert_text))
>>>>>>> main

    def start_threat_detection_worker(self):
        """Start a background worker thread for threat detection to avoid blocking the UI."""
        self.stop_threat_worker = False
        self.threat_detection_thread = threading.Thread(target=self._threat_detection_worker, daemon=True)
        self.threat_detection_thread.start()
    
    def _threat_detection_worker(self):
        """Background worker that processes threat detection without blocking the UI."""
        recent_threats = {}  # Track recent threats to reduce false positive alerts
<<<<<<< HEAD
        threat_cooldown = 5  # seconds between same threat from same IP
        
        print(f"DEBUG: Threat detection worker started for user {self.current_user}")
        while not self.stop_threat_worker:
            try:
                if self.threat_queue:
                    item = self.threat_queue.pop(0)
=======
        threat_cooldown = 10  # Increased cooldown to 10s to reduce alert spam
        
        while not self.stop_threat_worker:
            try:
                # Process threats in small batches to balance CPU and responsiveness
                processed = 0
                max_batch = 10
                
                while processed < max_batch:
                    try:
                        item = self.threat_queue.popleft()
                    except IndexError:
                        break # Queue empty
                        
>>>>>>> main
                    packet = item.get("packet")
                    src = item.get("src")
                    dst = item.get("dst")
                    pkt_num = item.get("pkt_num")
                    
<<<<<<< HEAD
                    # Log packet being processed every 50 packets to show activity
                    if pkt_num % 50 == 0:
                        print(f"DEBUG: Worker processing Packet #{pkt_num}. Queue depth: {len(self.threat_queue)}")
                    
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
                                print(f"[WORKER] 🔥 THREAT DETECTED on Packet #{pkt_num}: {threat}")
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
                        print(f"DEBUG: Worker Analysis Error on Packet #{pkt_num}: {e}")
                        import traceback
                        traceback.print_exc()
                        pass
                    
                    # Update the treeview with threat info if found
                    if threat:
                        print(f"DEBUG: Triggering UI Update for Packet #{pkt_num} - {threat}")
                        self.root.after(0, lambda t=threat, pn=pkt_num: self._update_threat_display(pn, t))
                
                time.sleep(0.001)  # Process threats quickly
            except Exception as e:
                print(f"DEBUG: Worker Main Loop Error: {e}")
                time.sleep(1)
=======
                    try:
                        # Extract features and analyze
                        if self.capture and self.capture.feature_extractor:
                            feat_dict = self.capture.feature_extractor.extract_packet_features(packet)
                            if self.capture.hybrid_engine:
                                result = self.capture.hybrid_engine.analyze(packet, feat_dict)
                                if result.get("malicious"):
                                    reasons = result.get("reasons", [])
                                    threat_text = ", ".join(reasons)
                                    alert_src = src
                                    if IP in packet: alert_src = packet[IP].src
                                    elif IPv6 in packet: alert_src = packet[IPv6].src

                                    threat = f"⚠ {threat_text}"
                                    if "Suspicious" in threat_text:
                                        threat = "⚠ Suspicious Behaviour"

                                    with self.ui_update_lock:
                                        # Queue for UI row coloring
                                        self.pending_threat_updates.append((pkt_num, threat))
                                        
                                        # DEBOUNCE the Logs and Popups to prevent UI freezing during floods
                                        threat_key = f"{alert_src}:{threat_text[:20]}"
                                        now = time.time()
                                        if threat_key not in recent_threats or (now - recent_threats[threat_key] > threat_cooldown):
                                            recent_threats[threat_key] = now
                                            self.threat_count += 1
                                            
                                            # Directly append to log queue (thread-safe)
                                            self.add_log(f"🚨 THREAT: {threat_text} from {alert_src}", "threat")
                                            
                                            # Show Popup - throttle popups significantly
                                            if ("Signature" in threat_text or "Injection" in threat_text) and len(tk._default_root.winfo_children()) < 10:
                                                threat_data = [{"attack": threat_text, "src": alert_src, "dst": dst}]
                                                self.root.after(0, lambda d=threat_data, p=packet: self.show_alert_func(d, p))

                        processed += 1
                    except Exception as e:
                        processed += 1
                
                # Manual cleanup removed - maxlen handled by deque
                
                if processed == 0:
                    time.sleep(0.2) # Idle longer when no work
                else:
                    time.sleep(0.02) # Yield to other threads
            except Exception:
                time.sleep(0.1)
>>>>>>> main


    def _update_threat_display(self, pkt_num, threat):
        """Update treeview with threat info (called from main thread via after)"""
        try:
<<<<<<< HEAD
            children = self.packet_tree.get_children()
            for item in children:
                values = list(self.packet_tree.item(item, "values"))
                if str(values[0]) == str(pkt_num):  # Match packet number (string comparison)
                    new_values = list(values)
                    new_values[7] = threat 
                    self.packet_tree.item(item, values=new_values)
                    # Red background for threat with bright red text
                    self.packet_tree.item(item, tags=("threat",))
                    self.packet_tree.tag_configure("threat", background="#4d0000", foreground="#ff4444")
                    print(f"DEBUG: Found and updated UI for Packet #{pkt_num} with threat: {threat}")
                    break
        except:
=======
            item_id = self.pkt_to_item.get(pkt_num)
            if item_id and self.packet_tree.exists(item_id):
                # Update threat column (index 7)
                self.packet_tree.set(item_id, "Threat", threat)
                # Red background for threat - tag is already configured
                self.packet_tree.item(item_id, tags=("threat",))
        except Exception as e:
>>>>>>> main
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
<<<<<<< HEAD
            batch_limit = 50  # Process max 50 packets per update cycle
            
            while not self.capture.packet_queue.empty() and packets_processed < batch_limit:
                try:
                    pkt_info = self.capture.packet_queue.get()
                    if self.total_packet_count % 10 == 0:
                         print(f"DEBUG: Processed {self.total_packet_count} packets so far...")
=======
            batch_limit = 100  # Larger batch to process queue faster
            
            while not self.capture.packet_queue.empty() and packets_processed < batch_limit:
                try:
                    pkt_info = self.capture.packet_queue.get_nowait()
>>>>>>> main
                    
                    # Extract parsed fields
                    src = pkt_info.get("src", "Unknown")
                    dst = pkt_info.get("dst", "Unknown")
                    proto = pkt_info.get("proto", "Other")
                    length = pkt_info.get("length", 0)
<<<<<<< HEAD
                    info = pkt_info.get("info", "")  # Get info field
=======
                    info = pkt_info.get("info", "") 
>>>>>>> main
                    packet = pkt_info.get("packet")
                    
                    # Store raw packet for details view
                    self.raw_packets.append(packet)
                    
<<<<<<< HEAD
                    # Parse additional info for display
                    parsed_info = self.parse_packet_for_display(packet)
                    display_proto = parsed_info["protocol"]
                    
                    # Update protocol statistics
                    with self.ui_update_lock:
                        if display_proto in self.protocol_counts:
                            self.protocol_counts[display_proto] += 1
=======
                    # Update protocol statistics
                    with self.ui_update_lock:
                        if proto in self.protocol_counts:
                            self.protocol_counts[proto] += 1
>>>>>>> main
                        else:
                            self.protocol_counts["Other"] += 1
                        self.total_packet_count += 1
                    
<<<<<<< HEAD
                    # Queue packet for threat detection (non-blocking)
=======
                    # Queue packet for threat detection
>>>>>>> main
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
<<<<<<< HEAD
                        "proto": display_proto,
                        "length": length,
                        "info": parsed_info["info"] # Use parsed info
=======
                        "proto": proto,
                        "length": length,
                        "info": info
>>>>>>> main
                    })
                    
                    packets_processed += 1
                    
<<<<<<< HEAD
                except Exception as e:
                    self.add_log(f"❌ Error processing packet: {str(e)}", "error")
            
            # Batch insert all items into Treeview (much faster)
            for item in batch_items:
                try:
=======
                except Exception:
                    break
            
            # Batch insert all items into Treeview
            for item in batch_items:
                try:
                    proto = item["proto"]
                    tag = proto if proto in self.protocol_colors else "Other"
                    
>>>>>>> main
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
<<<<<<< HEAD
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
    
=======
                            item["info"],
                            ""  # Threat placeholder
                        ),
                        tags=(tag,) # Crucial: Pass tags during insertion!
                    )
                    
                    self.pkt_to_item[item["num"]] = item_id
                    self.tree_item_ids.append((item["num"], item_id))
                    self.displayed_count += 1
                        
                except Exception:
                    pass
            
            # Now update pending threats
            updates_to_run = []
            with self.ui_update_lock:
                while self.pending_threat_updates and len(updates_to_run) < 50:
                    pn, threat = self.pending_threat_updates.popleft()
                    if pn in self.pkt_to_item:
                        updates_to_run.append((self.pkt_to_item[pn], threat))
            
            # Execute UI updates OUTSIDE the lock to keep background thread moving
            for item_id, threat in updates_to_run:
                try:
                    if self.packet_tree.exists(item_id):
                        self.packet_tree.set(item_id, "Threat", threat)
                        self.packet_tree.item(item_id, tags=("threat",))
                except Exception:
                    continue
            
            # Cleanup Treeview if limit reached (OPTIMIZED: Batch deletion)
            if self.displayed_count > self.display_limit:
                try:
                    # Cleanup oldest items to amortize cost
                    to_remove = self.displayed_count - self.display_limit + 50
                    ids_to_delete = []
                    
                    for _ in range(to_remove):
                        if self.tree_item_ids:
                            pn, tid = self.tree_item_ids.popleft()
                            ids_to_delete.append(tid)
                            if pn in self.pkt_to_item:
                                del self.pkt_to_item[pn]
                            self.displayed_count -= 1
                        else:
                            break
                    
                    if ids_to_delete:
                        # Batch delete for significantly better performance
                        valid_ids = [tid for tid in ids_to_delete if self.packet_tree.exists(tid)]
                        if valid_ids:
                            self.packet_tree.delete(*valid_ids)
                            
                except Exception as e:
                    pass
                
                # raw_packets is a deque with maxlen, so it cleans itself automatically.
                # No manual slicing needed.
            
            # Update status label
            if packets_processed > 0:
                self.status_label.config(
                    text=f"Status: Capturing on {self.interface_var.get()} | "
                         f"Packets: {self.displayed_count} | "
                         f"Queue: {len(self.threat_queue)} threats pending"
                )
        
        # Update statistics (now uses optimized displayed_count)
        self.update_statistics()
        
        # Reschedule next update with longer gap to avoid UI saturation
        self.root.after(400, self.update_packet_display)
    
    def clear_packets(self):
        """Clears all displayed packets, logs, and resets related counters/data."""
        # Clear treeview using batch deletion
        children = self.packet_tree.get_children()
        if children:
            self.packet_tree.delete(*children)
        
        # Clear dissection view
        self.details_tree.delete(*self.details_tree.get_children())
        
        # Clear detection log text widget
        self.log_text.delete('1.0', tk.END)
        
        # Clear internal data structures
        self.raw_packets.clear()
        self.pkt_to_item.clear()
        self.pending_threat_updates.clear()
        self.threat_queue.clear()
        self.log_queue.clear()
        
        # Reset counters
        self.total_packet_count = 0
        self.displayed_count = 0
        self.threat_count = 0
        self.protocol_counts = {
            "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0
        }
        
        # Update UI elements
        self.update_statistics()
        self.status_label.config(
            text=f"Status: Capturing on {self.interface_var.get()} | "
                 f"Packets: 0 | "
                 f"Queue: 0 threats pending"
        )
        self.add_log("✅ All logs and packets cleared successfully.", "success")

>>>>>>> main
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
<<<<<<< HEAD
        """Update packet statistics in the UI"""
        total_packets = len(self.packet_tree.get_children())
        
        stats_text = (
            f"📊 Statistics: "
            f"Packets: {total_packets} | "
=======
        """Update packet statistics in the UI - Optimized to avoid Treeview.get_children()"""
        stats_text = (
            f"📊 Statistics: "
            f"Packets: {self.displayed_count} | "
>>>>>>> main
            f"TCP: {self.protocol_counts['TCP']} | "
            f"UDP: {self.protocol_counts['UDP']} | "
            f"ICMP: {self.protocol_counts['ICMP']} | "
            f"ARP: {self.protocol_counts['ARP']} | "
            f"Other: {self.protocol_counts['Other']} | "
            f"🚨 Threats: {self.threat_count}"
        )
        
        self.stats_label.config(text=stats_text)
        
<<<<<<< HEAD
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
=======
    def on_packet_selected(self, event):
        """Update the hierarchical details pane when a packet is selected"""
        selected = self.packet_tree.selection()
        if not selected:
            return
            
        item_id = selected[0]
        try:
            # Extract packet number from the first column
            packet_num_str = self.packet_tree.item(item_id, "values")[0]
            packet_num = int(packet_num_str)
            
            # Find the packet in raw_packets (which is now a deque)
            # Find it by index if we can, but since deques and treeview insertions
            # might shift, it's safer to use the num if we stored it correctly.
            # For simplicity in this demo, we assume the index matches the deque position
            # (which it might not if deques rotate). 
            # A better way is to store the packet in a dict or with the item_id.
            
            # Find packet by number (linear search in deque is fine for 1000 items)
            target_pkt = None
            # The raw_packets contains the actual scapy packets
            # We need to find the one matching this number
            # For now, let's try to get it from the index relative to the treeview
            index = self.packet_tree.index(item_id)
            if index < len(self.raw_packets):
                target_pkt = self.raw_packets[index]
            
            if target_pkt:
                self.dissect_packet(target_pkt)
        except Exception as e:
            pass

    def dissect_packet(self, pkt):
        """Fill the details tree with scapy packet layers"""
        self.details_tree.delete(*self.details_tree.get_children())
        
        try:
            # Recurse through layers
            layer = pkt
            while layer:
                layer_name = layer.name
                if hasattr(layer, 'overload_fields') and layer.overload_fields:
                    layer_name += " (Overloaded)"
                
                # Add layer root
                parent = self.details_tree.insert("", "end", text=layer_name, open=True)
                
                # Add fields
                for f in layer.fields_desc:
                    if f.name in layer.fields:
                        val = layer.getfieldval(f.name)
                        # Format value
                        repr_val = layer.get_field(f.name).i2repr(layer, val)
                        self.details_tree.insert(parent, "end", text=f"{f.name}: {repr_val}")
                
                layer = layer.payload
                if not layer or isinstance(layer, scapy.packet.NoPayload):
                    break
                if isinstance(layer, Raw):
                    # Show raw payload as hex/ascii
                    payload_node = self.details_tree.insert("", "end", text="Raw Data", open=False)
                    raw_bytes = layer.load
                    # Format as hex dump
                    from packet_info import format_payload
                    dump = format_payload(raw_bytes)
                    for line in dump.split('\n'):
                        self.details_tree.insert(payload_node, "end", text=line)
                    break
        except Exception as e:
            self.details_tree.insert("", "end", text=f"Dissection Error: {str(e)}")

    def show_packet_details(self, event):
        """Show detailed packet info in a separate window when double-clicked"""
        selected = self.packet_tree.selection()
        if selected:
            index = self.packet_tree.index(selected[0])
            if 0 <= index < len(self.raw_packets):
                raw_packet = self.raw_packets[index]
                show_packet_info(self.root, raw_packet)
>>>>>>> main
                    
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
<<<<<<< HEAD
    try:
        print("Main block started...")
        root = tk.Tk()
        print("Tkinter root created.")
        
        # Set application icon (optional)
        try:
            root.iconbitmap("icon.ico")
            print("Icon set.")
        except:
            print("Icon skip/fail.")
            pass
        
        print("Initializing IDS_UI...")
        app = IDS_UI(root)
        print("IDS_UI initialized. Entering mainloop...")
        root.mainloop()
        print("Mainloop exited.")
    except Exception as e:
        import traceback
        error_msg = f"CRITICAL ERROR:\n{str(e)}\n\n{traceback.format_exc()}"
        print(error_msg)
        # Use a secondary hidden root if the primary one failed or was destroyed
        try:
            temp_root = tk.Tk()
            temp_root.withdraw()
            messagebox.showerror("Unified IDS - Critical Error", error_msg)
            temp_root.destroy()
        except:
            # Fallback if even Tkinter is broken
            with open("crash_log.txt", "w") as f:
                f.write(error_msg)
        
        # Keep console open if launched via command line
        print("\n" + "="*50)
        print("Application has crashed. See error above.")
        print("="*50)
        input("Press Enter to close...")
=======
    root = tk.Tk()
    
    # Set application icon (optional)
    try:
        root.iconbitmap("icon.ico")  # Add your icon file if available
    except:
        pass
    
    app = IDS_UI(root)
    root.mainloop()
>>>>>>> main
