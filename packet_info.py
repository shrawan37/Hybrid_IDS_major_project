import tkinter as tk
from tkinter import ttk
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP

def show_packet_info(root, packet):
    """ Show detailed packet information in a new stylized window """
    info_window = tk.Toplevel(root)
    info_window.title(f"Detailed Packet Analysis")
    info_window.geometry("850x600")
    info_window.configure(bg="#1a1a2e")

    # Styling for the Toplevel
    style = ttk.Style()
    style.configure("Packet.TFrame", background="#1a1a2e")

    # Main Container
    main_frame = tk.Frame(info_window, bg="#1a1a2e")
    main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

    # Title Label
    title_label = tk.Label(
        main_frame, 
        text="🔍 DEEP PACKET INSPECTION", 
        font=("Arial", 12, "bold"), 
        bg="#1a1a2e", 
        fg="#00ff9d"
    )
    title_label.pack(anchor=tk.W, pady=(0, 10))

    # Text Widget with Scrollbar
    text_frame = tk.Frame(main_frame, bg="#0d1117", bd=1, relief=tk.SOLID)
    text_frame.pack(fill=tk.BOTH, expand=True)

    scroll = tk.Scrollbar(text_frame, bg="#1a1a2e", activebackground="#00ff9d")
    scroll.pack(side=tk.RIGHT, fill=tk.Y)

    text = tk.Text(
        text_frame, 
        wrap=tk.WORD, 
        yscrollcommand=scroll.set, 
        bg="#0d1117", 
        fg="#8b949e",
        insertbackground="white",
        font=("Consolas", 10),
        padx=10,
        pady=10,
        relief=tk.FLAT
    )
    text.pack(fill=tk.BOTH, expand=True)
    scroll.config(command=text.yview)

    # Configure Tags for Styling
    text.tag_configure("header", foreground="#00ff9d", font=("Consolas", 11, "bold"))
    text.tag_configure("field", foreground="#00d4ff")
    text.tag_configure("value", foreground="#ffffff")
    text.tag_configure("divider", foreground="#34495e")

    def add_section(header, fields):
        text.insert(tk.END, f"┌── {header} " + "─"*(40-len(header)) + "\n", "header")
        for label, val in fields:
            text.insert(tk.END, f"│ ", "divider")
            text.insert(tk.END, f"{label:<20}: ", "field")
            text.insert(tk.END, f"{val}\n", "value")
        text.insert(tk.END, "└" + "─"*50 + "\n\n", "divider")

    # 1. Ethernet Layer
    if packet.haslayer(Ether):
        eth_fields = [
            ("Source MAC", packet[Ether].src),
            ("Destination MAC", packet[Ether].dst),
            ("Type", hex(packet[Ether].type))
        ]
        add_section("ETHERNET LAYER", eth_fields)

    # 2. IP Layer
    if packet.haslayer(IP):
        ip_fields = [
            ("Version", packet[IP].version),
            ("Source IP", packet[IP].src),
            ("Destination IP", packet[IP].dst),
            ("Protocol", f"{packet[IP].proto} ({packet.sprintf('%IP.proto%')})"),
            ("TTL", packet[IP].ttl),
            ("Flags", packet[IP].flags),
            ("Size", f"{packet[IP].len} bytes")
        ]
        add_section("INTERNET PROTOCOL (IPv4)", ip_fields)

    # 3. Transport Layer
    if packet.haslayer(TCP):
        tcp_fields = [
            ("Source Port", packet[TCP].sport),
            ("Destination Port", packet[TCP].dport),
            ("Seq Number", packet[TCP].seq),
            ("Ack Number", packet[TCP].ack),
            ("Flags", packet[TCP].flags),
            ("Window", packet[TCP].window)
        ]
        add_section("TRANSMISSION CONTROL PROTOCOL (TCP)", tcp_fields)
    elif packet.haslayer(UDP):
        udp_fields = [
            ("Source Port", packet[UDP].sport),
            ("Destination Port", packet[UDP].dport),
            ("Length", packet[UDP].len)
        ]
        add_section("USER DATAGRAM PROTOCOL (UDP)", udp_fields)
    elif packet.haslayer(ICMP):
        icmp_fields = [
            ("Type", f"{packet[ICMP].type} ({packet.sprintf('%ICMP.type%')})"),
            ("Code", packet[ICMP].code),
            ("Checksum", hex(packet[ICMP].chksum))
        ]
        add_section("ICMP (CONTROL MESSAGE)", icmp_fields)

    # 4. ARP Layer
    if packet.haslayer(ARP):
        arp_fields = [
            ("Operation", "Who-has (Request)" if packet[ARP].op == 1 else "Is-at (Reply)"),
            ("Sender MAC", packet[ARP].hwsrc),
            ("Sender IP", packet[ARP].psrc),
            ("Target MAC", packet[ARP].hwdst),
            ("Target IP", packet[ARP].pdst)
        ]
        add_section("ADDRESS RESOLUTION PROTOCOL (ARP)", arp_fields)

    # 5. Payload
    payload = extract_payload(packet)
    if payload:
        text.insert(tk.END, f"┌── DATA PAYLOAD " + "─"*30 + "\n", "header")
        formatted_data = format_payload(payload)
        text.insert(tk.END, formatted_data, "value")
        text.insert(tk.END, "\n└" + "─"*50 + "\n", "divider")
    else:
        text.insert(tk.END, "--- No Payload Data ---\n", "divider")

    text.config(state=tk.DISABLED)

    # Footer
    footer = tk.Label(main_frame, text="© Hybrid IDS Analysis Engine", bg="#1a1a2e", fg="#34495e", font=("Arial", 8))
    footer.pack(side=tk.BOTTOM, pady=5)

def extract_payload(packet):
    """ Extracts payload safely from packets """
    for layer in [TCP, UDP]:
        if packet.haslayer(layer) and hasattr(packet[layer].payload, "load"):
            return bytes(packet[layer].payload.load)
    return b""

def format_payload(raw_payload):
    """ Convert payload to Wireshark-style Hex + ASCII format """
    if not raw_payload:  
        return "No Payload"

    hex_ascii_lines = []
    for i in range(0, len(raw_payload), 16):
        chunk = raw_payload[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        hex_ascii_lines.append(f"  {i:04x}  {hex_part:<48}  {ascii_part}")

    return "\n".join(hex_ascii_lines)
