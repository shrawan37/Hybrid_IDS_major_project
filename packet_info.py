import tkinter as tk
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP

def show_packet_info(root, packet):
    """ Show detailed packet information in a new window """
    info_window = tk.Toplevel(root)
    info_window.title("Packet Information")

    # Create a scrollable frame for the information
    frame = tk.Frame(info_window)
    frame.pack(padx=10, pady=10)

    scroll = tk.Scrollbar(frame)
    scroll.pack(side=tk.RIGHT, fill=tk.Y)

    text = tk.Text(frame, wrap=tk.WORD, yscrollcommand=scroll.set, height=30, width=100)
    text.pack()

    scroll.config(command=text.yview)

    # Display packet details
    packet_info = f"Packet Info:\n{'='*60}\n"

    # Ethernet Layer (if available)
    if packet.haslayer(Ether):
        packet_info += f"Ethernet:\n"
        packet_info += f"  Source MAC: {packet[Ether].src}\n"
        packet_info += f"  Destination MAC: {packet[Ether].dst}\n"
        packet_info += f"  Type: {hex(packet[Ether].type)}\n\n"

    # IP Layer
    if packet.haslayer(IP):
        packet_info += f"IP:\n"
        packet_info += f"  Source IP: {packet[IP].src}\n"
        packet_info += f"  Destination IP: {packet[IP].dst}\n"
        packet_info += f"  Protocol: {packet[IP].proto}\n"
        packet_info += f"  TTL: {packet[IP].ttl}\n"
        packet_info += f"  Flags: {packet[IP].flags}\n\n"

    # TCP Layer
    if packet.haslayer(TCP):
        packet_info += f"TCP:\n"
        packet_info += f"  Source Port: {packet[TCP].sport}\n"
        packet_info += f"  Destination Port: {packet[TCP].dport}\n"
        packet_info += f"  Sequence Number: {packet[TCP].seq}\n"
        packet_info += f"  Acknowledgment Number: {packet[TCP].ack}\n"
        packet_info += f"  Flags: {packet[TCP].flags}\n\n"

    # UDP Layer
    elif packet.haslayer(UDP):
        packet_info += f"UDP:\n"
        packet_info += f"  Source Port: {packet[UDP].sport}\n"
        packet_info += f"  Destination Port: {packet[UDP].dport}\n"
        packet_info += f"  Length: {packet[UDP].len}\n\n"

    # ICMP Layer
    elif packet.haslayer(ICMP):
        packet_info += f"ICMP:\n"
        packet_info += f"  Type: {packet[ICMP].type}\n"
        packet_info += f"  Code: {packet[ICMP].code}\n"
        packet_info += f"  Checksum: {packet[ICMP].chksum}\n\n"

    # ARP Layer
    elif packet.haslayer(ARP):
        packet_info += f"ARP:\n"
        packet_info += f"  Operation: {packet[ARP].op}\n"
        packet_info += f"  Source MAC: {packet[ARP].hwsrc}\n"
        packet_info += f"  Destination MAC: {packet[ARP].hwdst}\n"
        packet_info += f"  Sender IP: {packet[ARP].psrc}\n"
        packet_info += f"  Target IP: {packet[ARP].pdst}\n\n"

    # Payload
    packet_info += f"Payload:\n{format_payload(extract_payload(packet))}\n"

    text.insert(tk.END, packet_info)
    text.config(state=tk.DISABLED)

def extract_payload(packet):
    """ Extracts payload safely from TCP or UDP packets """
    if packet.haslayer(TCP) and hasattr(packet[TCP].payload, "load"):
        return bytes(packet[TCP].payload.load)
    elif packet.haslayer(UDP) and hasattr(packet[UDP].payload, "load"):
        return bytes(packet[UDP].payload.load)
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
        hex_ascii_lines.append(f"{i:04x}  {hex_part:<48}  {ascii_part}")

    return "\n".join(hex_ascii_lines)
