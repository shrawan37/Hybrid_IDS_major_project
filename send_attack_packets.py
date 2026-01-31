#!/usr/bin/env python3
"""
Method 2: Send Real Network Attack Packets for IDS to Detect
This script sends actual Scapy packets with attack payloads
that the IDS UI will capture and analyze
"""

import sys
sys.path.append('src')
from scapy.all import IP, TCP, Raw, send, IFACE, get_if_list
import time
from datetime import datetime

def send_attack_packets():
    print("\n" + "="*70)
    print("SENDING REAL ATTACK PACKETS TO IDS")
    print("="*70 + "\n")
    
    # Get available interfaces
    interfaces = get_if_list()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  {i}: {iface}")
    
    print(f"\nUsing interface: {interfaces[0]}\n")
    
    # Attack payloads - realistic HTTP request format
    attacks = [
        ("SQL Injection", b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ("XSS Attack", b"GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ("Command Injection", b"GET /cmd?action=;cat /etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ("Path Traversal", b"GET /file?path=../../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        ("LDAP Injection", b"GET /ldap?filter=*) HTTP/1.1\r\nHost: localhost\r\n\r\n"),
    ]
    
    print("Sending attack payloads...")
    print("-" * 70 + "\n")
    
    sent_count = 0
    for i, (attack_name, payload) in enumerate(attacks, 1):
        try:
            # Create IP packet with TCP and Raw payload
            # src: localhost, dst: localhost (so it captures locally)
            pkt = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=54321+i, dport=80, flags="S")/Raw(load=payload)
            
            # Send packet
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending {i}: {attack_name}")
            print(f"         Payload: {payload[:50].decode('utf-8', errors='ignore')}...")
            
            send(pkt, iface=interfaces[0], verbose=0)
            sent_count += 1
            
            # Small delay between packets
            time.sleep(0.5)
            
        except Exception as e:
            print(f"         ❌ Error sending: {e}")
    
    print("\n" + "="*70)
    print(f"Sent {sent_count}/{len(attacks)} attack packets")
    print("="*70)
    print("\n✅ Check IDS window for alerts!")
    print("   Look for:")
    print("   - Red alert boxes")
    print("   - Threat counter increment")
    print("   - Attack type in logs")
    print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    try:
        send_attack_packets()
    except PermissionError:
        print("\n❌ ERROR: Need admin/root privileges to send packets")
        print("\nRun with admin privileges:")
        print("  Right-click PowerShell > Run as Administrator")
        print("  Then: python send_attack_packets.py")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
