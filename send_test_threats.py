"""
Comprehensive Attack Test - Tests all 10 attack signatures
Sends HTTP requests through localhost HTTP server to trigger IDS detection
"""
import requests
import socket
import threading
import time

print("=" * 70)
print("🚨 COMPREHENSIVE IDS ATTACK TEST")
print("=" * 70)
print("\nMake sure:")
print("  1. IDS UI is running (python ids_UI.py)")
print("  2. HTTP server is running (python -m http.server 8000)")
print()

target = "http://192.168.1.8:8000"
time_delay = 1

attacks = [
    {
        "name": "SQL Injection",
        "url": "/?id=1' OR '1'='1",
        "description": "Database query manipulation attack"
    },
    {
        "name": "XSS Attack",
        "url": "/?q=<script>alert('xss')</script>",
        "description": "JavaScript injection in web form"
    },
    {
        "name": "DDoS - HTTP Flood",
        "url": "/?test=flood attack",
        "description": "Multiple rapid HTTP requests"
    },
    {
        "name": "Port Scan Detection",
        "url": "/?tool=nmap",
        "description": "Network scanning tool signature"
    },
    {
        "name": "ARP Spoofing",
        "url": "/?attack=arp spoof",
        "description": "ARP manipulation attack"
    },
    {
        "name": "DNS Tunneling",
        "url": "/?protocol=dns-over-http",
        "description": "DNS over HTTP tunnel"
    },
    {
        "name": "SMB Exploit",
        "url": "/?exploit=eternalblue",
        "description": "SMB vulnerability exploitation"
    },
    {
        "name": "FTP Brute Force",
        "url": "/?service=ftp auth fail",
        "description": "FTP authentication failure"
    },
    {
        "name": "SSH Attack",
        "url": "/?service=ssh fail",
        "description": "SSH authentication failure"
    },
    {
        "name": "Email Phishing",
        "url": "/?msg=verify your account",
        "description": "Phishing/social engineering"
    }
]

print("Testing all attack signatures:\n")

for i, attack in enumerate(attacks, 1):
    print(f"[{i}/10] {attack['name']}")
    print(f"       {attack['description']}")
    print(f"       Sending: {attack['url'][:60]}...")
    
    try:
        response = requests.get(f"{target}{attack['url']}", timeout=2)
        print(f"       ✓ Sent (Status: {response.status_code})")
    except Exception as e:
        print(f"       ✗ Error: {e}")
    
    time.sleep(time_delay)
    print()

print("=" * 100)
print("✅ ALL ATTACKS SENT!")
print("=" * 100)
print("\n📊 Check IDS UI for:")
print("   ✓ Red highlighted rows for each attack")
print("   ✓ Threat counter increased to 10+")
print("   ✓ Alert pop-ups appearing")
print("   ✓ Detection log showing all attacks")
print("\n🎯 Expected detections:")
for i, attack in enumerate(attacks, 1):
    print(f"   {i}. {attack['name']}")
print("\n" + "=" * 100)

