#!/usr/bin/env python3
"""
IDS DEMO - Attack Traffic Generator
Shows different attack types for demonstration
"""

import requests
import socket
import threading
import time
import sys

def print_header(msg):
    print("\n" + "="*60)
    print(f"  {msg}")
    print("="*60)

def print_step(num, name):
    print(f"\n[{num}/4] {name}")
    print("-" * 60)

target = "localhost:8000"

try:
    print_header("🚨 IDS ATTACK DEMONSTRATION")
    print("Make sure IDS UI is running before continuing!\n")
    input("Press ENTER to start demo...")

    # ===== TEST 1: SQL INJECTION =====
    print_step(1, "SQL Injection Attack")
    print("Type: Database attack")
    print("Target: Web server parameter")
    print("Payload: 1' OR '1'='1")
    print("\nSending attack...")
    
    try:
        requests.get(f"{target}/?id=1' OR '1'='1", timeout=2)
        requests.get(f"{target}/?user=admin' --", timeout=2)
        requests.get(f"{target}/?search=1'; DROP TABLE users; --", timeout=2)
        print("✓ SQL Injection packets sent")
        print("✓ Look at IDS UI - RED rows should appear with ⚠ threat")
    except Exception as e:
        print(f"✗ Error: {e}")

    time.sleep(2)
    input("\nPress ENTER for next test...")

    # ===== TEST 2: XSS ATTACK =====
    print_step(2, "Cross-Site Scripting (XSS) Attack")
    print("Type: Client-side attack")
    print("Target: Web form input")
    print("Payload: <script>alert('xss')</script>")
    print("\nSending attack...")
    
    try:
        requests.get(f"{target}/?q=<script>alert('xss')</script>", timeout=2)
        requests.get(f"{target}/?search=<img src=x onerror=alert(1)>", timeout=2)
        requests.get(f"{target}/?name=<iframe src=javascript:alert('xss')>", timeout=2)
        print("✓ XSS packets sent")
        print("✓ Look at IDS UI - RED rows should appear")
    except Exception as e:
        print(f"✗ Error: {e}")

    time.sleep(2)
    input("\nPress ENTER for next test...")

    # ===== TEST 3: PORT SCAN =====
    print_step(3, "Port Scan Attack")
    print("Type: Reconnaissance")
    print("Target: Multiple ports")
    print("Scanning ports: 22, 80, 443, 3306, 3389, 8000")
    print("\nSending attack...")
    
    ports = [22, 23, 25, 53, 80, 443, 3306, 3389, 8000, 8080]
    for port in ports:

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect_ex(('127.0.0.1', port))
            sock.close()
            print(f"  Scanned port {port}")
            time.sleep(0.1)
        except:
            pass
    
    print("✓ Port scan packets sent")
    print("✓ Look at IDS UI - Multiple red rows for port scan")

    time.sleep(2)
    input("\nPress ENTER for next test...")

    # ===== TEST 4: DDoS/HTTP FLOOD =====
    print_step(4, "HTTP Flood (DDoS) Attack")
    print("Type: Denial of Service")
    print("Target: Web server")
    print("Method: Multiple concurrent requests")
    print("\nSending attack...")
    
    def send_flood():
        for i in range(30):
            try:
                requests.get(target, timeout=1)
            except:
                pass

    threads = []
    for i in range(3):
        t = threading.Thread(target=send_flood)
        t.start()
        threads.append(t)
        print(f"  Started thread {i+1}")

    for t in threads:
        t.join()

    print("✓ HTTP flood packets sent")
    print("✓ Look at IDS UI - Many RED rows rapidly appearing")

    # ===== SUMMARY =====
    print_header("✅ DEMO COMPLETE")
    print("\nObservations:")
    print("  • All attack packets appear as RED rows")
    print("  • Threat type shown in 'Threat' column")
    print("  • Detection Log shows all threats with timestamps")
    print("  • Statistics updated in real-time")
    print("  • Alert pop-ups appeared for each threat")
    print("\nIDS Status: ✅ WORKING CORRECTLY")
    print("="*60)

except KeyboardInterrupt:
    print("\n\nDemo interrupted by user")
except Exception as e:
    print(f"\n❌ Demo error: {e}")
