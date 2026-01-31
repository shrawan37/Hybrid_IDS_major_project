#!/usr/bin/env python3
"""
Automated Attack Generator for IDS Verification
"""

import requests
import socket
import threading
import time
import sys

target = "http://localhost:8000"

def send_sql_injection():
    print("Sending SQL Injection...")
    try:
        requests.get(f"{target}/?id=1' OR '1'='1", timeout=1)
        requests.get(f"{target}/?user=admin' --", timeout=1)
    except: pass

def send_xss():
    print("Sending XSS...")
    try:
        requests.get(f"{target}/?q=<script>alert('xss')</script>", timeout=1)
        requests.get(f"{target}/?search=<img src=x onerror=alert(1)>", timeout=1)
    except: pass

def send_path_traversal():
    print("Sending Path Traversal...")
    try:
        requests.get(f"{target}/../../../../etc/passwd", timeout=1)
    except: pass

def port_scan():
    print("Starting Port Scan...")
    ports = [22, 80, 443, 3306, 8080]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex(('127.0.0.1', port))
            sock.close()
        except: pass

def main():
    print("🚀 Starting Automated Attack Sequence...")
    
    # 1. SQLi
    send_sql_injection()
    time.sleep(1)
    
    # 2. XSS
    send_xss()
    time.sleep(1)
    
    # 3. Path Traversal
    send_path_traversal()
    time.sleep(1)
    
    # 4. Port Scan
    port_scan()
    time.sleep(1)
    
    print("✅ Attack Sequence Complete.")

if __name__ == "__main__":
    main()
