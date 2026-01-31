import sys
import os
import threading
import time
import random
from datetime import datetime
from scapy.all import IP, TCP, UDP, send, conf

# Ensure src/ is on the path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from signature import SignatureEngine

def get_random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def simulate_real_traffic(interface=None):
    print(f"\n[INFO] Starting Real Network Verification Traffic Generator")
    if interface:
        print(f"[INFO] Target Interface: {interface}")
        conf.iface = interface
    
    print("-" * 60)
    print("This script generates BOTH normal and attack traffic to test:")
    print("1. Packet Capture (Normal traffic)")
    print("2. Signature Detection (Attack traffic)")
    print("3. Anomaly Detection (High volume traffic)")
    print("-" * 60)
    
    try:
        # Load signatures to know what to simulate
        sig_engine = SignatureEngine()
        print(f"[INFO] Loaded {len(sig_engine.signatures)} attack signatures for testing.\n")
        
        count = 0
        whitelisted_src = "192.168.1.50" # Simulate internal
        external_src = "203.0.113.10"   # Simulate external attacker
        
        while True:
            # 1. Send Normal Traffic (80% chance)
            if random.random() < 0.8:
                pkt = IP(src=whitelisted_src, dst="192.168.1.1")/TCP(sport=12345, dport=80)/"Normal HTTP request"
                send(pkt, verbose=False)
                sys.stdout.write(".")
            
            # 2. Send Attack Traffic (20% chance)
            else:
                attack_type = random.choice(list(sig_engine.signatures.keys()))
                payload = "TEST_PAYLOAD"
                
                # Pick a representative payload based on type (simplified)
                if "SQL" in attack_type:
                    payload = "admin' OR '1'='1"
                elif "XSS" in attack_type:
                    payload = "<script>alert('test')</script>"
                elif "Command" in attack_type:
                    payload = "; cat /etc/passwd"
                
                pkt = IP(src=external_src, dst="192.168.1.100")/TCP(dport=80)/payload
                send(pkt, verbose=False)
                sys.stdout.write("!")
            
            sys.stdout.flush()
            count += 1
            time.sleep(0.5) # Send 2 packets per second
            
            if count % 20 == 0:
                print(f"  [Sent {count} packets]")
                
    except KeyboardInterrupt:
        print("\n[INFO] Traffic generation stopped.")

if __name__ == "__main__":
    simulate_real_traffic()
