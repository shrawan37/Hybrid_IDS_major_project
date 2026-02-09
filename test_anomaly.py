import time
import random
from scapy.all import IP, TCP, send
import sys

def send_anomaly_burst(target_ip="127.0.0.1", count=100):
    """
    Sends a burst of packets to trigger high 'count' and 'srv_count' anomalies.
    """
    print(f"🚀 Sending high-frequency burst to {target_ip} ({count} packets)...")
    payload = "A" * 10 
    for i in range(count):
        # Using 127.0.0.1 and a common port but at a very high rate
        pkt = IP(dst=target_ip)/TCP(dport=80)/payload
        send(pkt, verbose=False)
        if i % 20 == 0:
            print(f"  Sent {i} packets...")
    print("✅ Burst complete.")

def send_large_payload(target_ip="127.0.0.1"):
    """
    Sends packets with unusually large payloads to trigger 'src_bytes' anomaly.
    """
    print(f"🚀 Sending large payload packets to {target_ip}...")
    # Large payload (e.g., 2048 bytes of random data)
    payload = "".join([chr(random.randint(32, 126)) for _ in range(2000)])
    pkt = IP(dst=target_ip)/TCP(dport=443)/payload
    for _ in range(5):
        send(pkt, verbose=False)
    print("✅ Large payload packets sent.")

def main():
    print("="*60)
    print("      IDS ANOMALY DETECTION TESTER")
    print("="*60)
    print("This script generates traffic designed to trigger Anomaly Detection.")
    print("Note: Run this AS ADMINISTRATOR for Scapy to work correctly.\n")
    
    target = input("Enter target IP (default: 127.0.0.1): ") or "127.0.0.1"
    
    print("\n[1] TEST: High Frequency Burst (Anomaly: High Count)")
    print("[2] TEST: Large Data Transfer (Anomaly: High Bytes)")
    print("[3] TEST: Run Both")
    choice = input("\nSelect test (1/2/3): ")

    if choice in ['1', '3']:
        send_anomaly_burst(target)
        time.sleep(2)
    
    if choice in ['2', '3']:
        send_large_payload(target)

    print("\n" + "="*60)
    print("TESTING COMPLETE")
    print("Check your IDS UI for rows marked with '⚠ Anomaly Detected'.")
    print("="*60)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Automated run for testing
        send_anomaly_burst("127.0.0.1", count=50)
    else:
        main()
