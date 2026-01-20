import json
import re
import threading
import time
from queue import Queue
from scapy.all import sniff, IP, TCP, UDP, Raw

print("🌐 Live Signature Detection Test")
print("=" * 60)

# Load signatures from JSON
with open("models/signatures.json", "r") as f:
    signatures = json.load(f)

# Queue for captured packets
packet_queue = Queue()

def packet_handler(pkt):
    """Capture packets and push to queue"""
    if Raw in pkt:  # only process packets with payload
        packet_queue.put(pkt)

# Start sniffing in background
print("Starting packet capture (30s)...")
sniff_thread = threading.Thread(
    target=lambda: sniff(prn=packet_handler, store=0, timeout=30)
)
sniff_thread.daemon = True
sniff_thread.start()

# Wait for capture
time.sleep(5)

print("\n🔍 Analyzing captured packets...")
detections = {attack: False for attack in signatures.keys()}

while not packet_queue.empty():
    pkt = packet_queue.get()
    try:
        raw_payload = bytes(pkt[Raw].load).decode(errors="ignore")
    except Exception:
        continue

    # Apply each signature
    for attack, patterns in signatures.items():
        for pattern in patterns:
            if re.search(pattern, raw_payload):
                print(f"🚨 DETECTED: {attack}")
                detections[attack] = True
                break  # stop after first match for this attack

print("\n" + "=" * 60)
print("📊 SIGNATURE DETECTION SUMMARY")
print("=" * 60)

for attack, detected in detections.items():
    status = "✅ DETECTED" if detected else "❌ NOT DETECTED"
    print(f"{attack:20} {status}")

print("\n🎯 Test complete. Run real traffic or replay PCAPs to exercise signatures.")