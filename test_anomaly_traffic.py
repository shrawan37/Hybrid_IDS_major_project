import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor

def print_header(msg):
    print("\n" + "="*60)
    print(f"  {msg}")
    print("="*60)

import sys
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

target_ip = "127.0.0.1"
if len(sys.argv) > 1:
    target_ip = sys.argv[1]
    print(f"{Fore.CYAN}Target updated to: {target_ip}")

target = f"http://{target_ip}:8000"

print_header("📡 ANOMALY-ONLY TRAFFIC GENERATOR")
print("This script sends traffic designed to trigger the ML Anomaly Detector.")
print("It uses high volume and unusual patterns rather than known signatures.\n")
input("Press ENTER to start anomaly testing...")

# 1. Volume-based Anomaly (High Frequency)
print("\n[1/2] Sending High-Frequency Traffic Anomaly...")
print("Goal: Trigger detection via 'count' and 'srv_count' features.")

session = requests.Session()

def flood():
    print(f"  Sending burst of 1000 requests via Session...")
    import random
    def send_one(_):
        try: 
            path = f"test_{random.randint(1,1000)}"
            session.get(f"{target}/{path}", timeout=0.5)
        except: pass

    with ThreadPoolExecutor(max_workers=80) as executor:
        list(executor.map(send_one, range(1500)))
    print("  Burst complete.")

threads = []
for i in range(5):
    t = threading.Thread(target=flood)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("✓ Volume-based anomaly complete.")

time.sleep(2)

# 2. Size-based Anomaly (Large Payload)
print("\n[2/2] Sending Large Payload Anomaly...")
print("Goal: Trigger detection via 'src_bytes' feature.")

try:
    # Use random-looking data instead of 'A' (which triggers the Buffer Overflow signature)
    import random
    import string
    random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=1024 * 1024))
    print("  Sending 1MB POST request with random data...")
    requests.post(target, data={"data": random_data}, timeout=5)
    print("✓ Large payload anomaly complete.")
except Exception as e:
    print(f"  Request sent (might timeout, which is fine)")

print_header("✅ ANOMALY TEST COMPLETE")
print("Observations for IDS UI:")
print("1. Look for 'Suspicious Behaviour' in the Threat column.")
print("2. These rows should be RED.")
print("3. Check if 'src_bytes' or 'count' values are unusually high in these rows.")
