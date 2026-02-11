import requests
import time
import random

BASE_URL = "http://127.0.0.1:8000"

def send_normal():
    print("[+] Sending normal request...")
    try:
        requests.get(BASE_URL)
        print("    Success")
    except Exception as e:
        print(f"    Error: {e}")

def simulate_dos(count=100):
    print(f"[!] Simulating DoS Attack ({count} rapid requests)...")
    for i in range(count):
        try:
            # Rapid requests to trigger 'count' and 'srv_count' anomalies
            requests.get(f"{BASE_URL}/?dos={i}")
            if i % 20 == 0: print(f"    Sent {i}...")
        except:
            pass
    print("    DoS Simulation Complete")

def simulate_exfiltration():
    print("[!] Simulating Data Exfiltration (Massive payload)...")
    # Sending 50,000 characters to trigger 'src_bytes' anomaly
    payload = "A" * 50000 
    try:
        requests.get(f"{BASE_URL}/?data={payload}")
        print("    Large payload sent")
    except Exception as e:
        print(f"    Error: {e}")

if __name__ == "__main__":
    print("--- IDS TEST GENERATOR ---")
    print("1. Normal Traffic")
    print("2. DoS Simulation")
    print("3. Data Exfiltration Simulation")
    print("4. All of the above")
    
    choice = input("\nSelect test (1-4): ")
    
    if choice == '1':
        send_normal()
    elif choice == '2':
        simulate_dos()
    elif choice == '3':
        simulate_exfiltration()
    elif choice == '4':
        send_normal()
        time.sleep(2)
        simulate_dos()
        time.sleep(2)
        simulate_exfiltration()
    else:
        print("Invalid choice")
