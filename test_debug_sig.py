
import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))

from signature import SignatureEngine
from scapy.all import IP, TCP, Raw, Ether

def test_signature():
    engine = SignatureEngine(signatures_path="models/signatures.json")
    
    # Simulate the user's attack packet
    user_payload = "GET /?cmd=cat+/etc/passwd;ls -la HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    pkt = IP(src="192.168.1.5", dst="192.168.1.10") / TCP(dport=80) / Raw(load=user_payload)
    
    is_mal, reason, score = engine.check_packet(pkt)
    
    print(f"Payload: {user_payload.strip()}")
    print(f"Is Malicious: {is_mal}")
    print(f"Reason: {reason}")
    print(f"Score: {score}")

if __name__ == "__main__":
    test_signature()
