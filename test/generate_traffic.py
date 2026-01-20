from scapy.all import send, IP, TCP, UDP, Raw
import random
import time

def send_malicious_traffic():
    """ Generate and send aggressive malicious traffic to test detection """
    source_ip= "192.168.1."
    target_ip = "192.168.1.100"  # Change this to match your test machine
    target_port=80
    payload="select from *"

    packet=IP(src=source_ip,dst=target_ip)/TCP(dport=target_port)/Raw(payload)

    send(packet, verbose=0)

    print("✅ Malicious traffic sent successfully!")

if __name__ == "__main__":
    send_malicious_traffic()
