from scapy.all import *
import time

def send_port_scan(target="172.16.5.214"):
    print("🚀 Sending Port Scan packets...")
    for port in range(20, 25):  # small range for demo
        pkt = IP(dst=target)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)
    print("✅ Port Scan traffic sent")

def send_arp_spoof(victim="172.16.5.214", gateway="172.16.5.1"):
    print("🚀 Sending ARP Spoofing packets...")
    pkt = ARP(op=2, psrc=gateway, pdst=victim, hwdst="ff:ff:ff:ff:ff:ff")
    send(pkt, loop=0, count=5, verbose=0)
    print("✅ ARP Spoofing traffic sent")

def send_dns_tunneling(target="8.8.8.8"):
    print("🚀 Sending DNS Tunneling packets...")
    long_query = "a" * 50 + ".example.com"
    pkt = IP(dst=target)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=long_query))
    send(pkt, verbose=0)
    print("✅ DNS Tunneling traffic sent")

def send_smb_exploit(target="127.0.0.1"):
    print("🚀 Sending SMB Exploit signature packet...")
    payload = b"ETERNALBLUE MS17-010 SMBGhost Wannacry"
    pkt = IP(dst=target)/TCP(dport=445)/Raw(load=payload)
    send(pkt, verbose=0)
    print("✅ SMB Exploit traffic sent")

def send_ftp_bruteforce(target="172.16.5.214"):
    print("🚀 Sending FTP Brute Force packets...")
    payloads = [b"USER admin PASS 1234", b"530 Login incorrect"]
    for p in payloads:
        pkt = IP(dst=target)/TCP(dport=21)/Raw(load=p)
        send(pkt, verbose=0)
    print("✅ FTP Brute Force traffic sent")

def send_ssh_attack(target="172.16.5.214"):
    print("🚀 Sending SSH Attack packets...")
    payloads = [b"Failed password for root", b"Invalid user test"]
    for p in payloads:
        pkt = IP(dst=target)/TCP(dport=22)/Raw(load=p)
        send(pkt, verbose=0)
    print("✅ SSH Attack traffic sent")

def send_email_phishing(target="172.16.5.214"):
    print("🚀 Sending Email Phishing packets...")
    payload = b"Subject: Urgent action required - verify your account now!"
    pkt = IP(dst=target)/TCP(dport=25)/Raw(load=payload)
    send(pkt, verbose=0)
    print("✅ Email Phishing traffic sent")

if __name__ == "__main__":
    send_port_scan()
    time.sleep(1)
    send_arp_spoof()
    time.sleep(1)
    send_dns_tunneling()
    time.sleep(1)
    send_smb_exploit()
    time.sleep(1)
    send_ftp_bruteforce()
    time.sleep(1)
    send_ssh_attack()
    time.sleep(1)
    send_email_phishing()
    print("\n🎯 All test traffic sent. Check IDS logs for detections.")

    