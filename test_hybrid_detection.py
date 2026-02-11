#!/usr/bin/env python3
"""
Comprehensive IDS Testing Script
Tests BOTH Signature-Based and Anomaly-Based Detection
"""

import requests
import time
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# Default Target (will be updated if IP is provided)
TARGET_IP = "127.0.0.1"
TARGET_PORT = 8000

if len(sys.argv) > 1:
    TARGET_IP = sys.argv[1]
    print(f"{Fore.CYAN}Target updated to: {TARGET_IP}")

BASE_URL = f"http://{TARGET_IP}:{TARGET_PORT}"

class IDSTester:
    def __init__(self):
        self.test_count = 0
        self.signature_tests = 0
        self.anomaly_tests = 0
        self.normal_tests = 0
        
    def print_header(self, text):
        print("\n" + "=" * 70)
        print(f"{Fore.CYAN}{Style.BRIGHT}{text}")
        print("=" * 70)
    
    def print_test(self, test_name, attack_type):
        self.test_count += 1
        print(f"\n{Fore.YELLOW}[Test #{self.test_count}] {test_name}")
        print(f"{Fore.WHITE}Attack Type: {attack_type}")
        print(f"{Fore.WHITE}Time: {datetime.now().strftime('%H:%M:%S')}")
    
    def send_request(self, url, method="GET", data=None, description=""):
        try:
            if method == "GET":
                response = requests.get(url, timeout=5)
            else:
                response = requests.post(url, data=data, timeout=5)
            
            print(f"{Fore.GREEN}✓ Request sent successfully")
            if description:
                print(f"{Fore.WHITE}  {description}")
            return True
        except requests.exceptions.Timeout:
            print(f"{Fore.RED}✗ Request timed out")
            return False
        except Exception as e:
            print(f"{Fore.RED}✗ Error: {str(e)}")
            return False
    
    # ========================================================================
    # SIGNATURE-BASED DETECTION TESTS
    # ========================================================================
    
    def test_sql_injection(self):
        """Test SQL Injection Detection"""
        self.print_test("SQL Injection Attack", "SIGNATURE-BASED")
        self.signature_tests += 1
        
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users--"
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n  Payload {i}: {payload}")
            url = f"{BASE_URL}/?user={payload}"
            self.send_request(url, description="SQL Injection pattern")
            time.sleep(0.5)
    
    def test_xss_attack(self):
        """Test XSS Attack Detection"""
        self.print_test("Cross-Site Scripting (XSS)", "SIGNATURE-BASED")
        self.signature_tests += 1
        
        payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n  Payload {i}: {payload}")
            url = f"{BASE_URL}/?search={payload}"
            self.send_request(url, description="XSS pattern")
            time.sleep(0.5)
    
    def test_command_injection(self):
        """Test Command Injection Detection"""
        self.print_test("Command Injection", "SIGNATURE-BASED")
        self.signature_tests += 1
        
        payloads = [
            "; cat /etc/passwd",
            "| ls -la",
            "`whoami`",
            "$(id)"
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n  Payload {i}: {payload}")
            url = f"{BASE_URL}/?cmd={payload}"
            self.send_request(url, description="Command injection pattern")
            time.sleep(0.5)
    
    def test_path_traversal(self):
        """Test Path Traversal Detection"""
        self.print_test("Path Traversal Attack", "SIGNATURE-BASED")
        self.signature_tests += 1
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\cmd.exe",
            "/etc/shadow"
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n  Payload {i}: {payload}")
            url = f"{BASE_URL}/?file={payload}"
            self.send_request(url, description="Path traversal pattern")
            time.sleep(0.5)
    
    def test_web_shell(self):
        """Test Web Shell Detection"""
        self.print_test("Web Shell Upload", "SIGNATURE-BASED")
        self.signature_tests += 1
        
        payloads = [
            "eval($_POST['cmd'])",
            "system($_GET['cmd'])",
            "shell_exec($_POST['command'])"
        ]
        
        for i, payload in enumerate(payloads, 1):
            print(f"\n  Payload {i}: {payload}")
            url = f"{BASE_URL}/?code={payload}"
            self.send_request(url, description="Web shell pattern")
            time.sleep(0.5)
    
    # ========================================================================
    # ANOMALY-BASED DETECTION TESTS
    # ========================================================================
    
    def test_dos_attack(self):
        """Test DoS Attack Detection (High Connection Count)"""
        self.print_test("Denial of Service (DoS)", "ANOMALY-BASED")
        self.anomaly_tests += 1
        
        count = 100
        print(f"\n  Sending {count} rapid requests to trigger anomaly...")
        print(f"  This should trigger high 'count' and 'srv_count' features")
        
        for i in range(count):
            try:
                requests.get(f"{BASE_URL}/?dos={i}", timeout=1)
                if i % 20 == 0:
                    print(f"{Fore.CYAN}  Progress: {i}/{count} requests sent")
            except:
                pass
        
        print(f"{Fore.GREEN}✓ DoS simulation complete")
    
    def test_data_exfiltration(self):
        """Test Data Exfiltration (Large Payload)"""
        self.print_test("Data Exfiltration", "ANOMALY-BASED")
        self.anomaly_tests += 1
        
        # Large payload to trigger src_bytes anomaly
        payload_size = 50000
        payload = "A" * payload_size
        
        print(f"\n  Sending large payload ({payload_size} bytes)")
        print(f"  This should trigger high 'src_bytes' feature")
        
        url = f"{BASE_URL}/?data={payload}"
        self.send_request(url, description=f"Large payload: {payload_size} bytes")
    
    def test_port_scan(self):
        """Test Port Scanning Behavior"""
        self.print_test("Port Scanning Behavior", "ANOMALY-BASED")
        self.anomaly_tests += 1
        
        print(f"\n  Simulating port scan with multiple connections to different ports")
        print(f"  This should trigger high 'dst_host_count' and 'dst_host_srv_count'")
        
        ports = [8000, 8001, 8002, 8003, 8004]
        for port in ports:
            try:
                url = f"http://127.0.0.1:{port}"
                requests.get(url, timeout=1)
                print(f"{Fore.CYAN}  Scanning port {port}...")
            except:
                pass
            time.sleep(0.2)
        
        print(f"{Fore.GREEN}✓ Port scan simulation complete")
    
    def test_unusual_protocol(self):
        """Test Unusual Protocol Usage"""
        self.print_test("Unusual Protocol Patterns", "ANOMALY-BASED")
        self.anomaly_tests += 1
        
        print(f"\n  Sending requests with unusual patterns")
        print(f"  This should trigger protocol and service anomalies")
        
        # Multiple requests with different parameters
        patterns = [
            "?proto=icmp&flag=SF",
            "?proto=udp&service=unknown",
            "?proto=tcp&flag=REJ&urgent=1"
        ]
        
        for pattern in patterns:
            url = f"{BASE_URL}/{pattern}"
            self.send_request(url, description=f"Unusual pattern: {pattern}")
            time.sleep(0.5)
    
    # ========================================================================
    # HYBRID DETECTION TESTS (Both Signature + Anomaly)
    # ========================================================================
    
    def test_hybrid_attack(self):
        """Test Hybrid Attack (SQL Injection + DoS)"""
        self.print_test("Hybrid Attack (SQL + DoS)", "SIGNATURE + ANOMALY")
        self.signature_tests += 1
        self.anomaly_tests += 1
        
        print(f"\n  Phase 1: SQL Injection with high frequency")
        payload = "' OR '1'='1"
        
        for i in range(50):
            url = f"{BASE_URL}/?user={payload}&id={i}"
            try:
                requests.get(url, timeout=1)
                if i % 10 == 0:
                    print(f"{Fore.CYAN}  Sent {i}/50 malicious requests")
            except:
                pass
        
        print(f"{Fore.GREEN}✓ Hybrid attack complete (Signature + Anomaly)")
    
    # ========================================================================
    # NORMAL TRAFFIC TESTS (Should NOT be detected)
    # ========================================================================
    
    def test_normal_traffic(self):
        """Test Normal Traffic (Should NOT trigger alerts)"""
        self.print_test("Normal Web Traffic", "BASELINE (No Attack)")
        self.normal_tests += 1
        
        normal_requests = [
            "/",
            "/index.html",
            "/about",
            "/?page=home",
            "/?search=python programming"
        ]
        
        print(f"\n  Sending normal requests (should NOT be flagged)")
        
        for req in normal_requests:
            url = f"{BASE_URL}{req}"
            print(f"{Fore.WHITE}  → {req}")
            self.send_request(url, description="Normal request")
            time.sleep(0.5)
    
    # ========================================================================
    # MAIN TEST RUNNER
    # ========================================================================
    
    def run_all_tests(self):
        """Run all detection tests"""
        self.print_header("🚨 HYBRID IDS DETECTION TEST SUITE 🚨")
        
        print(f"\n{Fore.WHITE}Testing both detection methods:")
        print(f"  1. Signature-Based Detection (Pattern Matching)")
        print(f"  2. Anomaly-Based Detection (ML Model)")
        print(f"\n{Fore.YELLOW}⚠️  Make sure your IDS is running before starting tests!")
        print(f"{Fore.YELLOW}⚠️  Run: python ids_UI.py and click START")
        
        input(f"\n{Fore.GREEN}Press ENTER to start testing...")
        
        # Test server availability
        print(f"\n{Fore.CYAN}Checking if server is running...")
        try:
            requests.get(BASE_URL, timeout=2)
            print(f"{Fore.GREEN}✓ Server is running at {BASE_URL}")
        except:
            print(f"{Fore.RED}✗ Server is not running!")
            print(f"{Fore.YELLOW}Please start: python -m http.server 8000")
            return
        
        # ====================================================================
        # PART 1: SIGNATURE-BASED DETECTION TESTS
        # ====================================================================
        
        self.print_header("PART 1: SIGNATURE-BASED DETECTION TESTS")
        print(f"{Fore.WHITE}These attacks should be detected by pattern matching")
        
        time.sleep(2)
        self.test_sql_injection()
        time.sleep(2)
        self.test_xss_attack()
        time.sleep(2)
        self.test_command_injection()
        time.sleep(2)
        self.test_path_traversal()
        time.sleep(2)
        self.test_web_shell()
        
        # ====================================================================
        # PART 2: ANOMALY-BASED DETECTION TESTS
        # ====================================================================
        
        self.print_header("PART 2: ANOMALY-BASED DETECTION TESTS")
        print(f"{Fore.WHITE}These attacks should be detected by ML model")
        
        time.sleep(2)
        self.test_dos_attack()
        time.sleep(2)
        self.test_data_exfiltration()
        time.sleep(2)
        self.test_port_scan()
        time.sleep(2)
        self.test_unusual_protocol()
        
        # ====================================================================
        # PART 3: HYBRID DETECTION TESTS
        # ====================================================================
        
        self.print_header("PART 3: HYBRID DETECTION TESTS")
        print(f"{Fore.WHITE}These should trigger BOTH detection methods")
        
        time.sleep(2)
        self.test_hybrid_attack()
        
        # ====================================================================
        # PART 4: NORMAL TRAFFIC (BASELINE)
        # ====================================================================
        
        self.print_header("PART 4: NORMAL TRAFFIC (BASELINE)")
        print(f"{Fore.WHITE}These should NOT trigger any alerts")
        
        time.sleep(2)
        self.test_normal_traffic()
        
        # ====================================================================
        # SUMMARY
        # ====================================================================
        
        self.print_header("TEST SUMMARY")
        print(f"\n{Fore.CYAN}Total Tests Run: {self.test_count}")
        print(f"{Fore.YELLOW}  • Signature-Based Tests: {self.signature_tests}")
        print(f"{Fore.YELLOW}  • Anomaly-Based Tests: {self.anomaly_tests}")
        print(f"{Fore.GREEN}  • Normal Traffic Tests: {self.normal_tests}")
        
        print(f"\n{Fore.WHITE}Check your IDS UI for detected threats!")
        print(f"{Fore.WHITE}Expected results:")
        print(f"  ✓ Signature tests should show specific attack types")
        print(f"  ✓ Anomaly tests should show 'Suspicious Behaviour'")
        print(f"  ✓ Hybrid tests should show both")
        print(f"  ✓ Normal traffic should NOT be flagged")
        
        print(f"\n{Fore.GREEN}{'=' * 70}")
        print(f"{Fore.GREEN}✅ All tests completed!")
        print(f"{Fore.GREEN}{'=' * 70}\n")

def main():
    tester = IDSTester()
    
    print(f"\n{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║     HYBRID IDS DETECTION TEST SUITE                            ║")
    print(f"{Fore.CYAN}║     Tests Both Signature-Based and Anomaly-Based Detection     ║")
    print(f"{Fore.CYAN}╚════════════════════════════════════════════════════════════════╝")
    print(f"{Fore.WHITE}Targeting: {BASE_URL}")
    print(f"{Fore.WHITE}(To target another PC, run: python test_hybrid_detection.py <IP_ADDRESS>)")
    
    print(f"\n{Fore.WHITE}Test Options:")
    print(f"  1. Run ALL tests (Recommended)")
    print(f"  2. Signature-Based tests only")
    print(f"  3. Anomaly-Based tests only")
    print(f"  4. Normal traffic only")
    print(f"  5. Quick test (one of each)")
    
    choice = input(f"\n{Fore.GREEN}Select option (1-5): {Fore.WHITE}")
    
    if choice == '1':
        tester.run_all_tests()
    elif choice == '2':
        tester.print_header("SIGNATURE-BASED DETECTION TESTS")
        tester.test_sql_injection()
        time.sleep(2)
        tester.test_xss_attack()
        time.sleep(2)
        tester.test_command_injection()
    elif choice == '3':
        tester.print_header("ANOMALY-BASED DETECTION TESTS")
        tester.test_dos_attack()
        time.sleep(2)
        tester.test_data_exfiltration()
    elif choice == '4':
        tester.test_normal_traffic()
    elif choice == '5':
        tester.print_header("QUICK TEST")
        tester.test_sql_injection()
        time.sleep(2)
        tester.test_dos_attack()
        time.sleep(2)
        tester.test_normal_traffic()
    else:
        print(f"{Fore.RED}Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Tests interrupted by user")
        sys.exit(0)
