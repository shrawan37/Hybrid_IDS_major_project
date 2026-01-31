#!/usr/bin/env python3
"""
Direct Signature Detection Test - Tests payload patterns directly
"""

import sys
sys.path.append('src')
from signature import SignatureEngine

def main():
    print("\n" + "="*70)
    print("DIRECT SIGNATURE DETECTION TEST")
    print("="*70 + "\n")
    
    # Load engine
    print("Step 1: Loading Signature Engine...")
    engine = SignatureEngine()
    print(f"✓ Loaded {len(engine.signatures)} signatures\n")
    
    # Test payloads - these match the regex patterns exactly
    print("Step 2: Testing Payloads Against Signatures")
    print("-" * 70)
    
    test_payloads = [
        ("SQL Injection", "admin' OR '1'='1"),
        ("XSS - Script Tag", "<script>alert(1)</script>"),
        ("XSS - Event Handler", "onclick='alert(1)'"),
        ("Command Injection", ";cat /etc/passwd"),
        ("Command Injection Pipe", "| ls /"),
        ("Command Injection Backtick", "`whoami`"),
        ("Path Traversal", "../../etc/passwd"),
        ("LDAP Injection", "*)|admin*"),
        ("XXE Injection", "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"),
        ("Web Shell", "eval($_POST['cmd'])"),
    ]
    
    detected_count = 0
    
    for i, (name, payload) in enumerate(test_payloads, 1):
        # Check detection
        is_malicious, attack_type, score = engine.check_payload_signatures(payload, debug=False)
        
        if is_malicious:
            detected_count += 1
            status = "✓ DETECTED"
            color = "🔴"
        else:
            status = "✗ MISSED"
            color = "⚪"
        
        print(f"{color} Test {i}: {status:15} | {name:25} -> {attack_type} (Score: {score:.2f})")
    
    print("\n" + "="*70)
    print(f"RESULTS: {detected_count}/{len(test_payloads)} attacks detected")
    print("="*70 + "\n")
    
    if detected_count >= len(test_payloads) * 0.8:  # 80% detection rate
        print("✅ SUCCESS - Signature detection is WORKING!")
        print(f"   Detection rate: {(detected_count/len(test_payloads)*100):.1f}%")
    else:
        print(f"⚠️  WARNING - Low detection rate: {(detected_count/len(test_payloads)*100):.1f}%")
    
    print("\n" + "="*70)
    print("All Loaded Signatures:")
    print("="*70)
    for attack_type, sig_data in engine.signatures.items():
        description = sig_data.get('description', 'No description')
        severity = sig_data.get('severity', 0)
        print(f"  • {attack_type:25} | Severity: {severity:.2f} | {description}")
    
    print("\n✅ Test Complete")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
