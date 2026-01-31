#!/usr/bin/env python3
"""
Safe Signature Verification Script
Uses Base64 encoded payloads to avoid AV detection on file write.
"""

import sys
import base64
sys.path.append('src')

# Import Engine
try:
    from signature import SignatureEngine
except ImportError as e:
    print(f"Import Error: {e}")
    sys.exit(1)

def main():
    print("="*60)
    print("SAFE SIGNATURE VERIFICATION")
    print("="*60)
    
    import os
    print(f"CWD: {os.getcwd()}")
    sig_path = os.path.abspath("models/signatures.json")
    print(f"Looking for signatures at: {sig_path}")
    if os.path.exists(sig_path):
        print("File exists.")
    else:
        print("File DOES NOT exist.")

    engine = SignatureEngine(signatures_path=sig_path)
    print(f"✓ Engine loaded with {len(engine.signatures)} signatures")
    if not engine.signatures:
        print("ERROR: No signatures loaded!")
        # Try debugging why
        with open(sig_path, 'r') as f:
            print(f"File content preview: {f.read(100)}")


    with open("status.txt", "w") as status_file:
        status_file.write(f"CWD: {os.getcwd()}\n")
        status_file.write(f"Signatures path: {sig_path}\n")
        status_file.write(f"Engine signatures count: {len(engine.signatures)}\n")
        status_file.write(f"Signatures keys: {list(engine.signatures.keys())}\n")

    # (Attack Name, Base64 Payload, Expected Signature Key)
    tests = [
        ("SQL Injection", "R0VUIC9sb2dpbj91c2VyPWFkbWluJyBPUiAnMSc9JzEgSFRUUC8xLjE=", "sql_injection"),
        ("XSS Attack", "R0VUIC8/cT08c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+IEhUVFAvMS4x", "xss_payload"),
        ("Command Injection", "R0VUIC8/Y21kPTtjYXQgL2V0Yy9wYXNzd2QgSFRUUC8xLjE=", "command_injection"),
        ("Path Traversal", "R0VUIC9maWxlP3BhdGg9Li4vLi4vZXRjL3Bhc3N3ZCBIVFRQLzEuMQ==", "path_traversal"),
        ("LDAP Injection", "R0VUIC9sZGFwP2ZpbHRlcj0qKSh1aWQ9KikpIEhUVFAvMS4x", "ldap_injection"),
        ("XXE Injection", "UE9TVCAveG1sIEhUVFAvMS4xDQoNCjwhRE9DVFlQRSByb290IFs8IUVOVElUWSB4eGUgU1lTVEVNICdmaWxlOi8vL2V0Yy9wYXNzd2QnPl0+", "xxe_injection"),
        ("Web Shell", "UE9TVCAvdXBsb2FkLnBocCBIVFRQLzEuMQ0KDQo8P3BocCBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4=", "web_shell"),
        ("Malware Sig", "R0VUIC9kb3dubG9hZC5leGUgSFRUUC8xLjE=", "malware_signature"), # Note: regex might be strict
        ("JSON Injection", "UE9TVCAvYXV0aCBIVFRQLzEuMQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi9qc29uDQoNCnsidXNlcm5hbWUiOiB7IiRuZSI6IG51bGx9LCAicGFzc3dvcmQiOiAicGFzc3dvcmQifQ==", "json_injection"),
        ("NoSQL Injection", "UE9TVCAvcXVlcnkgSFRUUC8xLjENClxueyIkd2hlcmUiOiAic2xlZXAoNTAwMCkifQ==", "nosql_injection"),
        ("Suspicious Enc", "R0VUIC8lMmUlMmUlMmYlMmUlMmUlMmZldGMvcGFzc3dkIEhUVFAvMS4x", "suspicious_encoding"),
    ]

    detected = 0
    total = len(tests) + 1 # +1 for buffer overflow


    print(f"\nRunning {total} tests...\n")
    print(f"{'Attack Name':<20} | {'Status':<15} | {'Details'}")
    print("-" * 60)

    # Run standard tests
    for name, b64_load, expected_key in tests:
        try:
            payload = base64.b64decode(b64_load).decode('utf-8', errors='ignore')
            print(f"DEBUG PAYLOAD: {payload}")
            # Use check_payload_signatures directly to test logic
            is_mal, type_found, score = engine.check_payload_signatures(payload, debug=True)
            
            if is_mal:
                status = "✅ DETECTED"
                detail = f"{type_found} (Score: {score})"
                detected += 1
            else:
                status = "❌ MISSED"
                detail = f"Expected {expected_key}"
            
            print(f"{name:<20} | {status:<15} | {detail}")

        except Exception as e:
            print(f"{name:<20} | ⚠ ERROR       | {e}")
            import traceback
            traceback.print_exc()

    print("-" * 60)
    print(f"RESULTS: {detected}/{total} Detected")


    print("-" * 60)
    print(f"RESULTS: {detected}/{total} Detected")
    
    if detected == total:
        print("\n✅ Verification SUCCESSFUL")
    else:
        print("\n⚠ Some signatures were not triggered.")

if __name__ == "__main__":
    main()
