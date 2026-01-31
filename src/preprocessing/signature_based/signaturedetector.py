import re
import yaml
import pandas as pd
from datetime import datetime
import json

class SignatureRule:
    def __init__(self, rule_id, name, pattern, severity, protocol=None):
        self.rule_id = rule_id
        self.name = name
        self.pattern = pattern
        self.severity = severity  # low, medium, high, critical
        self.protocol = protocol
        
    def match(self, packet_data):
        """Check if packet matches the rule pattern"""
        # Convert packet data to string for pattern matching
        packet_str = str(packet_data)
        
        # Simple regex matching (can be extended for complex patterns)
        if re.search(self.pattern, packet_str, re.IGNORECASE):
            return True
        return False

class SignatureDatabase:
    def __init__(self, rule_path='data/rules/'):
        self.rule_path = rule_path
        self.rules = []
        self.load_rules()
    
    def load_rules(self):
        """Load rules from YAML files"""
        try:
            with open(f'{self.rule_path}signatures.yaml', 'r') as f:
                rule_data = yaml.safe_load(f)
                
            for rule in rule_data['rules']:
                signature = SignatureRule(
                    rule_id=rule['id'],
                    name=rule['name'],
                    pattern=rule['pattern'],
                    severity=rule['severity'],
                    protocol=rule.get('protocol')
                )
                self.rules.append(signature)
                
        except FileNotFoundError:
            # Create default rules if file doesn't exist
            self.create_default_rules()
    
    def create_default_rules(self):
        """Create default signature rules for common attacks"""
        default_rules = [
            {
                'id': 1,
                'name': 'SQL Injection Attempt',
                'pattern': r'(union.*select|select.*from|insert.*into|delete.*from)',
                'severity': 'high',
                'protocol': 'HTTP'
            },
            {
                'id': 2,
                'name': 'XSS Attack',
                'pattern': r'(<script>|javascript:|onload=|onerror=)',
                'severity': 'medium',
                'protocol': 'HTTP'
            },
            {
                'id': 3,
                'name': 'Port Scan Detection',
                'pattern': r'(port.*scan|nmap|masscan)',
                'severity': 'medium',
                'protocol': 'TCP'
            },
            {
                'id': 4,
                'name': 'DoS Attack Pattern',
                'pattern': r'(syn.*flood|ping.*of.*death|teardrop)',
                'severity': 'critical',
                'protocol': 'TCP'
            }
        ]
        
        # Save default rules
        with open(f'{self.rule_path}signatures.yaml', 'w') as f:
            yaml.dump({'rules': default_rules}, f)
        
        # Load them
        self.load_rules()
    
    def add_rule(self, rule):
        """Add a new rule to database"""
        self.rules.append(rule)
        self.save_rules()
    
    def save_rules(self):
        """Save rules to file"""
        rule_data = {'rules': []}
        for rule in self.rules:
            rule_data['rules'].append({
                'id': rule.rule_id,
                'name': rule.name,
                'pattern': rule.pattern,
                'severity': rule.severity,
                'protocol': rule.protocol
            })
        
        with open(f'{self.rule_path}signatures.yaml', 'w') as f:
            yaml.dump(rule_data, f)

class SignatureDetector:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.signature_db = SignatureDatabase(
            self.config['signatures']['rule_path']
        )
        self.detected_signatures = []
    
    def analyze_packet(self, packet_data):
        """Analyze a single packet for signature matches"""
        matches = []
        
        for rule in self.signature_db.rules:
            if rule.match(packet_data):
                match_info = {
                    'timestamp': datetime.now().isoformat(),
                    'rule_id': rule.rule_id,
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'protocol': rule.protocol,
                    'packet_info': str(packet_data)[:200]  # First 200 chars
                }
                matches.append(match_info)
                self.detected_signatures.append(match_info)
        
        return matches
    
    def analyze_batch(self, packets):
        """Analyze multiple packets"""
        all_matches = []
        for packet in packets:
            matches = self.analyze_packet(packet)
            all_matches.extend(matches)
        
        return all_matches
    
    def get_detection_stats(self):
        """Get statistics about detections"""
        df = pd.DataFrame(self.detected_signatures)
        
        if df.empty:
            return {
                'total_detections': 0,
                'by_severity': {},
                'by_rule': {}
            }
        
        stats = {
            'total_detections': len(df),
            'by_severity': df['severity'].value_counts().to_dict(),
            'by_rule': df['rule_name'].value_counts().to_dict()
        }
        
        return stats