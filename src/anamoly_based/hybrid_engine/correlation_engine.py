import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import json
import yaml

class HybridCorrelationEngine:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.signature_detector = None
        self.anomaly_detector = None
        self.alerts = []
        self.time_window = timedelta(minutes=5)  # Correlation time window
    
    def set_detectors(self, signature_detector, anomaly_detector):
        """Set the signature and anomaly detectors"""
        self.signature_detector = signature_detector
        self.anomaly_detector = anomaly_detector
    
    def correlate_alerts(self, signature_matches, anomaly_results, packet_data):
        """Correlate signature and anomaly detection results"""
        correlated_alerts = []
        
        # Process signature matches
        for sig_match in signature_matches:
            alert = self._create_alert_from_signature(sig_match, packet_data)
            correlated_alerts.append(alert)
        
        # Process anomaly detections
        for anomaly in anomaly_results:
            if anomaly['is_anomaly']:
                alert = self._create_alert_from_anomaly(anomaly, packet_data)
                correlated_alerts.append(alert)
        
        # Apply correlation logic
        correlated_alerts = self._apply_correlation_logic(correlated_alerts)
        
        # Store alerts
        self.alerts.extend(correlated_alerts)
        
        return correlated_alerts
    
    def _create_alert_from_signature(self, sig_match, packet_data):
        """Create alert from signature match"""
        severity_weights = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 1.0
        }
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_id': f"SIG_{sig_match['rule_id']}_{datetime.now().timestamp()}",
            'type': 'signature',
            'rule_id': sig_match['rule_id'],
            'rule_name': sig_match['rule_name'],
            'severity': sig_match['severity'],
            'confidence': severity_weights.get(sig_match['severity'], 0.5),
            'description': f"Signature match: {sig_match['rule_name']}",
            'packet_info': sig_match.get('packet_info', ''),
            'is_false_positive': False,
            'correlated_with': []
        }
        
        return alert
    
    def _create_alert_from_anomaly(self, anomaly, packet_data):
        """Create alert from anomaly detection"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_id': f"ANOM_{anomaly['index']}_{datetime.now().timestamp()}",
            'type': 'anomaly',
            'anomaly_score': anomaly['anomaly_score'],
            'confidence': anomaly['confidence'],
            'severity': self._calculate_anomaly_severity(anomaly['anomaly_score']),
            'description': f"Anomaly detected with score: {anomaly['anomaly_score']:.4f}",
            'packet_info': str(packet_data)[:200] if packet_data else '',
            'is_false_positive': self._check_false_positive(anomaly),
            'correlated_with': []
        }
        
        return alert
    
    def _calculate_anomaly_severity(self, score):
        """Calculate severity based on anomaly score"""
        if score < -5:
            return 'critical'
        elif score < -2:
            return 'high'
        elif score < 0:
            return 'medium'
        else:
            return 'low'
    
    def _check_false_positive(self, anomaly):
        """Check if anomaly is likely a false positive"""
        # Simple false positive reduction logic
        if anomaly['confidence'] < 0.3:
            return True
        return False
    
    def _apply_correlation_logic(self, alerts):
        """Apply correlation logic to reduce false positives"""
        if not alerts:
            return []
        
        # Group alerts by time window
        time_groups = defaultdict(list)
        for alert in alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            time_key = alert_time.strftime('%Y-%m-%d %H:%M')
            time_groups[time_key].append(alert)
        
        correlated = []
        
        # Correlation: If both signature and anomaly detect same pattern, increase confidence
        for time_key, group_alerts in time_groups.items():
            sig_alerts = [a for a in group_alerts if a['type'] == 'signature']
            anom_alerts = [a for a in group_alerts if a['type'] == 'anomaly']
            
            if sig_alerts and anom_alerts:
                # Strong correlation found
                for sig_alert in sig_alerts:
                    sig_alert['confidence'] = min(1.0, sig_alert['confidence'] + 0.2)
                    sig_alert['correlated_with'].extend(
                        [a['alert_id'] for a in anom_alerts]
                    )
                    correlated.append(sig_alert)
            
            # Add all alerts (correlated or not)
            correlated.extend(group_alerts)
        
        # Remove duplicates
        seen_ids = set()
        unique_correlated = []
        for alert in correlated:
            if alert['alert_id'] not in seen_ids:
                seen_ids.add(alert['alert_id'])
                unique_correlated.append(alert)
        
        return unique_correlated
    
    def get_alert_summary(self):
        """Get summary of all alerts"""
        df = pd.DataFrame(self.alerts)
        
        if df.empty:
            return {
                'total_alerts': 0,
                'by_type': {},
                'by_severity': {},
                'false_positives': 0
            }
        
        summary = {
            'total_alerts': len(df),
            'by_type': df['type'].value_counts().to_dict(),
            'by_severity': df['severity'].value_counts().to_dict(),
            'false_positives': df['is_false_positive'].sum(),
            'recent_alerts': self.alerts[-10:]  # Last 10 alerts
        }
        
        return summary