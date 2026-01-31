import argparse
import sys
import time
import threading
from datetime import datetime
import yaml

# Import custom modules
from preprocessing.data_processor import DataPreprocessor
from signature_based.signature_detector import SignatureDetector
from anomaly_based.anomaly_detector import AnomalyDetector
from hybrid_engine.correlation_engine import HybridCorrelationEngine
from visualization.dashboard import Dashboard

class HybridIDS:
    def __init__(self, config_path='config.yaml', mode='train'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.mode = mode
        self.preprocessor = DataPreprocessor(config_path)
        self.signature_detector = SignatureDetector(config_path)
        self.anomaly_detector = AnomalyDetector(config_path)
        self.correlation_engine = HybridCorrelationEngine(config_path)
        self.dashboard = None
        
        # Set detectors in correlation engine
        self.correlation_engine.set_detectors(
            self.signature_detector,
            self.anomaly_detector
        )
        
        print("="*60)
        print("HYBRID INTRUSION DETECTION SYSTEM")
        print("="*60)
    
    def train_model(self):
        """Train the anomaly detection model"""
        print("\n[PHASE 1] Loading and preprocessing data...")
        
        # Load NSL-KDD dataset
        train_df, test_df = self.preprocessor.load_nsl_kdd()
        
        print(f"Training samples: {len(train_df)}")
        print(f"Testing samples: {len(test_df)}")
        
        # Preprocess data
        print("\n[PHASE 2] Preprocessing data...")
        train_processed = self.preprocessor.preprocess(train_df, is_training=True)
        test_processed = self.preprocessor.preprocess(test_df, is_training=False)
        
        # Separate features and labels
        feature_cols = [col for col in train_processed.columns 
                       if col not in ['label', 'difficulty_level', 'attack_type']]
        
        X_train = train_processed[feature_cols]
        y_train = train_processed['attack_type']
        
        X_test = test_processed[feature_cols]
        y_test = test_processed['attack_type']
        
        print(f"Training features shape: {X_train.shape}")
        print(f"Testing features shape: {X_test.shape}")
        
        # Train anomaly detection model
        print("\n[PHASE 3] Training anomaly detection model...")
        self.anomaly_detector.train(X_train)
        
        # Evaluate model
        print("\n[PHASE 4] Evaluating model...")
        evaluation = self.anomaly_detector.evaluate(X_test, y_test)
        
        # Save trained model
        print("\n[PHASE 5] Saving model...")
        self.anomaly_detector.save_model('models/anomaly_detector.joblib')
        self.preprocessor.save_preprocessor('models/preprocessor.joblib')
        
        print("\nTraining completed successfully!")
        return evaluation
    
    def realtime_monitoring(self, interface='eth0'):
        """Start real-time network monitoring"""
        print(f"\nStarting real-time monitoring on interface: {interface}")
        print("Press Ctrl+C to stop...\n")
        
        try:
            from utils.packet_capture import PacketCapturer
            capturer = PacketCapturer(interface=interface)
            
            # Start dashboard in separate thread
            if self.config['system'].get('enable_dashboard', True):
                self.dashboard = Dashboard(self.correlation_engine)
                dashboard_thread = threading.Thread(
                    target=self.dashboard.run,
                    daemon=True
                )
                dashboard_thread.start()
                print("Dashboard started at http://localhost:8050")
            
            # Start capturing and analyzing packets
            packet_count = 0
            for packet in capturer.capture():
                packet_count += 1
                
                # Analyze with signature detector
                signature_matches = self.signature_detector.analyze_packet(packet)
                
                # Convert packet to features for anomaly detection
                packet_features = self._extract_features_from_packet(packet)
                if packet_features is not None:
                    anomaly_results = self.anomaly_detector.predict([packet_features])
                else:
                    anomaly_results = []
                
                # Correlate results
                alerts = self.correlation_engine.correlate_alerts(
                    signature_matches, 
                    anomaly_results,
                    packet
                )
                
                # Log alerts
                for alert in alerts:
                    if not alert.get('is_false_positive', False):
                        self._log_alert(alert)
                
                # Print progress every 100 packets
                if packet_count % 100 == 0:
                    stats = self.correlation_engine.get_alert_summary()
                    print(f"\nProcessed {packet_count} packets")
                    print(f"Total alerts: {stats['total_alerts']}")
                    print(f"False positives: {stats['false_positives']}")
        
        except KeyboardInterrupt:
            print("\n\nStopping monitoring...")
            self._generate_report()
    
    def _extract_features_from_packet(self, packet):
        """Extract features from network packet for anomaly detection"""
        try:
            # This is a simplified feature extraction
            # In reality, you would extract all 41 features from NSL-KDD
            
            # For demo, create a dummy feature vector
            # You should implement proper feature extraction here
            import numpy as np
            return np.random.rand(10)  # Dummy features
        
        except Exception as e:
            print(f"Error extracting features: {e}")
            return None
    
    def _log_alert(self, alert):
        """Log alert to file and console"""
        log_entry = {
            'timestamp': alert['timestamp'],
            'alert_id': alert['alert_id'],
            'type': alert['type'],
            'severity': alert['severity'],
            'description': alert['description'],
            'confidence': alert.get('confidence', 0.5)
        }
        
        # Console output
        print(f"\n[ALERT] {alert['severity'].upper()}: {alert['description']}")
        
        # File logging
        with open('logs/alerts.jsonl', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def _generate_report(self):
        """Generate final report"""
        print("\n" + "="*60)
        print("FINAL SYSTEM REPORT")
        print("="*60)
        
        stats = self.correlation_engine.get_alert_summary()
        
        print(f"\nTotal Packets Processed: {len(self.correlation_engine.alerts) + stats.get('false_positives', 0)}")
        print(f"Total Alerts Generated: {stats['total_alerts']}")
        print(f"False Positives: {stats['false_positives']}")
        print(f"False Positive Rate: {(stats['false_positives']/max(1, stats['total_alerts'])):.2%}")
        
        print("\nAlert Distribution by Type:")
        for alert_type, count in stats['by_type'].items():
            print(f"  {alert_type}: {count}")
        
        print("\nAlert Distribution by Severity:")
        for severity, count in stats['by_severity'].items():
            print(f"  {severity}: {count}")
        
        # Save report to file
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'summary': stats,
            'config': self.config
        }
        
        with open('logs/final_report.json', 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"\nReport saved to: logs/final_report.json")

def main():
    parser = argparse.ArgumentParser(description='Hybrid Intrusion Detection System')
    parser.add_argument('--mode', choices=['train', 'realtime', 'test'], 
                       default='train', help='Operation mode')
    parser.add_argument('--config', default='config.yaml', 
                       help='Configuration file path')
    parser.add_argument('--interface', default='eth0', 
                       help='Network interface for real-time monitoring')
    
    args = parser.parse_args()
    
    # Create Hybrid IDS instance
    ids = HybridIDS(config_path=args.config, mode=args.mode)
    
    if args.mode == 'train':
        # Train the model
        ids.train_model()
    
    elif args.mode == 'realtime':
        # Load pre-trained models
        ids.anomaly_detector.load_model('models/anomaly_detector.joblib')
        ids.preprocessor.load_preprocessor('models/preprocessor.joblib')
        
        # Start real-time monitoring
        ids.realtime_monitoring(interface=args.interface)
    
    elif args.mode == 'test':
        # Test mode - run on sample data
        print("Test mode selected")
        # Add your test logic here
    
    print("\nHybrid IDS execution completed!")

if __name__ == "__main__":
    main()