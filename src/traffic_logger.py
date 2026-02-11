import csv
import os
from datetime import datetime
import threading

class TrafficLogger:
    def __init__(self, log_file="traffic_data.csv"):
        self.log_file = log_file
        self.lock = threading.Lock()
        
        # Initialize file with headers if it doesn't exist
        if not os.path.exists(self.log_file):
            self._write_headers()

    def _write_headers(self):
        # Based on features.py extraction
        headers = [
            "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", 
            "src_bytes", "dst_bytes", "duration", "same_srv_rate", 
            "serror_rate", "srv_serror_rate", "dst_host_count", 
            "dst_host_srv_count", "outcome"
        ]
        with open(self.log_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)

    def log_traffic(self, feature_dict, is_malicious=False):
        """
        Log traffic features to CSV. 
        Only logs 'normal' traffic for future training unless specified.
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            outcome = "normal" if not is_malicious else "anomaly"
            
            # Map logic to match NSL-KDD style somewhat for retraining
            # Note: This is a simplified mapping based on available features
            row = [
                timestamp,
                feature_dict.get("src_ip", "0.0.0.0"),
                feature_dict.get("dst_ip", "0.0.0.0"),
                feature_dict.get("dst_port", 0),
                feature_dict.get("protocol_type", "tcp"),
                feature_dict.get("src_bytes", 0),
                feature_dict.get("dst_bytes", 0),
                feature_dict.get("duration", 0),
                # Placeholders for advanced features if not available
                feature_dict.get("count", 0),
                0.0, 0.0, # Error rates
                0, 0, # Host counts
                outcome
            ]
            
            with self.lock:
                with open(self.log_file, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(row)
                    
        except Exception as e:
            print(f"Error logging traffic: {e}")
