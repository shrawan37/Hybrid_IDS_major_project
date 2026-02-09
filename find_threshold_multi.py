import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))
from anamoly import AnomalyEngine

def multi_feature_sweep():
    engine = AnomalyEngine("models/isolation_forest.pkl", "models/scaler.pkl", "models/encoder.pkl")
    
    scenarios = [
        {"name": "Standard HTTP", "count": 1.0, "src_bytes": 100.0, "srv_count": 1.0, "flag": "SF", "service": "http"},
        {"name": "High Count Burst", "count": 2000.0, "src_bytes": 100.0, "srv_count": 2000.0, "flag": "SF", "service": "http"},
        {"name": "Large Payload", "count": 1.0, "src_bytes": 50000.0, "srv_count": 1.0, "flag": "SF", "service": "http"},
        {"name": "Syn Flood (S0)", "count": 1000.0, "src_bytes": 0.0, "srv_count": 1000.0, "flag": "S0", "service": "http"},
        {"name": "Port Scan (Other)", "count": 500.0, "src_bytes": 0.0, "srv_count": 1.0, "flag": "REJ", "service": "other"},
        {"name": "Extreme Anomaly", "count": 10000.0, "src_bytes": 100000.0, "srv_count": 1.0, "flag": "OTH", "service": "private"},
    ]
    
    print(f"{'SCENARIO':<25} | {'SCORE':<8} | {'MALICIOUS'}")
    print("-" * 50)
    for s in scenarios:
        feat = {
            "duration": 0.0, "dst_bytes": 0.0, "protocol_type": "tcp",
            "count": s["count"], "src_bytes": s["src_bytes"], 
            "srv_count": s["srv_count"], "flag": s["flag"], "service": s["service"]
        }
        res = engine.analyze(feat)
        print(f"{s['name']:<25} | {res['score']:<8.4f} | {res['malicious']}")

if __name__ == "__main__":
    multi_feature_sweep()
