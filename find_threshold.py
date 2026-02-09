import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))
from anamoly import AnomalyEngine

def sweep():
    engine = AnomalyEngine("models/isolation_forest.pkl", "models/scaler.pkl", "models/encoder.pkl")
    base_feat = {
        "duration": 0.0, "src_bytes": 0.0, "dst_bytes": 0.0, 
        "count": 1.0, "srv_count": 1.0, 
        "protocol_type": "tcp", "service": "http", "flag": "SF"
    }
    
    print("COUNT | SCORE | MALICIOUS")
    print("-" * 30)
    for c in range(100, 2001, 200):
        feat = base_feat.copy()
        feat["count"] = float(c)
        feat["srv_count"] = float(c)
        res = engine.analyze(feat)
        print(f"{c:5} | {res['score']:7.4f} | {res['malicious']}")

if __name__ == "__main__":
    sweep()
