import sys
import os
sys.path.append(os.path.join(os.getcwd(), 'src'))

from anamoly import AnomalyEngine

def test_model():
    print("--- 🧠 ML ANOMALY DETECTION CALIBRATION TEST ---")
    
    # Load the engine
    try:
        engine = AnomalyEngine(
            model_path="models/isolation_forest.pkl",
            scaler_path="models/scaler.pkl",
            encoder_path="models/encoder.pkl"
        )
    except Exception as e:
        print(f"FAILED TO LOAD MODELS: {e}")
        return

    # 1. TEST: Normal Traffic
    print("\n[1] Testing 'Normal' traffic...")
    normal_feat = {
        "duration": 0.0,
        "src_bytes": 100.0,
        "dst_bytes": 100.0,
        "count": 1.0, 
        "srv_count": 1.0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF"
    }
    res = engine.analyze(normal_feat)
    print(f"Result: {res}")

    # 2. TEST: Moderate Burst
    print("\n[2] Testing 'Moderate' burst (count=100)...")
    burst_feat = normal_feat.copy()
    burst_feat["count"] = 100.0
    burst_feat["srv_count"] = 100.0
    res = engine.analyze(burst_feat)
    print(f"Result: {res}")

    # 3. TEST: Massive Burst
    print("\n[3] Testing 'Massive' burst (count=500, src_bytes=5000)...")
    massive_feat = normal_feat.copy()
    massive_feat["count"] = 500.0
    massive_feat["srv_count"] = 500.0
    massive_feat["src_bytes"] = 5000.0
    res = engine.analyze(massive_feat)
    print(f"Result: {res}")

    # 4. TEST: Unknown Service
    print("\n[4] Testing 'Unknown' service burst...")
    unknown_feat = normal_feat.copy()
    unknown_feat.update({
        "service": "telnet",
        "count": 250.0,
        "src_bytes": 1000.0
    })
    res = engine.analyze(unknown_feat)
    print(f"Result: {res}")

if __name__ == "__main__":
    test_model()
