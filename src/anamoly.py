# src/anomaly.py
import joblib
import numpy as np

class AnomalyEngine:
    def __init__(self, model_path):
        self.model = joblib.load(model_path)

    def score_features(self, feat_dict):
        """
        Convert feat_dict to array in the same order used for training.
        Must keep feature order identical between training and inference.
        Returns (is_anomaly(bool), score(float)) where higher score => more anomalous.
        """
        # Feature order used for training: pkt_len, proto, sport, dport, tcp_flags, recent_count
        arr = np.array([[feat_dict['pkt_len'],
                         feat_dict['proto'],
                         feat_dict['sport'],
                         feat_dict['dport'],
                         feat_dict['tcp_flags'],
                         feat_dict['recent_count']]], dtype=float)
        # IsolationForest returns negative scores where lower means more anomalous; use -score
        raw = self.model.decision_function(arr)[0]    # higher -> more normal
        # Convert to anomaly score 0..1 (1 is most anomalous)
        anomaly_score = float(1.0 - (raw - self.model.score_samples(arr).min()) /
                              (self.model.score_samples(arr).max() - self.model.score_samples(arr).min() + 1e-9))
        # Simpler: use -raw normalized by some constant if above fails. Keep it small and robust:
        return (anomaly_score > 0.5, float(anomaly_score))
