import joblib
import pandas as pd
import numpy as np

class AnomalyEngine:
    def __init__(self, model_path, scaler_path, encoder_path):
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.encoder = joblib.load(encoder_path)

            # Define feature order (must match training!)
            self.numeric_features = ["duration", "src_bytes", "dst_bytes", "count", "srv_count"]
            self.categorical_features = ["protocol_type", "service", "flag"]

            print("✅ Model, scaler, and encoder loaded successfully")
        except Exception as e:
            # Graceful fallback: IDS UI still works
            print(f"[WARN] Could not load anomaly detection components: {e}")
            self.model = None
            self.scaler = None
            self.encoder = None
            self.numeric_features = []
            self.categorical_features = []

    def preprocess(self, feat_dict):
        """Convert feat_dict into scaled + encoded array that matches training pipeline."""
        if not self.scaler or not self.encoder:
            return None

        # Wrap dict into DataFrame
        X = pd.DataFrame([feat_dict])

        # Separate numeric and categorical
        X_num = X[self.numeric_features]
        X_cat = X[self.categorical_features]

        # Apply encoder to categorical features
        X_cat_encoded = self.encoder.transform(X_cat)

        # Concatenate numeric + encoded categorical
        X_final = np.hstack([X_num.values, X_cat_encoded])

        # Build DataFrame with feature names to match scaler expectations
        try:
            feature_names = list(self.numeric_features) + list(
                self.encoder.get_feature_names_out(self.categorical_features)
            )
            X_final_df = pd.DataFrame(X_final, columns=feature_names)
        except Exception as e:
            print(f"[WARN] Could not assign feature names: {e}")
            X_final_df = pd.DataFrame(X_final)

        # Debug: print shape and first row
        print("[DEBUG] Runtime feature vector shape:", X_final_df.shape)
        print("[DEBUG] Runtime feature vector sample:", X_final_df.iloc[0].to_dict())

        # Scale features
        X_scaled = self.scaler.transform(X_final_df)
        return X_scaled

    def analyze(self, feat_dict):
        """
        Run anomaly detection on extracted features.
        Returns dict with prediction and score.
        """
        if not self.model or not self.scaler or not self.encoder:
            # Fallback: no ML, but IDS UI continues
            return {
                "malicious": False,
                "score": 0.0,
                "reasons": "Anomaly detection disabled (model not loaded)"
            }

        try:
            X_scaled = self.preprocess(feat_dict)
            if X_scaled is None:
                return {
                    "malicious": False,
                    "score": 0.0,
                    "reasons": "Preprocessing unavailable"
                }

            prediction = self.model.predict(X_scaled)[0]   # -1 = anomaly, 1 = normal
            score = self.model.decision_function(X_scaled)[0]

            if prediction == -1 or score < 0.1: # Show even borderline cases
                print(f"[ANOMALY DEBUG] Pred: {prediction}, Score: {score:.4f} | Malicious: {prediction == -1}")

            return {
                "malicious": prediction == -1,
                "score": float(score),
                "reasons": "Isolation Forest anomaly detection"
            }
        except Exception as e:
            return {
                "malicious": False,
                "score": 0.0,
                "reasons": f"Error in analysis: {str(e)}"
            }