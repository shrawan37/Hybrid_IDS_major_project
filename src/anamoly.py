<<<<<<< HEAD
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
=======
import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import joblib
import pandas as pd
import numpy as np
import os

class AnomalyEngine:
    def __init__(self, model_path, scaler_path, encoder_path=None):
        """
        Initialize AnomalyEngine with MAX performance artifacts and threshold.
        """
        try:
            # Determine directory of models
            models_dir = os.path.dirname(model_path)
            if not models_dir: models_dir = 'models'
            
            # Load optimized artifacts
            self.model = joblib.load(os.path.join(models_dir, 'isolation_forest_frontend.pkl'), mmap_mode='r')
            self.scaler = joblib.load(os.path.join(models_dir, 'scaler_frontend.pkl'))
            self.encoder = joblib.load(os.path.join(models_dir, 'encoder_frontend.pkl'))
            
            # Full NSL-KDD original features
            self.numeric_features = [
                'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
                'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
                'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 
                'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count', 
                'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 
                'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 
                'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
                'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
                'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
                'dst_host_srv_rerror_rate'
            ]
            
            # 3 optimized categorical features (all are now OneHot in MAX model)
            self.categorical_features = ['protocol_type', 'flag', 'service']
            
        except Exception as e:
            print(f"WARN: Error loading model artifacts: {e}")
            self.model = None

    def preprocess(self, data_dict):
        """MAX Performance Preprocessing (No Pandas needed for inference)"""
        if not self.model: return None
        try:
            # 1. Process Numeric Features
            num_data = np.array([[data_dict.get(f, 0.0) for f in self.numeric_features]])
            num_scaled = self.scaler.transform(num_data)
            
            # 2. Process Categorical Features (OneHot)
            cat_data = [[
                data_dict.get('protocol_type', 'tcp'),
                data_dict.get('flag', 'SF'),
                data_dict.get('service', 'http')
            ]]
            cat_encoded = self.encoder.transform(cat_data)
            if hasattr(cat_encoded, 'toarray'):
                cat_encoded = cat_encoded.toarray()
            
            # 3. Combine vectors (Numeric + Categorical)
            X_final = np.hstack([num_scaled, cat_encoded])
            
            return X_final
        except Exception as e:
            print(f"DEBUG PREPROCESS ERROR: {e}")
            return None

    def analyze(self, feat_dict):
        if not self.model: return {"malicious": False, "score": 0.0, "reasons": "Model not loaded"}
        try:
            X_input = self.preprocess(feat_dict)
            if X_input is None: return {"malicious": False, "score": 0.0, "reasons": "Preprocessing failed"}
            
            # Get anomaly score from Isolation Forest
            score = self.model.decision_function(X_input)[0]
            
            # REALISTIC THRESHOLD (Optimized for 0.1 Contamination)
            OPTIMAL_THRESHOLD = 0.0796
            
            # Final Decision
            is_attack = bool(score < OPTIMAL_THRESHOLD)
            
            return {
                "malicious": is_attack, 
                "score": float(score), 
                "reasons": "ATTACK - Suspicious" if is_attack else "NORMAL - Safe"
            }
        except Exception as e:
            return {"malicious": False, "score": 0.0, "reasons": f"Error: {str(e)}"}
>>>>>>> main
