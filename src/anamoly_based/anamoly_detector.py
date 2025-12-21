import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import classification_report, roc_auc_score
import joblib
import yaml
import warnings
warnings.filterwarnings('ignore')

class AnomalyDetector:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.model = None
        self.threshold = self.config['system']['alert_threshold']
        
    def initialize_model(self):
        """Initialize the anomaly detection model"""
        model_type = self.config['model']['anomaly']['type']
        
        if model_type == 'IsolationForest':
            self.model = IsolationForest(
                contamination=self.config['model']['anomaly']['contamination'],
                n_estimators=self.config['model']['anomaly']['n_estimators'],
                random_state=self.config['model']['anomaly']['random_state']
            )
        elif model_type == 'OneClassSVM':
            self.model = OneClassSVM(
                nu=self.config['model']['anomaly']['contamination'],
                kernel='rbf',
                gamma='auto'
            )
        elif model_type == 'LOF':
            self.model = LocalOutlierFactor(
                contamination=self.config['model']['anomaly']['contamination'],
                novelty=True
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def train(self, X_train):
        """Train the anomaly detection model"""
        if self.model is None:
            self.initialize_model()
        
        print(f"Training {self.config['model']['anomaly']['type']} model...")
        self.model.fit(X_train)
        print("Training completed!")
        
        # Calculate anomaly scores for training data
        if hasattr(self.model, 'decision_function'):
            scores = self.model.decision_function(X_train)
        else:
            scores = self.model.score_samples(X_train)
        
        # Set dynamic threshold (95th percentile)
        self.threshold = np.percentile(scores, 5)
        print(f"Dynamic threshold set to: {self.threshold}")
        
        return self
    
    def predict(self, X):
        """Predict anomalies on new data"""
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Get anomaly scores
        if hasattr(self.model, 'decision_function'):
            scores = self.model.decision_function(X)
        else:
            scores = self.model.score_samples(X)
        
        # Convert scores to anomaly flags (1 = anomaly, 0 = normal)
        # Lower scores = more anomalous for Isolation Forest
        predictions = (scores < self.threshold).astype(int)
        
        results = []
        for i, (score, pred) in enumerate(zip(scores, predictions)):
            result = {
                'index': i,
                'anomaly_score': float(score),
                'is_anomaly': bool(pred),
                'confidence': min(1.0, max(0.0, abs(score) / 10.0))  # Normalized confidence
            }
            results.append(result)
        
        return results
    
    def evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        predictions = self.predict(X_test)
        y_pred = [p['is_anomaly'] for p in predictions]
        
        print("\n" + "="*50)
        print("ANOMALY DETECTION EVALUATION")
        print("="*50)
        
        # Classification report
        report = classification_report(y_test, y_pred, target_names=['Normal', 'Anomaly'])
        print(report)
        
        # AUC Score
        try:
            scores = [p['anomaly_score'] for p in predictions]
            auc_score = roc_auc_score(y_test, scores)
            print(f"AUC Score: {auc_score:.4f}")
        except:
            print("Could not calculate AUC score")
        
        # Detection rate
        detection_rate = np.sum(y_pred) / len(y_pred) * 100
        print(f"Detection Rate: {detection_rate:.2f}%")
        
        return {
            'classification_report': report,
            'predictions': predictions,
            'y_true': y_test.tolist()
        }
    
    def save_model(self, path='models/anomaly_detector.joblib'):
        """Save trained model"""
        joblib.dump({
            'model': self.model,
            'threshold': self.threshold,
            'config': self.config
        }, path)
        print(f"Model saved to {path}")
    
    def load_model(self, path='models/anomaly_detector.joblib'):
        """Load trained model"""
        data = joblib.load(path)
        self.model = data['model']
        self.threshold = data['threshold']
        self.config = data['config']
        print(f"Model loaded from {path}")
        return self