import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_selection import SelectKBest, f_classif
import joblib
import yaml

class DataPreprocessor:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_selector = None
        
    def load_nsl_kdd(self):
        """Load and preprocess NSL-KDD dataset"""
        # Column names for NSL-KDD
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised',
            'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds',
            'is_host_login', 'is_guest_login', 'count', 'srv_count',
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
        ]
        
        train_path = f"{self.config['dataset']['path']}{self.config['dataset']['train_file']}"
        test_path = f"{self.config['dataset']['path']}{self.config['dataset']['test_file']}"
        
        train_df = pd.read_csv(train_path, names=columns)
        test_df = pd.read_csv(test_path, names=columns)
        
        return train_df, test_df
    
    def preprocess(self, df, is_training=True):
        """Preprocess the dataframe"""
        df_clean = df.copy()
        
        # 1. Encode categorical features
        categorical_cols = self.config['features']['categorical']
        for col in categorical_cols:
            if col in df_clean.columns:
                if is_training:
                    le = LabelEncoder()
                    df_clean[col] = le.fit_transform(df_clean[col])
                    self.label_encoders[col] = le
                else:
                    le = self.label_encoders.get(col)
                    if le:
                        # Handle unseen labels
                        df_clean[col] = df_clean[col].apply(
                            lambda x: le.transform([x])[0] if x in le.classes_ else -1
                        )
        
        # 2. Encode target variable
        if self.config['features']['target'] in df_clean.columns:
            df_clean['attack_type'] = df_clean[self.config['features']['target']].apply(
                lambda x: 1 if x != 'normal' else 0
            )
        
        # 3. Scale numerical features
        numerical_cols = self.config['features']['numerical']
        if is_training:
            df_clean[numerical_cols] = self.scaler.fit_transform(df_clean[numerical_cols])
        else:
            df_clean[numerical_cols] = self.scaler.transform(df_clean[numerical_cols])
        
        # 4. Feature selection (training only)
        if is_training and self.config['features'].get('select_k'):
            X = df_clean.drop([self.config['features']['target'], 'difficulty_level', 'attack_type'], 
                            axis=1, errors='ignore')
            y = df_clean['attack_type']
            
            self.feature_selector = SelectKBest(score_func=f_classif, 
                                              k=self.config['features']['select_k'])
            X_selected = self.feature_selector.fit_transform(X, y)
            selected_features = X.columns[self.feature_selector.get_support()]
            
            df_clean = pd.DataFrame(X_selected, columns=selected_features)
            df_clean['attack_type'] = y.values
        
        return df_clean
    
    def save_preprocessor(self, path='models/preprocessor.joblib'):
        """Save preprocessor for later use"""
        joblib.dump({
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_selector': self.feature_selector
        }, path)
    
    def load_preprocessor(self, path='models/preprocessor.joblib'):
        """Load preprocessor"""
        data = joblib.load(path)
        self.scaler = data['scaler']
        self.label_encoders = data['label_encoders']
        self.feature_selector = data['feature_selector']