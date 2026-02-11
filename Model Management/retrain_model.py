import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
import joblib
import yaml
import os

print("=" * 70)
print("  RETRAINING ISOLATION FOREST - NSL-KDD DATASET")
print("=" * 70)

# 1. Load Configuration
print("\n[1/6] Loading settings from config.yaml...")
try:
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Get values from config
    anomaly_cfg = config.get('model', {}).get('anomaly', {})
    CONTAMINATION = anomaly_cfg.get('contamination', 0.1)
    N_ESTIMATORS = anomaly_cfg.get('n_estimators', 100)
    RANDOM_STATE = anomaly_cfg.get('random_state', 42)
    
    print(f"   ✓ Contamination: {CONTAMINATION}")
    print(f"   ✓ N_Estimators:  {N_ESTIMATORS}")
except Exception as e:
    print(f"   ! Warning loading config: {e}. Using defaults.")
    CONTAMINATION = 0.1
    N_ESTIMATORS = 100
    RANDOM_STATE = 42

# 2. Load Dataset
print("\n[2/6] Loading NSL-KDD Training Data...")
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty_level'
]

train_path = 'dataset/KDDTrain+.txt'
if not os.path.exists(train_path):
    print(f"   ✗ Error: Dataset not found at {train_path}")
    exit(1)

df = pd.read_csv(train_path, names=COLUMN_NAMES, header=None)
print(f"   ✓ Loaded {len(df)} training samples")

# 3. Preprocessing
print("\n[3/6] Preprocessing and Scaling...")
# Define ALL NSL-KDD original features
num_features = [
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
cat_features = ['protocol_type', 'flag', 'service']

# Scale numeric
scaler = StandardScaler()
X_num = scaler.fit_transform(df[num_features])

# Encode categorical
encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
X_cat = encoder.fit_transform(df[cat_features])

# Combine
X_train = np.hstack([X_num, X_cat])
print(f"   ✓ Feature matrix shape: {X_train.shape}")

# 4. Train Model
print(f"\n[4/6] Training Isolation Forest ({N_ESTIMATORS} trees)...")
model = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    random_state=RANDOM_STATE,
    n_jobs=-1
)
model.fit(X_train)
print("   ✓ Training Complete")

# 5. Internal Evaluation (Training Accuracy)
print("\n[5/6] Calculating Training Accuracy...")
y_train_true = (df['attack_type'] != 'normal').astype(int)
y_train_pred = (model.predict(X_train) == -1).astype(int)
train_acc = (y_train_true == y_train_pred).mean()
print(f"   ✓ Training Accuracy: {train_acc*100:.2f}%")

# 6. Save Artifacts
print("\n[6/6] Saving Optimized Model...")
if not os.path.exists('models'): os.makedirs('models')

joblib.dump(model, 'models/isolation_forest_frontend.pkl')
joblib.dump(scaler, 'models/scaler_frontend.pkl')
joblib.dump(encoder, 'models/encoder_frontend.pkl')

print("\n" + "=" * 70)
print("  TABLE 6.1 - TRAINING RESULTS")
print("=" * 70)
print(f"Algorithm:           Isolation Forest")
print(f"Training Accuracy:   {train_acc*100:.2f}%")
print(f"Samples Processed:   {len(df)}")
print(f"Status:              ✓ Models Saved to 'models/'")
print("=" * 70)

print("\n✅ NEXT STEP: Run 'python evaluate_model_metrics.py' to see testing results.")
