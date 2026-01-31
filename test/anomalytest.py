#anamalytest.py
import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score

# Load the trained Isolation Forest model and scaler
import joblib


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

iso_forest = joblib.load(os.path.join(BASE_DIR, "models", "isolation_forest.pkl"))
scaler = joblib.load(os.path.join(BASE_DIR, "models", "scaler.pkl"))
encoder = joblib.load(os.path.join(BASE_DIR, "models", "encoder.pkl"))


# Define column names (adjust if needed)
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_hot_logins',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack_type', 'difficulty_level'
]

# Load the new dataset
NEW_DATA_PATH = "dataset\\test_data1.csv"
new_df = pd.read_csv(NEW_DATA_PATH, names=COLUMN_NAMES, header=0, sep=",")
print("New dataset loaded. Shape:", new_df.shape)

# Separate features and target
X_new = new_df.drop(['attack_type', 'difficulty_level'], axis=1)
y_new = new_df['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)

# Ensure the columns are in the same order as during training
FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
    'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_hot_logins',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# Check for missing columns and add them with default value 0
missing_cols = set(FEATURES) - set(X_new.columns)
if missing_cols:
    for col in missing_cols:
        X_new[col] = 0  # Add missing columns with default value 0

# Remove extra columns that are not in FEATURES
extra_cols = set(X_new.columns) - set(FEATURES)
if extra_cols:
    X_new.drop(columns=extra_cols, inplace=True)

# Reorder columns to match the training dataset
X_new = X_new[FEATURES]

# Encode categorical columns
cat_cols = ['protocol_type', 'service', 'flag']
encoders = {}
for col in cat_cols:
    le = LabelEncoder()
    unique_train_vals = X_new[col].unique()
    le.fit(list(unique_train_vals) + ["unknown"])
    X_new[col] = X_new[col].apply(lambda x: x if x in unique_train_vals else "unknown")
    X_new[col] = le.transform(X_new[col])
    encoders[col] = le

# Scale numerical columns
X_new[FEATURES] = scaler.transform(X_new[FEATURES])

# Predict on the new dataset using a custom decision threshold
y_scores_new = iso_forest.decision_function(X_new[FEATURES])
threshold = -0.13  # Adjust this value as needed
y_pred_new = np.where(y_scores_new < threshold, 1, 0)

# Evaluate the model on the new dataset
print("\n=== Evaluation on New Dataset ===")
cm_new = confusion_matrix(y_new, y_pred_new)
cr_new = classification_report(y_new, y_pred_new)
acc_new = accuracy_score(y_new, y_pred_new)
prec_new = precision_score(y_new, y_pred_new)
rec_new = recall_score(y_new, y_pred_new)
f1_new = f1_score(y_new, y_pred_new)

print("Confusion Matrix:")
print(cm_new)
print("\nClassification Report:")
print(cr_new)
print(f"Accuracy:  {acc_new:.4f}")
print(f"Precision: {prec_new:.4f}")
print(f"Recall:    {rec_new:.4f}")
print(f"F1-Score:  {f1_new:.4f}")

# Calculate ROC-AUC score
roc_auc_new = roc_auc_score(y_new, -y_scores_new)  # Invert scores for ROC calculation
print(f"ROC-AUC Score: {roc_auc_new:.4f}")