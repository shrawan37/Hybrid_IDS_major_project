#training/train_anomaly.py

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, confusion_matrix, roc_curve, auc

###############################################################################

# Load Dataset
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'l+and',
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

DATA_PATH = "dataset/KDDTrain+.txt"
df = pd.read_csv(DATA_PATH, names=COLUMN_NAMES, header=0, sep=",")
print("Dataset loaded. Shape:", df.shape)

# Separate Features and Target
X = df.drop(['attack_type', 'difficulty_level'], axis=1)
y = df['attack_type'].apply(lambda x: 0 if x == 'normal' else 1)

# Train-Test Split
X_train_full, X_test, y_train_full, y_test = train_test_split(
    X, y, test_size=0.33, stratify=y, random_state=42
)
print("Train set:", X_train_full.shape, "Test set:", X_test.shape)

# Train Only on Normal Samples
X_train_normal = X_train_full[y_train_full == 0].copy()
print("Training data (normal only):", X_train_normal.shape)

# Encode Categorical Columns (One-Hot Encoding)
cat_cols = ['protocol_type', 'service', 'flag']
encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
X_train_encoded = encoder.fit_transform(X_train_normal[cat_cols])
X_test_encoded = encoder.transform(X_test[cat_cols])

# Convert to DataFrame
X_train_encoded = pd.DataFrame(X_train_encoded, columns=encoder.get_feature_names_out(cat_cols))
X_test_encoded = pd.DataFrame(X_test_encoded, columns=encoder.get_feature_names_out(cat_cols))

# Drop original categorical columns & add encoded ones
X_train_normal.drop(columns=cat_cols, inplace=True)
X_test.drop(columns=cat_cols, inplace=True)

X_train_normal = X_train_normal.reset_index(drop=True)
X_test = X_test.reset_index(drop=True)

X_train_normal = pd.concat([X_train_normal, X_train_encoded], axis=1)
X_test = pd.concat([X_test, X_test_encoded], axis=1)

# Feature Scaling
scaler = StandardScaler()
X_train_normal = scaler.fit_transform(X_train_normal)
X_test = scaler.transform(X_test)

# Hyperparameter Optimization
best_n_estimators = 500
best_contamination = 0.46
best_max_samples = 0.8
best_threshold = -0.13  # Adjusted based on validation set

# Train Isolation Forest
iso_forest = IsolationForest(
    n_estimators=best_n_estimators,
    contamination=best_contamination,
    max_samples=best_max_samples,
    bootstrap=False,  # Try training with replacement for better accuracy
    random_state=42
)
iso_forest.fit(X_train_normal)

# Test Predictions
y_test_scores = iso_forest.decision_function(X_test)
y_test_pred = np.where(y_test_scores < best_threshold, 1, 0)
test_acc = accuracy_score(y_test, y_test_pred)

# Evaluation Metrics
precision = precision_score(y_test, y_test_pred)
recall = recall_score(y_test, y_test_pred)
f1 = f1_score(y_test, y_test_pred)
roc_auc = roc_auc_score(y_test, -y_test_scores)

# Print Results
print("\n=== Optimized Model Results ===")
print(f"Test Accuracy: {test_acc:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1-Score: {f1:.4f}")
print(f"ROC-AUC Score: {roc_auc:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, y_test_pred))

cm = confusion_matrix(y_test, y_test_pred)

# Confusion Matrix Plot
plt.figure(figsize=(6, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Anomaly'], yticklabels=['Normal', 'Anomaly'])
plt.title("Confusion Matrix")
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.show()

# ROC Curve and AUC
fpr, tpr, thresholds = roc_curve(y_test, -y_test_scores)  # Use decision function scores for ROC
roc_auc = auc(fpr, tpr)

# Plot ROC Curve
plt.figure(figsize=(8, 6))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC) Curve')
plt.legend(loc='lower right')
plt.show()