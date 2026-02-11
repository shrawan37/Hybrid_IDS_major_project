import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.model_selection import learning_curve
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, confusion_matrix, classification_report,
    make_scorer, precision_recall_curve, average_precision_score
)
import joblib
import yaml
import os

print("=" * 80)
print("             CENTRALIZED ML REPORT GENERATOR")
print("  (Confusion Matrix | ROC Curve | Learning Curve | Metrics)")
print("=" * 80)

# ============================================================================
# 1. Load Data and Settings
# ============================================================================
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

print("\n[*] Loading Datasets...")
train_df = pd.read_csv('dataset/KDDTrain+.txt', names=COLUMN_NAMES, header=None)
test_df = pd.read_csv('test/KDDTest+.txt', names=COLUMN_NAMES, header=None)

# Settings from config or defaults
try:
    with open('config.yaml', 'r') as f:
        config = yaml.safe_load(f)
    anomaly_cfg = config.get('model', {}).get('anomaly', {})
    CONTAMINATION = anomaly_cfg.get('contamination', 0.2)
    N_ESTIMATORS = anomaly_cfg.get('n_estimators', 200)
except:
    CONTAMINATION = 0.2
    N_ESTIMATORS = 200

# SET YOUR OPTIMIZED THRESHOLD
OPTIMAL_THRESHOLD = 0.0621 

# ============================================================================
# 2. Preprocessing
# ============================================================================
print("[*] Preprocessing Data...")

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

# Scaler and Encoder
scaler = StandardScaler()
X_train_num = scaler.fit_transform(train_df[num_features])
X_test_num = scaler.transform(test_df[num_features])

encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
X_train_cat = encoder.fit_transform(train_df[cat_features])
X_test_cat = encoder.transform(test_df[cat_features])

X_train = np.hstack([X_train_num, X_train_cat])
y_train = (train_df['attack_type'] != 'normal').astype(int)

X_test = np.hstack([X_test_num, X_test_cat])
y_test = (test_df['attack_type'] != 'normal').astype(int)

# ============================================================================
# 3. Learning Curve
# ============================================================================
print("\n[A] Phase 1: Calculating Learning Curve (this may take a minute)...")

def iforest_scorer(estimator, X, y):
    # Predict using decision function and threshold for realistic learning curve
    scores = estimator.decision_function(X)
    preds = (scores < OPTIMAL_THRESHOLD).astype(int)
    return accuracy_score(y, preds)

model = IsolationForest(n_estimators=N_ESTIMATORS, contamination=CONTAMINATION, random_state=42, n_jobs=-1)

train_sizes = np.linspace(0.1, 1.0, 5)
train_sizes_abs, train_scores, cv_scores = learning_curve(
    model, X_train, y_train, train_sizes=train_sizes, cv=3, 
    scoring=iforest_scorer, n_jobs=-1
)

train_mean = np.mean(train_scores, axis=1)
train_std = np.std(train_scores, axis=1)
cv_mean = np.mean(cv_scores, axis=1)
cv_std = np.std(cv_scores, axis=1)

# Plot Learning Curve
plt.figure(figsize=(10, 6))
plt.plot(train_sizes_abs, train_mean, 'o-', color="#e74c3c", label="Training Accuracy", lw=2)
plt.plot(train_sizes_abs, cv_mean, 'o-', color="#27ae60", label="Cross-Validation Accuracy", lw=2)
plt.fill_between(train_sizes_abs, train_mean - train_std, train_mean + train_std, alpha=0.1, color="#e74c3c")
plt.fill_between(train_sizes_abs, cv_mean - cv_std, cv_mean + cv_std, alpha=0.1, color="#27ae60")
plt.title("Model Learning Curve - System Scalability", fontsize=14)
plt.xlabel("Number of Training Samples", fontsize=12)
plt.ylabel("Accuracy Score", fontsize=12)
plt.legend(loc="best")
plt.grid(True, linestyle='--', alpha=0.6)
plt.savefig('learning_curve.png', dpi=150)
print("   ✓ Learning Curve saved to: learning_curve.png")

# ============================================================================
# 4. Evaluation (Confusion Matrix & ROC)
# ============================================================================
print("\n[B] Phase 2: Generating Performance Visuals...")

# Fit final model
model.fit(X_train)
y_scores = model.decision_function(X_test)
y_pred = (y_scores < OPTIMAL_THRESHOLD).astype(int)

# METRICS
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, -y_scores)
cm = confusion_matrix(y_test, y_pred)

# Plot Confusion Matrix
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
            xticklabels=['Normal', 'Attack'], 
            yticklabels=['Normal', 'Attack'],
            annot_kws={"size": 14})
plt.title(f"Confusion Matrix (Threshold: {OPTIMAL_THRESHOLD})", fontsize=14)
plt.ylabel('Actual Label', fontsize=12)
plt.xlabel('Predicted Label', fontsize=12)
plt.savefig('confusion_matrix.png', dpi=150)
print("   ✓ Confusion Matrix saved to: confusion_matrix.png")

# Plot ROC Curve
plt.figure(figsize=(8, 6))

# Class 1 (Anomaly)
fpr1, tpr1, _ = roc_curve(y_test, -y_scores)
auc1 = roc_auc_score(y_test, -y_scores)

# Class 0 (Normal)
# For Normal class, we invert the labels and the scores
y_test_inv = 1 - y_test
fpr0, tpr0, _ = roc_curve(y_test_inv, y_scores)
auc0 = roc_auc_score(y_test_inv, y_scores)

plt.plot(fpr0, tpr0, color='blue', lw=2, label=f'Class 0 (Normal) ROC (AUC = {auc0:.4f})')
plt.plot(fpr1, tpr1, color='red', lw=2, label=f'Class 1 (Anomaly) ROC (AUC = {auc1:.4f})')
plt.plot([0, 1], [0, 1], color='black', linestyle='--', lw=1)

plt.title("Receiver Operating Characteristic (ROC) Curves for Both Classes", fontsize=14)
plt.xlabel("False Positive Rate", fontsize=12)
plt.ylabel("True Positive Rate", fontsize=12)
plt.legend(loc="lower right")
plt.grid(alpha=0.3)
plt.savefig('roc_curve.png', dpi=150)
print("   ✓ Multi-class ROC Curve saved to: roc_curve.png")

# Plot Precision-Recall Curve
plt.figure(figsize=(8, 6))
# Using -y_scores because lower scores are more anomalous
precision_values, recall_values, _ = precision_recall_curve(y_test, -y_scores)
avg_precision = average_precision_score(y_test, -y_scores)

plt.plot(recall_values, precision_values, color='green', lw=2, label=f'AP = {avg_precision:.4f}')
plt.fill_between(recall_values, precision_values, alpha=0.2, color='green')
plt.title("Precision-Recall Curve (Anomaly Detection)", fontsize=14)
plt.xlabel("Recall", fontsize=12)
plt.ylabel("Precision", fontsize=12)
plt.legend(loc="lower left")
plt.grid(alpha=0.3)
plt.savefig('precision_recall_curve.png', dpi=150)
print("   ✓ Precision-Recall Curve saved to: precision_recall_curve.png")

# Plot Anomaly Score Distribution
plt.figure(figsize=(10, 6))
# Scores for Normal vs Attack in the test set
normal_scores = y_scores[y_test == 0]
attack_scores = y_scores[y_test == 1]

sns.histplot(normal_scores, color='blue', label='Normal Traffic', kde=True, stat="density", alpha=0.5)
sns.histplot(attack_scores, color='red', label='Attack Traffic', kde=True, stat="density", alpha=0.5)

# Highlight the threshold
plt.axvline(x=OPTIMAL_THRESHOLD, color='black', linestyle='--', lw=2, label=f'Threshold ({OPTIMAL_THRESHOLD})')

plt.title("Anomaly Score Distribution (Decision Function)", fontsize=14)
plt.xlabel("Anomaly Score (Lower = More Anomalous)", fontsize=12)
plt.ylabel("Density", fontsize=12)
plt.legend(loc="best")
plt.grid(alpha=0.3)
plt.savefig('score_distribution.png', dpi=150)
print("   ✓ Anomaly Score Distribution saved to: score_distribution.png")

# ============================================================================
# 5. Summary Report
# ============================================================================
print("\n" + "="*80)
print("                         FINAL REPORT SUMMARY")
print("="*80)
print(f"Algorithm:       Isolation Forest")
print(f"Threshold:       {OPTIMAL_THRESHOLD}")
print(f"Accuracy:        {acc*100:.2f}%")
print(f"Precision:       {prec*100:.2f}%")
print(f"Recall:          {rec*100:.2f}% (Detection Rate)")
print(f"F1-Score:        {f1:.4f}")
print(f"Avg Precision:   {avg_precision:.4f}")
print(f"AUC (Anomaly):   {auc1:.4f}")
print(f"AUC (Normal):    {auc0:.4f}")
print("-" * 80)
print("CONFUSION MATRIX BREAKDOWN:")
tn, fp, fn, tp = cm.ravel()
print(f" - True Positives (Caught): {tp}")
print(f" - True Negatives (Safe):   {tn}")
print(f" - False Positives (Alarm):  {fp}")
print(f" - False Negatives (Missed): {fn}")
print("="*80)

# Save to file
with open('FINAL_ML_PROJECT_REPORT.txt', 'w') as f:
    f.write("="*80 + "\n")
    f.write("             COMPREHENSIVE ML PERFORMANCE REPORT\n")
    f.write("="*80 + "\n")
    f.write(f"Algorithm:      Isolation Forest\n")
    f.write(f"Threshold:      {OPTIMAL_THRESHOLD}\n")
    f.write(f"Accuracy:       {acc*100:.2f}%\n")
    f.write(f"Precision:      {prec*100:.2f}%\n")
    f.write(f"Recall:         {rec*100:.2f}%\n")
    f.write(f"F1-Score:       {f1:.4f}\n")
    f.write(f"Avg Precision:  {avg_precision:.4f}\n")
    f.write(f"AUC (Anomaly):  {auc1:.4f}\n")
    f.write(f"AUC (Normal):   {auc0:.4f}\n")
    f.write("-" * 35 + "\n")
    f.write(f"TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}\n")
    f.write("="*80)

print("\n✅ ALL REPORTS GENERATED SUCCESSFULLY!")
print("   Check your folder for: learning_curve.png, confusion_matrix.png, roc_curve.png, precision_recall_curve.png, FINAL_ML_PROJECT_REPORT.txt")
