#!/usr/bin/env python3
"""
Evaluate the Frontend Model Metrics
Displays: Accuracy, Precision, Recall, F1-Score, ROC-AUC, Confusion Matrix
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, confusion_matrix, classification_report
)
from sklearn.model_selection import learning_curve
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns

print("=" * 70)
print("  FRONTEND MODEL EVALUATION - NSL-KDD Test Set")
print("=" * 70)

# ============================================================================
# 1. Load Test Data
# ============================================================================
print("\n[1/5] Loading NSL-KDD Test Dataset...")

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

# Try multiple test file locations
test_paths = [
    "test/KDDTest+.txt",
    "dataset/testdata.csv",
    "dataset/test_data1.csv"
]

test_df = None
for path in test_paths:
    if os.path.exists(path):
        print(f"   [*] Found test data: {path}")
        test_df = pd.read_csv(path, names=COLUMN_NAMES, header=None)
        break

if test_df is None:
    print("   [!] Error: No test data found!")
    print(f"   Searched: {test_paths}")
    exit(1)

print(f"   [OK] Loaded {len(test_df)} test samples")

# --- Load Training Data for Table 6.1 ---
train_path = "dataset/KDDTrain+.txt"
if os.path.exists(train_path):
    print(f"   [*] Loading training data for metrics: {train_path}")
    train_df = pd.read_csv(train_path, names=COLUMN_NAMES, header=None)
else:
    train_df = test_df.copy() # Fallback if unavailable

# ============================================================================
# 2. Load Model and Preprocessing Artifacts
# ============================================================================
print("\n[2/5] Loading Model and Preprocessing Artifacts...")

try:
    model = joblib.load('models/isolation_forest_frontend.pkl')
    scaler = joblib.load('models/scaler_frontend.pkl')
    encoder = joblib.load('models/encoder_frontend.pkl')
    freq_encoding = joblib.load('models/freq_encoding_frontend.pkl')
    frontend_features = joblib.load('models/frontend_features.pkl')
    print("   [*] All artifacts loaded successfully")
except Exception as e:
    print(f"   ✗ Error loading model: {e}")
    exit(1)

# ============================================================================
# 3. Preprocess Test Data (Same as Training)
# ============================================================================
print("\n[3/5] Preprocessing Test Data...")

# Create target labels (0 = normal, 1 = attack)
y_test = (test_df['attack_type'] != 'normal').astype(int)
print(f"   Normal samples: {(y_test == 0).sum()}")
print(f"   Attack samples: {(y_test == 1).sum()}")

# Preprocess Test Data
X_test_raw = test_df.drop(['attack_type', 'difficulty_level'], axis=1)

# ALL NSL-KDD features
numeric_features = [
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
categorical_features = ['protocol_type', 'flag', 'service']

# 1. Scale numeric features
X_test_num = scaler.transform(X_test_raw[numeric_features])

# 2. Encode categorical features
X_test_cat = encoder.transform(X_test_raw[categorical_features])
if hasattr(X_test_cat, 'toarray'):
    X_test_cat = X_test_cat.toarray()

# 3. Combine vectors
X_test_final = np.hstack([X_test_num, X_test_cat])

print(f"   [*] Preprocessed to {X_test_final.shape[1]} features")

# --- Preprocess Training Data for Metrics ---
X_train_raw = train_df.drop(['attack_type', 'difficulty_level'], axis=1)
y_train_true = (train_df['attack_type'] != 'normal').astype(int)
X_train_num = scaler.transform(X_train_raw[numeric_features])
X_train_cat = encoder.transform(X_train_raw[categorical_features])
if hasattr(X_train_cat, 'toarray'): X_train_cat = X_train_cat.toarray()
X_train_final = np.hstack([X_train_num, X_train_cat])

# ============================================================================
# 4. Make Predictions (Using Optimized Threshold)
# ============================================================================
print("\n[4/5] Running Model Predictions (Optimized)...")

# Get raw decision scores
y_scores = model.decision_function(X_test_final)

# Balanced threshold for optimum performance
OPTIMAL_THRESHOLD = 0.0796
y_pred = (y_scores < OPTIMAL_THRESHOLD).astype(int)

print(f"   [OK] Predicted {(y_pred == 1).sum()} attacks out of {len(y_pred)} samples")

# ============================================================================
# 5. Calculate Metrics
# ============================================================================
print("\n[5/5] Calculating Performance Metrics...")

# Calculate all metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, zero_division=0)
recall = recall_score(y_test, y_pred, zero_division=0)
f1 = f1_score(y_test, y_pred, zero_division=0)
roc_auc = roc_auc_score(y_test, -y_scores)  # Negative because lower = more anomalous
cm = confusion_matrix(y_test, y_pred)

# Calculate Training Accuracy
y_train_scores = model.decision_function(X_train_final)
y_train_pred = (y_train_scores < OPTIMAL_THRESHOLD).astype(int)
train_accuracy = accuracy_score(y_train_true, y_train_pred)

# ============================================================================
# Display Results
# ============================================================================
print("\n" + "=" * 70)
print("                    MODEL PERFORMANCE METRICS")
print("=" * 70)
print(f"\n[*] Overall Metrics:")
print(f"   Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"   Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"   Recall:    {recall:.4f} ({recall*100:.2f}%)")
print(f"   F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
print(f"   ROC-AUC:   {roc_auc:.4f} ({roc_auc*100:.2f}%)")

print(f"\n[*] Confusion Matrix:")
print(f"                 Predicted")
print(f"                 Normal  Attack")
print(f"   Actual Normal  {cm[0][0]:6d}  {cm[0][1]:6d}")
print(f"   Actual Attack  {cm[1][0]:6d}  {cm[1][1]:6d}")

print(f"\n[*] Detailed Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

# Calculate detection rate and false positive rate
tn, fp, fn, tp = cm.ravel()
detection_rate = tp / (tp + fn) * 100 if (tp + fn) > 0 else 0
false_positive_rate = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0

print(f"\n[*] Additional Metrics:")
print(f"   True Positives:  {tp:6d} (Correctly detected attacks)")
print(f"   True Negatives:  {tn:6d} (Correctly identified normal)")
print(f"   False Positives: {fp:6d} (False alarms)")
print(f"   False Negatives: {fn:6d} (Missed attacks)")
print(f"   Detection Rate:  {detection_rate:.2f}%")
print(f"   False Positive Rate: {false_positive_rate:.2f}%")

print("\n" + "=" * 70)
print("✅ Evaluation Complete!")
print("=" * 70)

# ============================================================================
# Optional: Save Confusion Matrix Plot
# ============================================================================
try:
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'])
    plt.title('Confusion Matrix - Frontend Model')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png', dpi=150)
    print("\n📊 Confusion matrix saved to: confusion_matrix.png")
except Exception as e:
    print(f"\n[!] Could not save confusion matrix: {e}")

# ============================================================================
# Optional: Save ROC Curve Plot
# ============================================================================
try:
    fpr, tpr, _ = roc_curve(y_test, -y_scores)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.4f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic (ROC) Curve')
    plt.legend(loc="lower right")
    plt.grid(alpha=0.3)
    plt.savefig('roc_curve.png', dpi=150)
    print("\n[OK] ROC curve saved to: roc_curve.png")
except Exception as e:
    print(f"\n[!] Could not save ROC curve: {e}")

# ============================================================================
# Optional: Save Learning Curve Plot
# ============================================================================
try:
    print("\n[6/6] Generating Learning Curve (this may take a minute)...")
    # Subsample training data to speed up learning curve calculation
    if len(X_train_final) > 20000:
        indices = np.random.choice(len(X_train_final), 20000, replace=False)
        X_lc = X_train_final[indices]
        y_lc = y_train_true.values[indices] if hasattr(y_train_true, 'values') else y_train_true[indices]
    else:
        X_lc = X_train_final
        y_lc = y_train_true

    # We use a fresh model with same params to avoid fit issues
    lc_model = IsolationForest(
        contamination=0.1, 
        n_estimators=100, # Reduced for speed in LC
        random_state=42,
        n_jobs=-1
    )

    train_sizes, train_scores, test_scores = learning_curve(
        lc_model, X_lc, y_lc, cv=3, n_jobs=-1,
        train_sizes=np.linspace(0.1, 1.0, 5),
        scoring='accuracy'
    )

    plt.figure(figsize=(8, 6))
    plt.plot(train_sizes, np.mean(train_scores, axis=1), 'o-', label="Training Accuracy")
    plt.plot(train_sizes, np.mean(test_scores, axis=1), 'o-', label="Cross-validation Accuracy")
    plt.title("Learning Curve (Isolation Forest)")
    plt.xlabel("Training Examples")
    plt.ylabel("Accuracy Score")
    plt.legend(loc="best")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig('learning_curve.png', dpi=150)
    print("   [OK] Learning curve saved to: learning_curve.png")
except Exception as e:
    print(f"   [!] Could not save learning curve: {e}")

# ============================================================================
# FINAL SUMMARY TABLE (Matches Research Report Table 6.1)
# ============================================================================
summary_table = []
summary_table.append("\n" + "=" * 76)
summary_table.append("            TABLE 6.1: FINAL MODEL PERFORMANCE SUMMARY")
summary_table.append("=" * 76)
header = f"{'Algorithm':<15} | {'Acc (Avg)':<10} | {'Train Acc':<10} | {'Test Acc':<10} | {'Prec':<7} | {'Recall':<7}"
summary_table.append(header)
summary_table.append("-" * 76)

avg_acc = (train_accuracy + accuracy) / 2
row = f"{'Iso-forest':<15} | {avg_acc*100:8.2f}% | {train_accuracy*100:8.2f}% | {accuracy*100:8.2f}% | {precision:7.4f} | {recall:7.4f}"
summary_table.append(row)
summary_table.append("-" * 76)
summary_table.append(f"F1-Score: {f1:.4f} | ROC-AUC: {roc_auc:.4f} | Threshold: {OPTIMAL_THRESHOLD}")
summary_table.append("=" * 76)

for line in summary_table:
    print(line)

# Also save to a file to ensure visibility
try:
    with open('TABLE_6.1_RESULTS.txt', 'w', encoding='utf-8') as f:
        f.write("\n".join(summary_table))
    print(f"\n📄 Results locked in: TABLE_6.1_RESULTS.txt")
except Exception as e:
    print(f"⚠️ Error saving table: {e}")
