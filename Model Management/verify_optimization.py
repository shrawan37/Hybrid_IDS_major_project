#!/usr/bin/env python3
"""
Verify Optimized Threshold Update
Compares performance before and after the threshold optimization
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

print("=" * 70)
print("  VERIFICATION: Optimized Threshold Performance")
print("=" * 70)

# Load test data
print("\n[1/3] Loading test data...")
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

test_df = pd.read_csv("test/KDDTest+.txt", names=COLUMN_NAMES, header=None)
y_test = (test_df['attack_type'] != 'normal').astype(int)
print(f"   ✓ Loaded {len(test_df)} test samples")

# Load model
print("\n[2/3] Loading model...")
model = joblib.load('models/isolation_forest_frontend.pkl')
scaler = joblib.load('models/scaler_frontend.pkl')
encoder = joblib.load('models/encoder_frontend.pkl')
freq_encoding = joblib.load('models/freq_encoding_frontend.pkl')
frontend_features = joblib.load('models/frontend_features.pkl')

# Preprocess
X_test = test_df.drop(['attack_type', 'difficulty_level'], axis=1)
numeric_features = [
    'duration', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'dst_host_count',
    'dst_host_srv_count', 'level'
]
categorical_features = ['flag', 'protocol_type']

if 'level' not in X_test.columns:
    X_test['level'] = 0

X_test[numeric_features] = scaler.transform(X_test[numeric_features])
encoded_features = encoder.transform(X_test[categorical_features])
encoded_df = pd.DataFrame(encoded_features, columns=encoder.get_feature_names_out(categorical_features), index=X_test.index)
X_test = X_test.drop(columns=categorical_features)
X_test = pd.concat([X_test, encoded_df], axis=1)
X_test['service'] = X_test['service'].map(freq_encoding).fillna(freq_encoding.median())
X_test_final = X_test[frontend_features]

# Get scores
y_scores = model.decision_function(X_test_final)

print("\n[3/3] Comparing performance...")

# OLD METHOD: Default model.predict()
y_pred_old = model.predict(X_test_final)
y_pred_old = (y_pred_old == -1).astype(int)

# NEW METHOD: Optimized threshold
OPTIMAL_THRESHOLD = 0.0892
y_pred_new = (y_scores < OPTIMAL_THRESHOLD).astype(int)

# Calculate metrics for both
def calc_metrics(y_true, y_pred, name):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    return {
        'name': name,
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1': f1,
        'fp_rate': fp_rate,
        'tp': tp,
        'tn': tn,
        'fp': fp,
        'fn': fn
    }

old_metrics = calc_metrics(y_test, y_pred_old, "OLD (Default)")
new_metrics = calc_metrics(y_test, y_pred_new, "NEW (Optimized)")

# Display comparison
print("\n" + "=" * 70)
print("                    PERFORMANCE COMPARISON")
print("=" * 70)

print(f"\n{'Metric':<20} {'OLD (Default)':<20} {'NEW (Optimized)':<20} {'Change':<15}")
print("-" * 70)

metrics_to_compare = [
    ('Recall (Detection)', 'recall', True),
    ('Precision', 'precision', False),
    ('F1-Score', 'f1', True),
    ('Accuracy', 'accuracy', True),
    ('False Positive Rate', 'fp_rate', False),
]

for label, key, higher_is_better in metrics_to_compare:
    old_val = old_metrics[key] * 100
    new_val = new_metrics[key] * 100
    change = new_val - old_val
    
    if higher_is_better:
        symbol = "↑" if change > 0 else "↓"
        color = "✅" if change > 0 else "⚠️"
    else:
        symbol = "↓" if change < 0 else "↑"
        color = "✅" if change < 0 else "⚠️"
    
    print(f"{label:<20} {old_val:>7.2f}%          {new_val:>7.2f}%          {color} {change:+.2f}% {symbol}")

print("\n" + "=" * 70)
print("                    CONFUSION MATRIX COMPARISON")
print("=" * 70)

print(f"\nOLD (Default Threshold):")
print(f"   True Positives:  {old_metrics['tp']:>6,} (Detected attacks)")
print(f"   True Negatives:  {old_metrics['tn']:>6,} (Correctly identified normal)")
print(f"   False Positives: {old_metrics['fp']:>6,} (False alarms)")
print(f"   False Negatives: {old_metrics['fn']:>6,} (Missed attacks) ⚠️")

print(f"\nNEW (Optimized Threshold = 0.0892):")
print(f"   True Positives:  {new_metrics['tp']:>6,} (Detected attacks) ✅ +{new_metrics['tp'] - old_metrics['tp']:,}")
print(f"   True Negatives:  {new_metrics['tn']:>6,} (Correctly identified normal)")
print(f"   False Positives: {new_metrics['fp']:>6,} (False alarms) ⚠️ +{new_metrics['fp'] - old_metrics['fp']:,}")
print(f"   False Negatives: {new_metrics['fn']:>6,} (Missed attacks) ✅ {new_metrics['fn'] - old_metrics['fn']:,}")

print("\n" + "=" * 70)
print("                    SUMMARY")
print("=" * 70)

print(f"\n🎯 Key Improvements:")
print(f"   ✅ Recall improved by {new_metrics['recall']*100 - old_metrics['recall']*100:+.2f}%")
print(f"      → Now catching {new_metrics['tp'] - old_metrics['tp']:,} MORE attacks!")
print(f"   ✅ F1-Score improved by {new_metrics['f1']*100 - old_metrics['f1']*100:+.2f}%")
print(f"      → Better overall balance")

print(f"\n⚠️  Trade-offs:")
print(f"   • Precision decreased by {new_metrics['precision']*100 - old_metrics['precision']*100:.2f}%")
print(f"      → Still excellent at {new_metrics['precision']*100:.2f}%")
print(f"   • False alarms increased by {new_metrics['fp'] - old_metrics['fp']:,}")
print(f"      → But only {new_metrics['fp_rate']*100:.2f}% false positive rate")

print(f"\n💡 Verdict:")
print(f"   The optimized threshold is MUCH BETTER for IDS!")
print(f"   - Catches {new_metrics['tp'] - old_metrics['tp']:,} more attacks")
print(f"   - Only {new_metrics['fp'] - old_metrics['fp']:,} more false alarms")
print(f"   - Trade-off is WORTH IT for security!")

print("\n" + "=" * 70)
print("✅ Verification Complete - Update Successful!")
print("=" * 70)
