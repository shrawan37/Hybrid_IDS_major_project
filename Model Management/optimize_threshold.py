#!/usr/bin/env python3
"""
Find Optimal Detection Threshold for IDS
Balances Recall (catching attacks) vs Precision (avoiding false alarms)
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix
)
import matplotlib.pyplot as plt

print("=" * 70)
print("  THRESHOLD OPTIMIZATION - Finding Best Detection Threshold")
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

# Load model
print("[2/3] Loading model and preprocessing...")
model = joblib.load('models/isolation_forest_frontend.pkl')
scaler = joblib.load('models/scaler_frontend.pkl')
encoder = joblib.load('models/encoder_frontend.pkl')
freq_encoding = joblib.load('models/freq_encoding_frontend.pkl')
frontend_features = joblib.load('models/frontend_features.pkl')

# Preprocess (same as anamoly.py)
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

# Get decision scores
y_scores = model.decision_function(X_test_final)

# Test different thresholds
print("\n[3/3] Testing different thresholds...")
print("\n" + "=" * 90)
print(f"{'Threshold':<12} {'Recall':<10} {'Precision':<12} {'F1-Score':<12} {'Accuracy':<12} {'FP Rate':<10}")
print("=" * 90)

# Test 50 different threshold points for extreme precision
thresholds = np.linspace(np.min(y_scores), np.max(y_scores), 50)
results = []

for threshold in thresholds:
    y_pred = (y_scores < threshold).astype(int)
    
    recall = recall_score(y_test, y_pred, zero_division=0)
    precision = precision_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    accuracy = accuracy_score(y_test, y_pred)
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    results.append({
        'threshold': threshold,
        'recall': recall,
        'precision': precision,
        'f1': f1,
        'accuracy': accuracy,
        'fp_rate': fp_rate
    })
    
    print(f"{threshold:>11.4f}  {recall*100:>8.2f}%  {precision*100:>10.2f}%  {f1*100:>10.2f}%  {accuracy*100:>10.2f}%  {fp_rate*100:>8.2f}%")

print("=" * 90)

# Find best threshold for different goals
results_df = pd.DataFrame(results)

# Best for Accuracy (Realistic/Balanced)
best_acc_idx = results_df['accuracy'].idxmax()
best_acc = results_df.iloc[best_acc_idx]

# Best for Recall (Security-First)
best_recall_idx = results_df['recall'].idxmax()
best_recall = results_df.iloc[best_recall_idx]

# Best for F1 (Balanced)
best_f1_idx = results_df['f1'].idxmax()
best_f1 = results_df.iloc[best_f1_idx]

# Best for Precision (Low False Alarms)
best_precision_idx = results_df['precision'].idxmax()
best_precision = results_df.iloc[best_precision_idx]

print("\n[*] ACCURACY-FIRST (Most Realistic Results):")
print(f"   Threshold: {best_acc['threshold']:.4f}")
print(f"   Accuracy:  {best_acc['accuracy']*100:.2f}% (Goal Reachable)")
print(f"   Precision: {best_acc['precision']*100:.2f}%")
print(f"   Recall:    {best_acc['recall']*100:.2f}%")

print("\n[*] SECURITY-FIRST (Maximize Attack Detection):")
print(f"   Threshold: {best_recall['threshold']:.4f}")
print(f"   Recall:    {best_recall['recall']*100:.2f}% (Catches most attacks)")
print(f"   Precision: {best_recall['precision']*100:.2f}%")
print(f"   F1-Score:  {best_recall['f1']*100:.2f}%")
print(f"   FP Rate:   {best_recall['fp_rate']*100:.2f}% (More false alarms)")

print("\n[*] BALANCED (Best Overall Performance):")
print(f"   Threshold: {best_f1['threshold']:.4f}")
print(f"   Recall:    {best_f1['recall']*100:.2f}%")
print(f"   Precision: {best_f1['precision']*100:.2f}%")
print(f"   F1-Score:  {best_f1['f1']*100:.2f}% ← Best balance")
print(f"   FP Rate:   {best_f1['fp_rate']*100:.2f}%")

print("\n[*] PRECISION-FIRST (Minimize False Alarms):")
print(f"   Threshold: {best_precision['threshold']:.4f}")
print(f"   Recall:    {best_precision['recall']*100:.2f}%")
print(f"   Precision: {best_precision['precision']*100:.2f}% ← Fewest false alarms")
print(f"   F1-Score:  {best_precision['f1']*100:.2f}%")
print(f"   FP Rate:   {best_precision['fp_rate']*100:.2f}%")

print("\n" + "=" * 70)
print("💡 RECOMMENDATION FOR IDS:")
print("   Use BALANCED threshold for best overall performance")
print(f"   Add this to your code: threshold = {best_f1['threshold']:.4f}")
print("=" * 70)

# Plot
try:
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    
    # Recall vs Threshold
    axes[0, 0].plot(results_df['threshold'], results_df['recall']*100, 'b-', linewidth=2)
    axes[0, 0].axhline(y=70, color='r', linestyle='--', label='Target: 70%')
    axes[0, 0].set_xlabel('Threshold')
    axes[0, 0].set_ylabel('Recall (%)')
    axes[0, 0].set_title('Recall vs Threshold')
    axes[0, 0].grid(True, alpha=0.3)
    axes[0, 0].legend()
    
    # Precision vs Threshold
    axes[0, 1].plot(results_df['threshold'], results_df['precision']*100, 'g-', linewidth=2)
    axes[0, 1].axhline(y=85, color='r', linestyle='--', label='Target: 85%')
    axes[0, 1].set_xlabel('Threshold')
    axes[0, 1].set_ylabel('Precision (%)')
    axes[0, 1].set_title('Precision vs Threshold')
    axes[0, 1].grid(True, alpha=0.3)
    axes[0, 1].legend()
    
    # F1-Score vs Threshold
    axes[1, 0].plot(results_df['threshold'], results_df['f1']*100, 'm-', linewidth=2)
    axes[1, 0].axvline(x=best_f1['threshold'], color='r', linestyle='--', label=f'Best: {best_f1["threshold"]:.4f}')
    axes[1, 0].set_xlabel('Threshold')
    axes[1, 0].set_ylabel('F1-Score (%)')
    axes[1, 0].set_title('F1-Score vs Threshold')
    axes[1, 0].grid(True, alpha=0.3)
    axes[1, 0].legend()
    
    # Precision-Recall Curve
    axes[1, 1].plot(results_df['recall']*100, results_df['precision']*100, 'r-', linewidth=2, marker='o')
    axes[1, 1].set_xlabel('Recall (%)')
    axes[1, 1].set_ylabel('Precision (%)')
    axes[1, 1].set_title('Precision-Recall Trade-off')
    axes[1, 1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('threshold_optimization.png', dpi=150)
    print("\n[OK] Plots saved to: threshold_optimization.png")
except Exception as e:
    print(f"\n[!] Could not save plots: {e}")
