import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import learning_curve
from sklearn.datasets import make_classification
from sklearn.preprocessing import LabelEncoder
from sklearn.impute import SimpleImputer

# ---------------------------
# Configuration
# ---------------------------
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
POSSIBLE_FILES = [
    os.path.join(DATASET_DIR, "KDDTrain+.txt"),
    os.path.join(DATASET_DIR, "KDDTrain+.csv"),
    os.path.join(DATASET_DIR, "NSL_KDD.csv"),
    os.path.join(DATASET_DIR, "KDDTrain+.data"),
    os.path.join(PROJECT_ROOT, "dataset", "KDDTrain+.txt"),
]

os.makedirs(MODELS_DIR, exist_ok=True)

# ---------------------------
# Helper functions
# ---------------------------
def try_load_nsl_kdd(paths):
    """
    Try to load a KDD-style file from a list of candidate paths.
    Returns a DataFrame or None if not found/parsable.
    """
    for p in paths:
        if os.path.exists(p):
            try:
                # Many KDD files are comma-separated without header
                df = pd.read_csv(p, header=None)
                print(f"[INFO] Loaded dataset from: {p} (shape={df.shape})")
                return df
            except Exception as e:
                print(f"[WARN] Found file but failed to read {p}: {e}")
    return None

def preprocess_kdd_dataframe(df):
    """
    Convert a raw KDD DataFrame (no headers) into numeric features X and raw labels y_raw.
    - Assumes last column is the label.
    - Encodes categorical columns using LabelEncoder.
    - Imputes missing values if any.
    Returns: X (numpy array), y_raw (numpy array of original labels)
    """
    # If df is empty or too small, raise
    if df is None or df.shape[0] < 10:
        raise ValueError("DataFrame is empty or too small for preprocessing.")

    # Last column is label
    y_raw = df.iloc[:, -1].astype(str).values

    # Features are all other columns
    X_df = df.iloc[:, :-1].copy()

    # Identify non-numeric columns and encode them
    for col in X_df.columns:
        if not pd.api.types.is_numeric_dtype(X_df[col]):
            # Convert to string then label encode
            X_df[col] = X_df[col].astype(str)
            le = LabelEncoder()
            try:
                X_df[col] = le.fit_transform(X_df[col])
            except Exception:
                # fallback: map unique values to integers
                mapping = {v: i for i, v in enumerate(pd.unique(X_df[col]))}
                X_df[col] = X_df[col].map(mapping).fillna(-1).astype(int)

    # Impute any missing numeric values
    imputer = SimpleImputer(strategy="median")
    X_num = imputer.fit_transform(X_df)

    return X_num, y_raw

def create_synthetic_dataset(n_samples=3000, n_features=20, random_state=42):
    X, y = make_classification(
        n_samples=n_samples,
        n_features=n_features,
        n_informative=int(n_features * 0.6),
        n_redundant=int(n_features * 0.2),
        n_repeated=0,
        n_classes=2,
        random_state=random_state,
    )
    # Create a synthetic 'service' categorical column for visualization demo
    services = np.random.choice(["http", "ftp", "smtp", "dns", "ssh"], size=X.shape[0])
    df = pd.DataFrame(X, columns=[f"f{i}" for i in range(X.shape[1])])
    df["label"] = np.where(y == 0, "normal", "attack")
    df["service"] = services
    return df

# ---------------------------
# Load dataset (try real file, else synthetic)
# ---------------------------
df_raw = try_load_nsl_kdd(POSSIBLE_FILES)

if df_raw is None:
    print("[INFO] NSL-KDD file not found or unreadable. Using synthetic dataset for demo.")
    df_demo = create_synthetic_dataset(n_samples=3000, n_features=20)
    # For synthetic dataset, label column is 'label'
    X_all = df_demo.drop(columns=["label", "service"], errors="ignore").values
    y_raw = df_demo["label"].values
    df_for_vis = df_demo  # keep for service countplot
else:
    # Preprocess KDD-style DataFrame
    try:
        X_all, y_raw = preprocess_kdd_dataframe(df_raw)
        # For visualization, try to extract a 'service' column if present in original df
        df_for_vis = None
        # If original df had a 'service' like column (categorical), attempt to use it:
        # Many KDD variants have protocol/service/flag in first few columns; try to extract column 2 if exists
        if df_raw.shape[1] >= 3:
            try:
                service_col = df_raw.iloc[:, 2].astype(str)
                df_for_vis = pd.DataFrame({"service": service_col})
            except Exception:
                df_for_vis = None
    except Exception as e:
        print(f"[WARN] Preprocessing failed: {e}. Falling back to synthetic dataset.")
        df_demo = create_synthetic_dataset(n_samples=3000, n_features=20)
        X_all = df_demo.drop(columns=["label", "service"], errors="ignore").values
        y_raw = df_demo["label"].values
        df_for_vis = df_demo

print(f"[INFO] Feature matrix shape: {X_all.shape}, Labels length: {len(y_raw)}")

# ---------------------------
# Map labels for IsolationForest scoring
# ---------------------------
# IsolationForest's predict() returns 1 for inliers (normal) and -1 for outliers (anomaly).
# For supervised scoring (accuracy), we map original labels to 1 (normal) and -1 (attack).
def map_labels_to_if(y_raw_array):
    y_str = np.array([str(v).lower() for v in y_raw_array])
    # Consider 'normal' substring as normal; everything else as attack
    is_normal = np.array([("normal" in s) or (s == "0") or (s == "0.0") for s in y_str])
    y_if = np.where(is_normal, 1, -1)
    return y_if

y_if = map_labels_to_if(y_raw)

# ---------------------------
# Optional: create X_train_normal (only normal samples) if needed
# ---------------------------
X_train_normal = X_all[y_if == 1]
print(f"[INFO] Normal-only training samples: {X_train_normal.shape[0]}")

# ---------------------------
# Visualization: service count (if available)
# ---------------------------
if df_for_vis is not None and "service" in df_for_vis.columns:
    plt.figure(figsize=(12, 5))
    sns.countplot(x="service", data=df_for_vis)
    plt.xticks(rotation=45, ha="right")
    plt.xlabel("Service")
    plt.ylabel("Count")
    plt.title("Count of Services (dataset)")
    plt.tight_layout()
    out_path = os.path.join(MODELS_DIR, "service_count.png")
    plt.savefig(out_path, dpi=150)
    print(f"[INFO] Saved service count plot to: {out_path}")
    plt.show()

# ---------------------------
# Train IsolationForest (fit on full numeric data for demonstration)
# ---------------------------
iso_forest = IsolationForest(
    n_estimators=300,
    contamination=0.1,  # tune this for your dataset
    max_samples="auto",
    random_state=42,
    n_jobs=-1
)

# Fit on all numeric features (unsupervised)
iso_forest.fit(X_all)

# Compute anomaly scores (decision_function: higher -> more normal)
scores = iso_forest.decision_function(X_all)
# For interpretability, we can also get raw predict labels (1 normal, -1 anomaly)
preds_if = iso_forest.predict(X_all)

# Histogram of anomaly scores
plt.figure(figsize=(10, 5))
plt.hist(scores, bins=60, color="steelblue", edgecolor="black")
plt.title("Anomaly Scores Distribution (Isolation Forest)")
plt.xlabel("Anomaly Score (decision_function)")
plt.ylabel("Frequency")
plt.grid(alpha=0.3)
hist_path = os.path.join(MODELS_DIR, "anomaly_scores_hist.png")
plt.tight_layout()
plt.savefig(hist_path, dpi=150)
print(f"[INFO] Saved anomaly scores histogram to: {hist_path}")
plt.show()

# ---------------------------
# Learning curve
# ---------------------------
# Note: IsolationForest is unsupervised. learning_curve expects a supervised estimator interface.
# We can still use learning_curve by providing labels mapped to 1/-1 and letting sklearn fit the estimator.
# The "accuracy" score will compare iso_forest.predict(X) to y_if (1/-1).
#
# Use X_all and y_if for learning_curve so shapes match.
try:
    train_sizes, train_scores, valid_scores = learning_curve(
        iso_forest,
        X_all,
        y_if,
        train_sizes=np.linspace(0.1, 1.0, 8),
        cv=5,
        scoring="accuracy",
        n_jobs=-1,
        shuffle=True,
        random_state=42,
    )

    train_mean = train_scores.mean(axis=1)
    train_std = train_scores.std(axis=1)
    valid_mean = valid_scores.mean(axis=1)
    valid_std = valid_scores.std(axis=1)

    plt.figure(figsize=(10, 6))
    plt.plot(train_sizes, train_mean, color="blue", marker="o", label="Train Accuracy")
    plt.plot(train_sizes, valid_mean, color="green", marker="o", label="Validation Accuracy")
    plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.2, color="blue")
    plt.fill_between(train_sizes, valid_mean - valid_std, valid_mean + valid_std, alpha=0.2, color="green")
    plt.title("Learning Curve for Isolation Forest (accuracy vs train size)")
    plt.xlabel("Training Set Size")
    plt.ylabel("Accuracy")
    plt.legend(loc="best")
    plt.grid(alpha=0.3)
    lc_path = os.path.join(MODELS_DIR, "learning_curve.png")
    plt.tight_layout()
    plt.savefig(lc_path, dpi=150)
    print(f"[INFO] Saved learning curve to: {lc_path}")
    plt.show()
except Exception as e:
    print(f"[WARN] Learning curve generation failed: {e}")
    print("[INFO] You can still inspect anomaly histogram and run custom evaluations.")

# ---------------------------
# Quick evaluation summary (confusion-like counts)
# ---------------------------
# Compare IsolationForest predictions to mapped labels (y_if)
tp = np.sum((preds_if == -1) & (y_if == -1))  # predicted anomaly & true anomaly
tn = np.sum((preds_if == 1) & (y_if == 1))    # predicted normal & true normal
fp = np.sum((preds_if == -1) & (y_if == 1))   # predicted anomaly but true normal
fn = np.sum((preds_if == 1) & (y_if == -1))   # predicted normal but true anomaly

total = len(y_if)
print("\n[SUMMARY]")
print(f"Total samples: {total}")
print(f"True normal (mapped): {np.sum(y_if == 1)}")
print(f"True anomaly (mapped): {np.sum(y_if == -1)}")
print(f"IsolationForest predicted normal: {np.sum(preds_if == 1)}")
print(f"IsolationForest predicted anomaly: {np.sum(preds_if == -1)}")
print(f"TP (pred anomaly & true anomaly): {tp}")
print(f"TN (pred normal & true normal): {tn}")
print(f"FP (pred anomaly but true normal): {fp}")
print(f"FN (pred normal but true anomaly): {fn}")

# Save a small CSV with scores and labels for further analysis
out_scores_df = pd.DataFrame({
    "score": scores,
    "pred_if": preds_if,
    "label_mapped": y_if
})
scores_csv_path = os.path.join(MODELS_DIR, "anomaly_scores_and_labels.csv")
out_scores_df.to_csv(scores_csv_path, index=False)
print(f"[INFO] Saved scores and mapped labels to: {scores_csv_path}")

# End of script
