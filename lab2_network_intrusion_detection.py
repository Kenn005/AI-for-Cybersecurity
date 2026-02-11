"""
Network Intrusion Detection System (NIDS) using Random Forest
with recall‑focused threshold tuning (optimized for catching attacks).

Dataset: NSL-KDD (public benchmark)
Approach:
  1. Load & preprocess data (handle categorical features, binary labelling).
  2. Train Random Forest with `class_weight='balanced'` to handle imbalance.
  3. Obtain out‑of‑fold probability estimates on training data via cross‑validation.
  4. Tune decision threshold using Precision‑Recall curve to achieve high recall.
  5. Evaluate final model on a separate test set.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_predict, train_test_split
from sklearn.metrics import precision_recall_curve, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings('ignore')

# -----------------------------
# 1. DATA LOADING (NSL-KDD)
# -----------------------------
# Column names for NSL-KDD (41 features + label + difficulty level)
col_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# URLs for the NSL-KDD dataset (raw text files)
TRAIN_URL = 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt'
TEST_URL  = 'https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt'

print("[INFO] Loading NSL-KDD training data...")
train_df = pd.read_csv(TRAIN_URL, header=None, names=col_names)
print("[INFO] Loading NSL-KDD test data...")
test_df  = pd.read_csv(TEST_URL,  header=None, names=col_names)

# Drop the 'difficulty' column (not used for classification)
train_df.drop('difficulty', axis=1, inplace=True)
test_df.drop('difficulty', axis=1, inplace=True)

# -----------------------------
# 2. BINARY LABELLING
# -----------------------------
# Attack is everything that is not 'normal'
train_df['label'] = (train_df['label'] != 'normal').astype(int)
test_df['label']  = (test_df['label']  != 'normal').astype(int)

# Separate features and target
X_train_raw = train_df.drop('label', axis=1)
y_train = train_df['label']
X_test_raw  = test_df.drop('label', axis=1)
y_test  = test_df['label']

# -----------------------------
# 3. CATEGORICAL ENCODING
# -----------------------------
# Identify categorical columns (type 'object')
cat_cols = X_train_raw.select_dtypes(include=['object']).columns.tolist()
print(f"[INFO] Categorical features: {cat_cols}")

# One‑hot encode the categorical columns.
# Use pd.get_dummies on train and test separately, then align columns.
X_train = pd.get_dummies(X_train_raw, columns=cat_cols, drop_first=False)
X_test  = pd.get_dummies(X_test_raw,  columns=cat_cols, drop_first=False)

# Align test columns to training columns (fill missing with 0)
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

print(f"[INFO] Final feature shape: {X_train.shape}")

# -----------------------------
# 4. RANDOM FOREST WITH CLASS WEIGHT
# -----------------------------
# Use 'balanced' to automatically adjust weights inversely proportional to class frequencies
rf = RandomForestClassifier(
    n_estimators=100,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)

# -----------------------------
# 5. OUT‑OF‑FOLD PROBABILITIES FOR THRESHOLD TUNING
# -----------------------------
print("[INFO] Generating out-of-fold probability estimates (CV=5)...")
# cross_val_predict with method='predict_proba' gives probabilities for each fold
y_probs_cv = cross_val_predict(rf, X_train, y_train, cv=5, method='predict_proba')[:, 1]

# -----------------------------
# 6. THRESHOLD TUNING USING PRECISION‑RECALL CURVE
# -----------------------------
# Goal: achieve very high recall (catch nearly all attacks) while maximising precision.
desired_recall = 0.95  # We want to catch at least 95% of attacks

precisions, recalls, thresholds = precision_recall_curve(y_train, y_probs_cv)

# Find thresholds where recall >= desired_recall (excluding the last element which is 0)
valid_indices = np.where(recalls[:-1] >= desired_recall)[0]
if len(valid_indices) == 0:
    # If no threshold meets the desired recall, pick the one with highest recall
    best_threshold_idx = np.argmax(recalls[:-1])
else:
    # Among those, choose the threshold that gives the highest precision
    best_threshold_idx = valid_indices[np.argmax(precisions[valid_indices])]

best_threshold = thresholds[best_threshold_idx]
print(f"[INFO] Optimal threshold for recall >= {desired_recall:.0%}: {best_threshold:.3f}")
print(f"       -> CV Recall: {recalls[best_threshold_idx]:.3f}, Precision: {precisions[best_threshold_idx]:.3f}")

# -----------------------------
# 7. RETRAIN ON FULL TRAINING DATA
# -----------------------------
print("[INFO] Retraining Random Forest on full training set...")
rf.fit(X_train, y_train)

# -----------------------------
# 8. EVALUATE ON TEST SET WITH TUNED THRESHOLD
# -----------------------------
print("[INFO] Evaluating on test set...")
y_probs_test = rf.predict_proba(X_test)[:, 1]
y_pred_test = (y_probs_test >= best_threshold).astype(int)

print("\n" + "="*60)
print(f" FINAL TEST SET EVALUATION (Threshold = {best_threshold:.3f}) ")
print("="*60)
print(classification_report(y_test, y_pred_test, target_names=['Normal', 'Attack']))

print("\nConfusion Matrix:")
cm = confusion_matrix(y_test, y_pred_test)
print(cm)

# Optional: Show raw numbers
tn, fp, fn, tp = cm.ravel()
print(f"\nTrue Negatives : {tn}")
print(f"False Positives: {fp}  (alerts on normal traffic)")
print(f"False Negatives: {fn}  (MISSED ATTACKS – critical!)")
print(f"True Positives : {tp}")

# -----------------------------
# 9. (OPTIONAL) COMPARE WITH DEFAULT 0.5 THRESHOLD
# -----------------------------
y_pred_default = (y_probs_test >= 0.5).astype(int)
print("\n" + "="*60)
print(" DEFAULT 0.5 THRESHOLD (for comparison) ")
print("="*60)
print(classification_report(y_test, y_pred_default, target_names=['Normal', 'Attack']))
