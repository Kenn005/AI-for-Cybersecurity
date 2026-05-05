import numpy as np
import pandas as pd

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.feature_selection import SelectFromModel
from sklearn.model_selection import cross_val_predict
from sklearn.metrics import precision_recall_curve, classification_report, confusion_matrix

from xgboost import XGBClassifier

import warnings
warnings.filterwarnings("ignore")

# =========================================================
# 1. LOAD DATA
# =========================================================

col_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty'
]

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"

train_df = pd.read_csv(TRAIN_URL, header=None, names=col_names)
test_df  = pd.read_csv(TEST_URL, header=None, names=col_names)

train_df.drop(columns=["difficulty"], inplace=True)
test_df.drop(columns=["difficulty"], inplace=True)

# Binary classification: normal (0) vs attack (1)
train_df["label"] = (train_df["label"] != "normal").astype(int)
test_df["label"]  = (test_df["label"] != "normal").astype(int)

X_train = train_df.drop(columns=["label"])
y_train = train_df["label"]

X_test = test_df.drop(columns=["label"])
y_test = test_df["label"]

# =========================================================
# 2. PREPROCESSING
# =========================================================

categorical_cols = X_train.select_dtypes(include=["object"]).columns
numeric_cols = X_train.columns.difference(categorical_cols)

numeric_transformer = Pipeline(steps=[
    ("imputer", SimpleImputer(strategy="median"))
])

categorical_transformer = Pipeline(steps=[
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", OneHotEncoder(handle_unknown="ignore"))
])

preprocess = ColumnTransformer(
    transformers=[
        ("num", numeric_transformer, numeric_cols),
        ("cat", categorical_transformer, categorical_cols)
    ]
)

# =========================================================
# 3. FEATURE SELECTION (MODEL-BASED, NO LEAKAGE)
# =========================================================

selector_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

feature_selector = SelectFromModel(
    estimator=selector_model,
    threshold="median"   # keep top 50% important features
)

# =========================================================
# 4. FINAL CLASSIFIER
# =========================================================

classifier = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.7,
    colsample_bytree=0.7,
    reg_alpha=1,
    reg_lambda=1,
    scale_pos_weight=2,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

# =========================================================
# 5. FULL PIPELINE
# =========================================================

model = Pipeline(steps=[
    ("preprocess", preprocess),
    ("feature_selection", feature_selector),
    ("classifier", classifier)
])

# =========================================================
# 6. OUT-OF-FOLD PROBABILITIES (CV)
# =========================================================

print("[INFO] Generating out-of-fold predictions...")

y_probs_cv = cross_val_predict(
    model,
    X_train,
    y_train,
    cv=5,
    method="predict_proba",
    n_jobs=-1
)[:, 1]

# =========================================================
# 7. THRESHOLD TUNING (RECALL-FOCUSED)
# =========================================================

precision, recall, thresholds = precision_recall_curve(y_train, y_probs_cv)
precision=precision[:-1]
recall=recall[:-1]
desired_recall = 0.95
valid = np.where(recall[:-1] >= desired_recall)[0]

if len(valid) > 0:
    best_idx = valid[np.argmax(np.abs(recall[valid] - desired_recall))]
else:
    best_idx =np.argmax(recall)
#best_threshold=threshold[best_idx]
best_threshold = thresholds[best_idx]

print(f"[INFO] Selected threshold: {best_threshold:.4f}")
print(f"[INFO] CV Recall: {recall[best_idx]:.3f}, Precision: {precision[best_idx]:.3f}")

# =========================================================
# 8. TRAIN FINAL MODEL
# =========================================================

print("[INFO] Training final model on full dataset...")
model.fit(X_train, y_train)

# =========================================================
# 9. TEST EVALUATION
# =========================================================

y_probs_test = model.predict_proba(X_test)[:, 1]
y_pred_test = (y_probs_test >= best_threshold).astype(int)

print("\n================ FINAL TEST RESULTS ================\n")
print(classification_report(y_test, y_pred_test, target_names=["Normal", "Attack"]))

cm = confusion_matrix(y_test, y_pred_test)
tn, fp, fn, tp = cm.ravel()

print("Confusion Matrix:")
print(cm)

print("\nKey Metrics:")
print(f"True Negatives : {tn}")
print(f"False Positives: {fp}")
print(f"False Negatives: {fn}  (critical misses)")
print(f"True Positives : {tp}")
