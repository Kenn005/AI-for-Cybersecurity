import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    RocCurveDisplay
)

from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline


# =========================
# 1. LOAD DATA
# =========================

file_path = "nsl_kdd_train.csv"
df = pd.read_csv(file_path, header=None)

print("Raw dataset shape:", df.shape)


# =========================
# 2. HANDLE NSL-KDD 43 COLUMN ISSUE
# =========================

if df.shape[1] == 43:
    df = df.iloc[:, :-1]

print("Adjusted dataset shape:", df.shape)


# =========================
# 3. COLUMN NAMES
# =========================

df.columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login",
    "count","srv_count","serror_rate","srv_serror_rate","rerror_rate",
    "srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","class"
]


# =========================
# 4. FEATURES & TARGET
# =========================

X = df.drop(columns=["class"])
y = df["class"]

# Binary classification: normal vs attack
y = y.apply(lambda x: 0 if x == "normal" else 1)


# =========================
# 5. TRAIN / TEST SPLIT
# =========================

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# =========================
# 6. COLUMN TYPES
# =========================

categorical_cols = X.select_dtypes(include=["object", "string", "category"]).columns
numeric_cols = X.select_dtypes(exclude=["object", "string", "category"]).columns


# =========================
# 7. PREPROCESSING
# =========================

numeric_transformer = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
    ("scaler", StandardScaler())
])

categorical_transformer = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", OneHotEncoder(handle_unknown="ignore"))
])

preprocess = ColumnTransformer(
    transformers=[
        ("num", numeric_transformer, numeric_cols),
        ("cat", categorical_transformer, categorical_cols)
    ],
    sparse_threshold=0
)


# =========================
# 8. MODEL
# =========================

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


# =========================
# 9. PIPELINE
# =========================

pipeline = ImbPipeline([
    ("preprocess", preprocess),
    ("smote", SMOTE(random_state=42)),
    ("model", model)
])


# =========================
# 10. TRAIN MODEL
# =========================

print("Training IDS model...")
pipeline.fit(X_train, y_train)


# =========================
# 11. PREDICTIONS
# =========================

y_pred = pipeline.predict(X_test)
y_proba = pipeline.predict_proba(X_test)[:, 1]


# =========================
# 12. METRICS
# =========================

print("\n=== IDS PERFORMANCE ===")
print("Accuracy:", accuracy_score(y_test, y_pred))

print("\nPrecision:", precision_score(y_test, y_pred))
print("Recall (CRITICAL IDS METRIC):", recall_score(y_test, y_pred))
print("F1 Score:", f1_score(y_test, y_pred))

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))


# =========================
# 13. CONFUSION MATRIX
# =========================

cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print("\n=== CONFUSION MATRIX ===")
print(cm)

print("\nInterpretation:")
print("TN:", tn, "FP:", fp, "FN:", fn, "TP:", tp)


plt.figure(figsize=(6,5))
sns.heatmap(
        cm,
        annot =True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Normal", "Attack"],
        yticklabels=["Normal","Attack"]
        )
#plt.imshow(cm, cmap="Blues")
plt.title("Confusion Matrix - IDS Model")
#plt.colorbar()
plt.xlabel("Predicted Label")
plt.ylabel("Actual Label")
plt.show()


# =========================
# 14. ROC-AUC
# =========================

auc = roc_auc_score(y_test, y_proba)
print("\nROC-AUC Score:", auc)

RocCurveDisplay.from_predictions(y_test, y_proba)
plt.title("ROC Curve - IDS Model")
plt.show()


# =========================
# 15. FEATURE IMPORTANCE
# =========================

feature_names = pipeline.named_steps["preprocess"].get_feature_names_out()
importances = pipeline.named_steps["model"].feature_importances_

top_idx = np.argsort(importances)[-20:]

plt.figure(figsize=(10,6))
plt.barh(range(len(top_idx)), importances[top_idx])
plt.yticks(range(len(top_idx)), np.array(feature_names)[top_idx])
plt.title("Top 20 Attack Indicators (Feature Importance)")
plt.show()


print("\nIDS Training Completed Successfully.")
