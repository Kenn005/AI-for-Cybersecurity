"""
Full Pipeline: PE Malware Detection using Gradient Boosting
-----------------------------------------------------------
Extracts features from Windows Portable Executable (PE) files:
  - Number of sections
  - Entropy of the .text section (packing / encryption indicator)
  - Count of suspicious imported API functions
  - (Additional features can be easily added)

Workflow:
  1. Recursively scan directories containing 'benign' and 'malicious' PE files.
  2. Extract feature vectors and corresponding labels.
  3. Train a GradientBoostingClassifier.
  4. Evaluate on a hold‑out test set.
  5. Save the trained model for future predictions on unknown files.

Dependencies: pefile, scikit-learn, joblib, numpy
Install: pip install pefile scikit-learn joblib numpy
"""

import os
import math
import numpy as np
import pefile
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# ----------------------------------------------------------------------
# Feature Extraction Functions
# ----------------------------------------------------------------------

def calculate_entropy(data):
    """Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    data_len = len(data)
    for x in range(256):
        p_x = data.count(x) / data_len
        if p_x > 0:
            entropy -= p_x * math.log(p_x, 2)
    return entropy

def extract_pe_features(file_path):
    """
    Extract a feature vector from a PE file.
    Returns a list of numerical features or None if parsing fails.
    """
    try:
        pe = pefile.PE(file_path)

        # --- 1. Number of sections ---
        n_sections = len(pe.sections)

        # --- 2. Entropy of the .text section (if present) ---
        text_section = None
        for section in pe.sections:
            if b'.text' in section.Name:
                text_section = section
                break
        entropy = calculate_entropy(text_section.get_data()) if text_section else 0.0

        # --- 3. Count of suspicious imports ---
        SUSPICIOUS_APIS = {
            'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'HttpSendRequest',
            'URLDownloadToFile', 'WinExec', 'ShellExecute', 'CreateProcess',
            'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread',
            'OpenProcess', 'VirtualAllocEx', 'VirtualProtectEx',
            'GetProcAddress', 'LoadLibrary', 'LdrLoadDll'
        }
        suspicious_imports = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name and imp.name.decode() in SUSPICIOUS_APIS:
                        suspicious_imports += 1

        # --- 4. Additional features (optional) ---
        # Check if the file has a valid digital signature (simple indicator)
        has_signature = int(hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'))

        # Return the feature vector
        return [
            n_sections,
            entropy,
            suspicious_imports,
            has_signature,
            # You can add more features here:
            # - Size of code section
            # - Number of resources
            # - Entropy of other sections
            # - etc.
        ]

    except Exception as e:
        print(f"[!] Error processing {file_path}: {e}")
        return None

# ----------------------------------------------------------------------
# Dataset Loading
# ----------------------------------------------------------------------

def load_dataset(benign_dir, malicious_dir):
    """
    Walk through the given directories, extract features from each PE file,
    and return a feature matrix X and label vector y.
    Assumes subdirectories contain the actual PE files.
    """
    X = []
    y = []
    files_processed = 0

    # Process benign files (label = 0)
    for root, dirs, files in os.walk(benign_dir):
        for file in files:
            file_path = os.path.join(root, file)
            feats = extract_pe_features(file_path)
            if feats is not None:
                X.append(feats)
                y.append(0)
                files_processed += 1
                if files_processed % 100 == 0:
                    print(f"[+] Processed {files_processed} files...")

    # Process malicious files (label = 1)
    for root, dirs, files in os.walk(malicious_dir):
        for file in files:
            file_path = os.path.join(root, file)
            feats = extract_pe_features(file_path)
            if feats is not None:
                X.append(feats)
                y.append(1)
                files_processed += 1
                if files_processed % 100 == 0:
                    print(f"[+] Processed {files_processed} files...")

    print(f"[+] Total files successfully processed: {files_processed}")
    return np.array(X), np.array(y)

# ----------------------------------------------------------------------
# Training & Evaluation
# ----------------------------------------------------------------------

def train_and_evaluate(X, y):
    """Train a GradientBoostingClassifier and evaluate on a test split."""
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Initialize model (adjust hyperparameters for recall if desired)
    model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.1,
        random_state=42
    )

    # Train
    print("[+] Training Gradient Boosting model...")
    model.fit(X_train, y_train)

    # Predict on test set
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    # Evaluation
    print("\n" + "="*60)
    print("CLASSIFICATION REPORT (Test Set)")
    print("="*60)
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    # Optional: threshold tuning for high recall
    # (as shown in the NIDS example, can be applied here too)

    return model

# ----------------------------------------------------------------------
# Main Execution
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # ------------------------------------------------------------------
    # CONFIGURATION – CHANGE THESE PATHS TO MATCH YOUR DATASET
    # ------------------------------------------------------------------
    BENIGN_DIR = "./dataset/benign"      # Folder containing benign PE files
    MALICIOUS_DIR = "./dataset/malicious" # Folder containing malicious PE files
    MODEL_SAVE_PATH = "pe_gb_model.pkl"

    # ------------------------------------------------------------------
    # Step 1: Load dataset and extract features
    # ------------------------------------------------------------------
    if not os.path.exists(BENIGN_DIR) or not os.path.exists(MALICIOUS_DIR):
        print("[!] Dataset directories not found.")
        print("    Please adjust BENIGN_DIR and MALICIOUS_DIR variables.")
        print("    For demonstration, creating a synthetic dummy dataset.\n")

        # --- Dummy data generation for demonstration only ---
        np.random.seed(42)
        n_samples = 500
        # Simulate features (n_sections, entropy, suspicious_imports, has_signature)
        X_synth = np.random.rand(n_samples, 4) * [10, 8, 20, 1]
        X_synth = X_synth.astype(float)
        X_synth[:, 3] = np.random.randint(0, 2, n_samples)  # signature binary
        y_synth = np.random.randint(0, 2, n_samples)
        print("[!] Using SYNTHETIC data – replace with real PE files for meaningful results.\n")
        X, y = X_synth, y_synth
        # --------------------------------------------------------
    else:
        print("[+] Loading real PE dataset...")
        X, y = load_dataset(BENIGN_DIR, MALICIOUS_DIR)
        if len(X) == 0:
            print("[!] No valid PE files found. Exiting.")
            exit(1)

    # ------------------------------------------------------------------
    # Step 2: Train and evaluate
    # ------------------------------------------------------------------
    model = train_and_evaluate(X, y)

    # ------------------------------------------------------------------
    # Step 3: Save the trained model for later use
    # ------------------------------------------------------------------
    joblib.dump(model, MODEL_SAVE_PATH)
    print(f"\n[+] Model saved to {MODEL_SAVE_PATH}")

    # ------------------------------------------------------------------
    # Step 4: Example prediction on a new file
    # ------------------------------------------------------------------
    def predict_file(file_path, model_path=MODEL_SAVE_PATH):
        """Load model and predict a single PE file."""
        if not os.path.exists(model_path):
            print("[!] Model file not found.")
            return
        clf = joblib.load(model_path)
        feats = extract_pe_features(file_path)
        if feats is None:
            print("[!] Could not extract features.")
            return
        feats = np.array(feats).reshape(1, -1)
        proba = clf.predict_proba(feats)[0][1]  # probability of malicious
        pred = clf.predict(feats)[0]
        label = "Malicious" if pred == 1 else "Benign"
        print(f"\n--- Prediction for {file_path} ---")
        print(f"Features: {feats.tolist()[0]}")
        print(f"Prediction: {label} (confidence: {proba:.3f})")
        return pred, proba

    # Uncomment to test on a specific file after training
    # predict_file("path/to/unknown_file.exe")
