import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# -------------------------------
# Column names for NSL-KDD
# -------------------------------
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate',
    'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate',
    'dst_host_srv_rerror_rate','class'
]

# -------------------------------
# Load dataset
# -------------------------------
df = pd.read_csv('nsl_kdd_train.csv', names=columns)

print("Dataset loaded successfully")
print("Shape:", df.shape)

# -------------------------------
# STEP 1: Data Integrity Check
# -------------------------------
print("\n=== Missing Values Check ===")
print(df.isnull().sum())

print("\n=== Basic Statistical Summary ===")
print(df.describe())

# -------------------------------
# STEP 2: Class Imbalance Analysis
# -------------------------------

# Convert to binary label
# normal = 0, attack = 1
df['binary_label'] = df['class'].apply(
    lambda x: 0 if 'normal' in str(x).lower() else 1
)




print("\nBinary Label Distribution:")
print(df['binary_label'].value_counts())

plt.figure(figsize=(6,4))
sns.countplot(x='binary_label', data=df)
plt.title('Normal vs Attack Traffic Distribution')
plt.xlabel('Traffic Type (0 = Normal, 1 = Attack)')
plt.ylabel('Number of Network Connections')
plt.show()


# -------------------------------
# STEP 3: Correlation Analysis
# -------------------------------
security_features = [
    'duration',
    'src_bytes',
    'dst_bytes',
    'wrong_fragment',
    'binary_label'
]

df[security_features] = df[security_features].apply(
    pd.to_numeric, errors='coerce'
)

correlation = df[security_features].corr()

plt.figure(figsize=(8,6))
sns.heatmap(correlation, annot=True, fmt=".2f", cmap='coolwarm')
plt.title('Correlation with Binary Attack Label')
plt.tight_layout()
plt.show()

# -------------------------------
# Sample Records
# -------------------------------
print("\nSample Records:")
print(df[['protocol_type', 'service', 'flag', 'class', 'binary_label']].head())
