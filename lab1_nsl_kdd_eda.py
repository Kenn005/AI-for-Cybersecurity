import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
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





#Load NSL-KDD dataset
#Note:This dataset is a standard benchmark for testing IDS

df = pd.read_csv('nsl_kdd_train.csv',names=columns)
print("Dataset loaded successfully")
print("Shape:",df.shape)
#----STEP 1: Data integrity Check---
#In Security, missing logs = blind spots. We must check for null values
print("\n===Missing values check===")
print(df.isnull().sum())#If we see nulls in 'src-bytes',the logging sensors might be broken
print("\n===Basic Statical Summary===")
print(df.describe())

#----STEP 2: 'The Accuracy Trap' Check (imbalance)---
#We visualize how many 'Normal' vs 'Attack' smaples exist.
plt.figure(figsize=(8,5))
sns.countplot(x='class',data=df)

#0=Normal, 1=Attack
# Convert to binary: Normal vs Attack
df['binary_class'] = df['class'].apply(lambda x: 'Normal' if x == 0 else 'Attack')
sns.countplot(x='binary_class', data=df)
plt.title('Normal vs Attack Traffic Distribution')
plt.ylabel('Number of Network Connections')
plt.show()

#NOTE:If 'Attack' is a tiny silver,we must techniques like SMOTE
#or focus on 'Recall' rather than 'Accuracy'
#----STEP: Feature Correlation (The "Smoking Gun")----
#We want to see which network behaviours are linked to attacks.
#We pick a subset of numeerical features to avoid overwhelming heatmap.




security_features=['duration','src_bytes','dst_bytes','wrong_fragment','label']
df[security_features]= df[security_features].apply(pd.to_numeric,errors='coerce')
correlation=df[security_features].dropna().corr()
plt.figure(figsize=(10,8))
sns.heatmap(correlation,annot=True,cmap='coolwarm',fmt=".2f",linewidths=0.5)
plt.title('Correlation Matrix:Indentifying Attack Indicators')
plt.tight_layout()
plt.show()

print("\nSample Records:")
print(df[['protocol_type', 'service','flag','class','label']].head())

#INTERPRETATION: if 'wrong_fragments' has a high correlation with 'label',
#it means fragmented packets are a strong indicator of a tear drop attack


