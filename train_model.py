import pandas as pd
import numpy as np
import os
import pickle
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from xgboost import XGBClassifier
import warnings
warnings.filterwarnings('ignore')

os.makedirs('models', exist_ok=True)

# NSL-KDD column names
COLUMNS = [
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

ATTACK_MAP = {
    'normal': 'normal',
    'neptune': 'DoS', 'back': 'DoS', 'land': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS',
    'processtable': 'DoS', 'udpstorm': 'DoS',
    'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 'satan': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'imap': 'R2L', 'multihop': 'R2L',
    'phf': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L', 'warezmaster': 'R2L',
    'sendmail': 'R2L', 'named': 'R2L', 'snmpgetattack': 'R2L', 'snmpguess': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'worm': 'R2L',
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'rootkit': 'U2R',
    'httptunnel': 'U2R', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R'
}

print("=" * 55)
print("   NETSENTINEL AI — ML MODEL TRAINING")
print("=" * 55)

# ─── LOAD DATA ───────────────────────────────────────────
print("\n📂 Loading datasets...")
train_df = pd.read_csv('datasets/KDDTrain+.txt', names=COLUMNS)
test_df = pd.read_csv('datasets/KDDTest+.txt', names=COLUMNS)
df = pd.concat([train_df, test_df], ignore_index=True)
print(f"✅ Total records loaded: {len(df):,}")

# ─── PREPROCESSING ───────────────────────────────────────
print("\n⚙️  Preprocessing data...")
df['label'] = df['label'].str.strip().str.lower()
df['attack_category'] = df['label'].map(ATTACK_MAP).fillna('Unknown')
df = df[df['attack_category'] != 'Unknown']
df.drop('difficulty', axis=1, inplace=True)

# Encode categorical columns
cat_cols = ['protocol_type', 'service', 'flag']
encoders = {}
for col in cat_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le

# Binary label: 0 = normal, 1 = attack
df['binary_label'] = (df['attack_category'] != 'normal').astype(int)

# Category label encoder
cat_le = LabelEncoder()
df['category_label'] = cat_le.fit_transform(df['attack_category'])

feature_cols = [c for c in df.columns if c not in ['label', 'attack_category', 'binary_label', 'category_label']]
X = df[feature_cols]
y_binary = df['binary_label']
y_category = df['category_label']

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, yb_train, yb_test, yc_train, yc_test = train_test_split(
    X_scaled, y_binary, y_category, test_size=0.2, random_state=42
)

print(f"✅ Features: {len(feature_cols)}")
print(f"✅ Training samples: {len(X_train):,}")
print(f"✅ Testing samples: {len(X_test):,}")

# ─── MODEL 1: RANDOM FOREST ──────────────────────────────
print("\n🌲 Training Random Forest (known attack classifier)...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train, yb_train)
rf_pred = rf_model.predict(X_test)
rf_acc = accuracy_score(yb_test, rf_pred)
print(f"✅ Random Forest Accuracy: {rf_acc * 100:.2f}%")

# ─── MODEL 2: XGBOOST ────────────────────────────────────
print("\n⚡ Training XGBoost (CVE severity predictor)...")
xgb_model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    eval_metric='logloss',
    verbosity=0
)
xgb_model.fit(X_train, yb_train)
xgb_pred = xgb_model.predict(X_test)
xgb_acc = accuracy_score(yb_test, xgb_pred)
print(f"✅ XGBoost Accuracy: {xgb_acc * 100:.2f}%")

# ─── MODEL 3: ISOLATION FOREST (Zero-Day) ────────────────
print("\n🔍 Training Isolation Forest (zero-day anomaly detector)...")
X_normal = X_scaled[df['binary_label'] == 0]
iso_model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
iso_model.fit(X_normal)

# Evaluate on test set
iso_pred_raw = iso_model.predict(X_test)
iso_pred = (iso_pred_raw == -1).astype(int)  # -1 = anomaly = attack
iso_acc = accuracy_score(yb_test, iso_pred)
print(f"✅ Isolation Forest Accuracy: {iso_acc * 100:.2f}%")

# ─── ENSEMBLE FUNCTION ───────────────────────────────────
print("\n🧠 Building Ensemble Voting Model...")

def ensemble_predict(X_input):
    rf_p = rf_model.predict(X_input)
    xgb_p = xgb_model.predict(X_input)
    iso_p = (iso_model.predict(X_input) == -1).astype(int)
    # Majority vote
    votes = rf_p + xgb_p + iso_p
    return (votes >= 2).astype(int)

ensemble_pred = ensemble_predict(X_test)
ensemble_acc = accuracy_score(yb_test, ensemble_pred)
print(f"✅ Ensemble Accuracy: {ensemble_acc * 100:.2f}%")

# ─── RESULTS SUMMARY ─────────────────────────────────────
print("\n" + "=" * 55)
print("   MODEL PERFORMANCE SUMMARY")
print("=" * 55)
print(f"  🌲 Random Forest     : {rf_acc * 100:.2f}%")
print(f"  ⚡ XGBoost           : {xgb_acc * 100:.2f}%")
print(f"  🔍 Isolation Forest  : {iso_acc * 100:.2f}%")
print(f"  🧠 Ensemble (Final)  : {ensemble_acc * 100:.2f}%")
print("=" * 55)

# ─── SAVE MODELS ─────────────────────────────────────────
print("\n💾 Saving models...")
with open('models/rf_model.pkl', 'wb') as f:
    pickle.dump(rf_model, f)
with open('models/xgb_model.pkl', 'wb') as f:
    pickle.dump(xgb_model, f)
with open('models/iso_model.pkl', 'wb') as f:
    pickle.dump(iso_model, f)
with open('models/scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
with open('models/encoders.pkl', 'wb') as f:
    pickle.dump(encoders, f)
with open('models/feature_cols.pkl', 'wb') as f:
    pickle.dump(feature_cols, f)

print("✅ All models saved to /models/")
print("\n🚀 NetSentinel AI ML models ready!")