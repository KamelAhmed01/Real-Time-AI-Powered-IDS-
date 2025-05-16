import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os

# Define file paths relative to the script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BENIGN_CSV = os.path.join(SCRIPT_DIR, 'flows_benign.csv')
ATTACK_CSV = os.path.join(SCRIPT_DIR, 'flows_attack.csv')
MODEL_FILE = os.path.join(SCRIPT_DIR, 'ids_model.pkl')

# Load benign data
print(f"Loading benign data from {BENIGN_CSV}...")
df_base = pd.read_csv(BENIGN_CSV)
features = ['duration', 'src2dst_packets', 'dst2src_packets', 'src2dst_bytes', 'dst2src_bytes']

# Ensure all required features are present
missing_features = [f for f in features if f not in df_base.columns]
if missing_features:
    print(f"Error: Missing features in {BENIGN_CSV}: {missing_features}")
    exit(1)

X = df_base[features]

# Train model
print("Training Isolation Forest model...")
model = IsolationForest(contamination=0.05, random_state=42) # Contamination can be tuned
model.fit(X)
joblib.dump(model, MODEL_FILE)
print(f"Model saved to {MODEL_FILE}")

# Validate with attack data (optional, but good for a sanity check)
if os.path.exists(ATTACK_CSV):
    print(f"Loading attack data from {ATTACK_CSV} for validation...")
    df_anomaly = pd.read_csv(ATTACK_CSV)
    missing_features_attack = [f for f in features if f not in df_anomaly.columns]
    if missing_features_attack:
        print(f"Warning: Missing features in {ATTACK_CSV}: {missing_features_attack}. Skipping validation with this file.")
    else:
        X_anomaly = df_anomaly[features]
        predictions = model.predict(X_anomaly)
        anomalies = (predictions == -1).sum()
        print(f"Validation: Detected {anomalies} anomalies out of {len(X_anomaly)} flows in the attack dataset.")
else:
    print(f"Attack data file {ATTACK_CSV} not found. Skipping validation step.")

print("Training script finished.")

