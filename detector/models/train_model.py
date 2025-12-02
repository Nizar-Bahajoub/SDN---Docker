import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

# ------- GENERATION DATASET SYNTHETIQUE ---------

N = 6000

# Normal traffic
normal_pkt = np.random.normal(200, 80, N)
normal_bytes = normal_pkt * np.random.uniform(40, 80)
normal_dur = np.random.uniform(0.1, 1.5, N)
normal_arp = np.random.poisson(2, N)
normal_pir = np.random.normal(30, 10, N)

normal = np.vstack([normal_pkt, normal_bytes, normal_dur, normal_arp, normal_pir]).T
normal_label = np.zeros(N)

# Attack traffic
attack_pkt = np.random.normal(4000, 1000, N)
attack_bytes = attack_pkt * np.random.uniform(200, 500)
attack_dur = np.random.uniform(0.01, 0.3, N)
attack_arp = np.random.poisson(120, N)
attack_pir = np.random.normal(600, 150, N)

attack = np.vstack([attack_pkt, attack_bytes, attack_dur, attack_arp, attack_pir]).T
attack_label = np.ones(N)

# Combine
X = np.vstack([normal, attack])
y = np.concatenate([normal_label, attack_label])

# ------- ENTRAINEMENT ---------
clf = RandomForestClassifier(n_estimators=100, max_depth=12)
clf.fit(X, y)

joblib.dump(clf, "model.pkl")
print("✔️ Model saved as model.pkl")
