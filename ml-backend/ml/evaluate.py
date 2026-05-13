"""
Évaluation comparative : AI Risk Score vs CVSS baseline.
Métriques : précision, rappel, F1, AUC-ROC, gain opérationnel.
"""
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import (precision_score, recall_score, f1_score,
                              confusion_matrix, roc_curve, roc_auc_score)
from ml.features import FEATURE_COLS

ROOT = Path(__file__).parent.parent
df = pd.read_csv(ROOT / "data" / "real_findings.csv")

# Charger modèle
model = joblib.load(ROOT / "models" / "risk_model.joblib")

# Prédire (probabilité d'être Critical)
X = df[FEATURE_COLS].values
probas = model.predict_proba(X)
df['ai_score'] = probas[:, -1] * 100   # score 0-100
df['cvss'] = df['cvss_score']
df['label'] = df['exploited']

# Approche 1 : seuillage simple
ai_pred   = (df['ai_score'] > 70).astype(int)
cvss_pred = (df['cvss']     >= 7).astype(int)

print("=== Approche 1 : seuillage ===")
print(f"AI    — P={precision_score(df.label, ai_pred):.3f}  R={recall_score(df.label, ai_pred):.3f}  F1={f1_score(df.label, ai_pred):.3f}")
print(f"CVSS  — P={precision_score(df.label, cvss_pred):.3f}  R={recall_score(df.label, cvss_pred):.3f}  F1={f1_score(df.label, cvss_pred):.3f}")

# Approche 2 : courbe ROC
fpr_ai, tpr_ai, _ = roc_curve(df.label, df.ai_score)
fpr_cv, tpr_cv, _ = roc_curve(df.label, df.cvss)
auc_ai = roc_auc_score(df.label, df.ai_score)
auc_cv = roc_auc_score(df.label, df.cvss)

print(f"=== AUC-ROC ===")
print(f"AI   : {auc_ai:.3f}")
print(f"CVSS : {auc_cv:.3f}")

# Approche 3 (LA métrique opérationnelle) :
# Combien de findings traiter (triés) pour couvrir 80 % des vulns exploitées ?
def workload_at_recall(df_sorted, target=0.8):
    cum_recall = df_sorted['label'].cumsum() / df_sorted['label'].sum()
    return (cum_recall >= target).idxmax() - df_sorted.index[0] + 1

df_ai   = df.sort_values('ai_score', ascending=False).reset_index(drop=True)
df_cvss = df.sort_values('cvss',     ascending=False).reset_index(drop=True)

w_ai   = workload_at_recall(df_ai)
w_cvss = workload_at_recall(df_cvss)
gain   = 1 - w_ai / w_cvss

print(f"=== Gain opérationnel (80 % de recall) ===")
print(f"AI   : {w_ai:5d} findings à traiter")
print(f"CVSS : {w_cvss:5d} findings à traiter")
print(f"Gain : {gain:.1%} de charge en moins avec l'IA")
