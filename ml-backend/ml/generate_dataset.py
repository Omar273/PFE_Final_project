"""
ml/generate_dataset.py
──────────────────────
Génère un dataset synthétique réaliste de findings DefectDojo,
puis le nettoie et le sauvegarde dans data/findings_clean.csv.

Basé sur les features utilisées dans le frontend (defectdojoApi.js) :
  severity, cvss_score, cwe, has_mitigation, age_days,
  verified, duplicate, false_positive, scanner_confidence

Label : risk_label  (0=Low, 1=Medium, 2=High, 3=Critical)
"""

import os
import numpy as np
import pandas as pd
from pathlib import Path

RANDOM_SEED = 42
N_SAMPLES   = 8_000
DATA_DIR    = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
OUTPUT_PATH = DATA_DIR / "findings_clean.csv"

rng = np.random.default_rng(RANDOM_SEED)

# ── CWE catalog (id → risk_tier) ──────────────────────────────────────────────
CWE_HIGH = [22, 78, 79, 89, 94, 119, 120, 134, 190, 287, 327, 330, 400, 476, 787]
CWE_MED  = [20, 74, 176, 248, 674, 754, 908]
CWE_LOW  = [200, 284, 362, 369, 377, 407, 415, 456, 459, 467, 561, 563, 570, 571]
ALL_CWE  = CWE_HIGH + CWE_MED + CWE_LOW + [0]   # 0 = unknown

SEV_MAP = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

def cwe_tier(cwe):
    if cwe in CWE_HIGH: return 3
    if cwe in CWE_MED:  return 2
    if cwe in CWE_LOW:  return 1
    return 0

def generate_raw():
    severities = rng.choice(
        ["Info", "Low", "Medium", "High", "Critical"],
        size=N_SAMPLES,
        p=[0.10, 0.25, 0.35, 0.22, 0.08],
    )
    sev_numeric = np.array([SEV_MAP[s] for s in severities])

    # CVSS correlated with severity + noise
    cvss_base = sev_numeric * 2.0 + rng.normal(0, 0.8, N_SAMPLES)
    cvss_score = np.clip(cvss_base, 0, 10).round(1)

    cwe_ids = rng.choice(ALL_CWE, size=N_SAMPLES,
                          p=[1/len(ALL_CWE)] * len(ALL_CWE))
    cwe_tier_vals = np.array([cwe_tier(c) for c in cwe_ids])

    age_days            = rng.integers(0, 730, size=N_SAMPLES)
    has_mitigation      = rng.integers(0, 2,   size=N_SAMPLES)
    verified            = rng.integers(0, 2,   size=N_SAMPLES)
    duplicate           = rng.choice([0, 1],   size=N_SAMPLES, p=[0.85, 0.15])
    false_positive      = rng.choice([0, 1],   size=N_SAMPLES, p=[0.92, 0.08])
    scanner_confidence  = rng.integers(1, 6,   size=N_SAMPLES)   # 1-5
    risk_accepted       = rng.choice([0, 1],   size=N_SAMPLES, p=[0.93, 0.07])

    df = pd.DataFrame({
        "severity":           severities,
        "sev_numeric":        sev_numeric,
        "cvss_score":         cvss_score,
        "cwe":                cwe_ids,
        "cwe_tier":           cwe_tier_vals,
        "age_days":           age_days,
        "has_mitigation":     has_mitigation,
        "verified":           verified,
        "duplicate":          duplicate,
        "false_positive":     false_positive,
        "scanner_confidence": scanner_confidence,
        "risk_accepted":      risk_accepted,
    })
    return df

def compute_risk_label(df):
    """
    Règle déterministe (même logique que computeRiskScore JS)
    transformée en label 0-3.
    """
    age_capped  = np.minimum(df["age_days"], 365)
    age_risk    = np.log1p(age_capped) / np.log1p(365) * 10
    cvss_norm   = df["cvss_score"] / 10
    sev_norm    = (df["sev_numeric"] / 4)
    cwe_norm    = df["cwe_tier"] / 3
    no_fix      = 1 - df["has_mitigation"]

    raw = (
        cvss_norm * 35 +
        sev_norm  * 25 +
        cwe_norm  * 15 +
        (age_risk / 10) * 10 +
        no_fix    *  5
    )
    raw = raw.clip(0, 100)

    # Add realistic noise so the model has something to learn beyond the rule
    noise = np.random.default_rng(RANDOM_SEED).normal(0, 4, len(df))
    raw   = (raw + noise).clip(0, 100)

    # Bin into 4 classes
    labels = pd.cut(
        raw,
        bins=[-1, 25, 50, 75, 101],
        labels=[0, 1, 2, 3],   # Low / Medium / High / Critical
    ).astype(int)
    return labels

def clean(df):
    """Nettoyage & feature engineering."""
    df = df.copy()

    # Drop findings already dismissed (no predictive value for active triage)
    df = df[df["false_positive"] == 0]
    df = df[df["duplicate"]      == 0]

    # Feature engineering
    df["log_age"]      = np.log1p(df["age_days"])
    df["cvss_x_sev"]   = df["cvss_score"] * df["sev_numeric"]   # interaction
    df["is_old"]       = (df["age_days"] > 180).astype(int)
    df["no_fix"]       = 1 - df["has_mitigation"]
    df["high_cwe"]     = (df["cwe_tier"] >= 2).astype(int)

    # Drop raw fields replaced by engineered ones
    df = df.drop(columns=["severity", "age_days"])

    # Ensure no nulls
    df = df.fillna(0)
    return df

def main():
    print("⚙  Génération du dataset brut …")
    raw = generate_raw()

    print("🏷  Calcul des labels …")
    raw["risk_label"] = compute_risk_label(raw)

    print("🧹 Nettoyage & feature engineering …")
    clean_df = clean(raw)

    print(f"💾 Sauvegarde → {OUTPUT_PATH}")
    clean_df.to_csv(OUTPUT_PATH, index=False)

    print("\n📊 Distribution des classes :")
    dist = clean_df["risk_label"].value_counts().sort_index()
    labels_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
    for k, v in dist.items():
        print(f"   {labels_map[k]:10s} ({k}): {v:5d} ({v/len(clean_df)*100:.1f}%)")
    print(f"\n   Total: {len(clean_df)} lignes")

if __name__ == "__main__":
    main()
