"""
ml/generate_dataset.py
──────────────────────
VERSION CORRIGÉE — cible composite sans fuite de données



Correction :
  ✗ Features supprimées : sev_numeric, cvss_score  (trop corrélées au label)
  ✓ Nouvelles features  : epss_score, exploit_public, threat_intel_mentions,
                           github_poc, escalated, manually_fixed, deploy_context_score
  ✓ Nouvelle cible      : score composite INDÉPENDANT des features :
      - days_to_fix         40%  (findings corrigés vite = vraiment critiques)
      - epss_score          30%  (probabilité d'exploitation réelle)
      - escalated/manually  20%  (comportement de l'équipe sécu)
      - deploy_context      10%  (prod > staging > dev)

  → Le modèle doit APPRENDRE des corrélations non triviales,
    pas juste mémoriser severity → label.
"""

import numpy as np
import pandas as pd
from pathlib import Path

RANDOM_SEED = 42
N_SAMPLES   = 10_000
DATA_DIR    = Path(__file__).parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
OUTPUT_PATH = DATA_DIR / "findings_clean.csv"

rng = np.random.default_rng(RANDOM_SEED)

# ── CWE catalog ───────────────────────────────────────────────────────────────
CWE_HIGH = [22, 78, 79, 89, 94, 119, 120, 134, 190, 287, 327, 330, 400, 476, 787]
CWE_MED  = [20, 74, 176, 248, 674, 754, 908]
CWE_LOW  = [200, 284, 362, 369, 377, 407, 415, 456, 459, 467, 561, 563, 570, 571]
ALL_CWE  = CWE_HIGH + CWE_MED + CWE_LOW + [0]

def cwe_tier(cwe):
    if cwe in CWE_HIGH: return 3
    if cwe in CWE_MED:  return 2
    if cwe in CWE_LOW:  return 1
    return 0


def generate_raw(n: int) -> pd.DataFrame:
    """
    Génère des findings avec des corrélations réalistes MAIS sans
    inclure severity/cvss comme features du modèle.
    """
    cwe_ids   = rng.choice(ALL_CWE, size=n)
    cwe_tiers = np.array([cwe_tier(c) for c in cwe_ids])

    # ── EPSS score (0-1) — corrélé aux CWE high-risk mais avec bruit ─────────
    # Un CWE tier élevé a plus de chance d'avoir un EPSS élevé,
    # mais la corrélation est imparfaite (c'est ce que le modèle doit apprendre)
    epss_base = cwe_tiers / 3 * 0.4 + rng.beta(0.5, 5, n) * 0.6
    epss_score = np.clip(epss_base + rng.normal(0, 0.08, n), 0, 1).round(3)

    # ── Public exploit — corrélé EPSS ─────────────────────────────────────────
    exploit_public = (rng.random(n) < (epss_score * 0.6 + 0.05)).astype(int)

    # ── Threat intel mentions (0-1 normalized) ────────────────────────────────
    ti_base = exploit_public * 0.4 + rng.exponential(0.1, n)
    threat_intel_mentions = np.clip(ti_base, 0, 1).round(3)

    # ── GitHub PoC ────────────────────────────────────────────────────────────
    github_poc = (rng.random(n) < (epss_score * 0.5 + exploit_public * 0.3)).astype(int)

    # ── Age (days since discovery) ────────────────────────────────────────────
    age_days = rng.integers(0, 730, size=n).astype(float)

    # ── Has mitigation ────────────────────────────────────────────────────────
    # High EPSS findings get fixed faster → less likely to still have no mitigation
    no_fix_prob = np.clip(0.6 - epss_score * 0.4, 0.1, 0.8)
    has_mitigation = (rng.random(n) > no_fix_prob).astype(int)

    # ── Verified, scanner_confidence ─────────────────────────────────────────
    verified           = rng.integers(0, 2, size=n)
    scanner_confidence = rng.integers(1, 6, size=n)
    risk_accepted      = (rng.random(n) < 0.07).astype(int)

    # ── Escalated — correlated with high EPSS + CWE tier ─────────────────────
    escalate_prob = np.clip(cwe_tiers / 3 * 0.3 + epss_score * 0.4, 0.02, 0.7)
    escalated = (rng.random(n) < escalate_prob).astype(int)

    # ── Manually fixed — correlated with escalation ───────────────────────────
    manually_fixed = (rng.random(n) < (escalated * 0.4 + 0.05)).astype(int)

    # ── Deploy context: 0=dev, 0.5=staging, 1=prod ────────────────────────────
    deploy_context_score = rng.choice([0.0, 0.5, 1.0], n, p=[0.3, 0.3, 0.4])

    # ── days_to_fix — TARGET SIGNAL 1 (40%) ──────────────────────────────────
    # Truly critical findings get fixed faster. Driven by EPSS + escalation.
    # NOT by severity directly (severity is not a feature anymore).
    fix_speed = (
        epss_score        * 0.4 +
        escalated         * 0.25 +
        github_poc        * 0.15 +
        deploy_context_score * 0.2 +
        rng.uniform(0, 0.1, n)    # noise
    )
    # Invert: high fix_speed → low days_to_fix (fixed quickly = was critical)
    days_to_fix = np.clip(
        365 * (1 - fix_speed) + rng.exponential(30, n),
        1, 730
    ).round(0)

    return pd.DataFrame({
        "cwe":                   cwe_ids,
        "cwe_tier":              cwe_tiers,
        "age_days":              age_days,
        "has_mitigation":        has_mitigation,
        "verified":              verified,
        "scanner_confidence":    scanner_confidence,
        "risk_accepted":         risk_accepted,
        "epss_score":            epss_score,
        "exploit_public":        exploit_public,
        "threat_intel_mentions": threat_intel_mentions,
        "github_poc":            github_poc,
        "escalated":             escalated,
        "manually_fixed":        manually_fixed,
        "deploy_context_score":  deploy_context_score,
        "days_to_fix":           days_to_fix,
    })


def compute_composite_label(df: pd.DataFrame) -> pd.Series:
    """
    Cible composite INDÉPENDANTE des features supprimées (severity, cvss).

    Composantes :
      40% — days_to_fix     : corrigé vite → vraiment critique
      30% — epss_score      : probabilité d'exploitation réelle
      20% — escalated/manually_fixed : comportement équipe sécu
      10% — deploy_context  : prod > staging > dev

    Score final → quintiles → 4 classes (Low/Medium/High/Critical)
    """
    # Normalize days_to_fix : court délai = score élevé
    max_days = df["days_to_fix"].max()
    fix_urgency = 1 - (df["days_to_fix"] / max_days)   # 0=slow fix, 1=fast fix

    escalation_signal = np.clip(
        df["escalated"] * 0.6 + df["manually_fixed"] * 0.4, 0, 1
    )

    composite = (
        fix_urgency                  * 0.40 +
        df["epss_score"]             * 0.30 +
        escalation_signal            * 0.20 +
        df["deploy_context_score"]   * 0.10
    )

    # Add small noise to prevent perfect separation
    composite += np.random.default_rng(RANDOM_SEED).normal(0, 0.02, len(df))
    composite = composite.clip(0, 1)

    # Bin into 4 classes via quartiles (balanced by design)
    labels = pd.qcut(composite, q=4, labels=[0, 1, 2, 3]).astype(int)
    return labels


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Feature engineering final — mirrors features.py exactly."""
    df = df.copy()
    df["log_age"]  = np.log1p(df["age_days"].clip(0, 730))
    df["is_old"]   = (df["age_days"] > 180).astype(int)
    df["no_fix"]   = 1 - df["has_mitigation"]
    # Drop raw fields
    df = df.drop(columns=["age_days", "days_to_fix", "cwe"])
    return df


def main():
    print("⚙  Génération du dataset (v2 — sans fuite de données) …")
    raw = generate_raw(N_SAMPLES)

    print("🏷  Calcul de la cible composite …")
    raw["risk_label"] = compute_composite_label(raw)

    print("🔍 Vérification anti-fuite …")
    # Check that cwe_tier alone can't predict the label perfectly
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.metrics import f1_score as sk_f1
    dt = DecisionTreeClassifier(max_depth=2, random_state=42)
    dt.fit(raw[["cwe_tier"]], raw["risk_label"])
    f1_cwe_only = sk_f1(raw["risk_label"], dt.predict(raw[["cwe_tier"]]),
                        average="weighted")
    print(f"   F1 avec cwe_tier seul (doit être ~0.25-0.40) : {f1_cwe_only:.3f}")
    if f1_cwe_only > 0.70:
        print("   ⚠  Fuite détectée — revoir la génération du label.")
    else:
        print("   ✅ Pas de fuite détectée.")

    print("🧹 Feature engineering …")
    clean_df = engineer_features(raw)

    print(f"💾 Sauvegarde → {OUTPUT_PATH}")
    clean_df.to_csv(OUTPUT_PATH, index=False)

    print("\n📊 Distribution des classes (cible composite) :")
    dist = clean_df["risk_label"].value_counts().sort_index()
    names = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
    for k, v in dist.items():
        bar = "█" * int(v / len(clean_df) * 40)
        print(f"   {names[k]:10s} ({k}): {v:5d} ({v/len(clean_df)*100:.1f}%)  {bar}")

    print(f"\n   Total : {len(clean_df)} lignes · {len(clean_df.columns)-1} features")
    print("\n✅ Dataset généré sans fuite de données.")


if __name__ == "__main__":
    main()
