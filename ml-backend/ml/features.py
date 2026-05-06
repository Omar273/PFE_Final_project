"""
ml/features.py
──────────────
Feature engineering — VERSION CORRIGÉE (sans fuite de données)

Changements majeurs vs v1 :
  ✗ Supprimé  : sev_numeric, cvss_score  (trop corrélés au label → fuite)
  ✓ Conservé  : cwe_tier, age_days, has_mitigation, verified, scanner_confidence
  ✓ Ajouté    : epss_score, exploit_public, threat_intel_mentions,
                github_poc, escalated, manually_fixed, deploy_context_score
  ✓ Cible     : risk_label composite (days_to_fix 40% + EPSS 30% +
                escalation 20% + deploy context 10%)
"""

import numpy as np

# ── CWE risk tiers ────────────────────────────────────────────────────────────
CWE_HIGH_RISK = frozenset([
    22, 78, 79, 89, 94, 119, 120, 134,
    190, 287, 327, 330, 400, 476, 787,
])
CWE_MED_RISK = frozenset([20, 74, 176, 248, 674, 754, 908])

# ── Feature columns (in exact order expected by the model) ───────────────────
FEATURE_COLS = [
    # ── Vulnerability context (no direct severity leak) ──────────────────────
    "cwe_tier",             # 0-3  rule-based CWE risk bucket
    "log_age",              # log1p(days since discovery)
    "is_old",               # 1 if age > 180 days
    "no_fix",               # 1 if no mitigation documented
    "verified",             # manually verified by analyst
    "scanner_confidence",   # 1-5 scanner-reported confidence
    "risk_accepted",        # team formally accepted the risk

    # ── Exploitability signals (independent of raw severity) ─────────────────
    "epss_score",           # EPSS probability 0-1 (Exploit Prediction Scoring)
    "exploit_public",       # known public exploit exists (0/1)
    "threat_intel_mentions",# normalized count of CTI mentions (0-1)
    "github_poc",           # public PoC on GitHub (0/1)

    # ── Remediation behaviour signals ────────────────────────────────────────
    "escalated",            # finding was escalated to security team (0/1)
    "manually_fixed",       # fixed outside automated pipeline (0/1)

    # ── Deployment context ───────────────────────────────────────────────────
    "deploy_context_score", # 0=dev/test  0.5=staging  1=production
]

LABEL_NAMES = ["Low", "Medium", "High", "Critical"]


def cwe_tier(cwe: int) -> int:
    if cwe in CWE_HIGH_RISK:
        return 3
    if cwe in CWE_MED_RISK:
        return 2
    return 1 if cwe != 0 else 0


def finding_to_features(finding: dict) -> np.ndarray:
    """
    Transforme un finding normalisé (dict) → vecteur numpy [1 × n_features].
    Compatible avec FindingInput de l'API.

    Les champs EPSS / threat intel ont des valeurs par défaut conservatrices
    (0.1 / 0) quand ils ne sont pas disponibles — pas de fuite vers le label.
    """
    cwe      = int(finding.get("cwe") or 0)
    age      = float(finding.get("age_days") or 90)
    has_fix  = int(bool(finding.get("has_mitigation") or finding.get("mitigation")))
    verified = int(bool(finding.get("verified", False)))
    scanner_c = int(finding.get("scanner_confidence") or 3)
    r_accept  = int(bool(finding.get("risk_accepted", False)))

    # Exploitability — real values when available, conservative defaults otherwise
    epss              = float(finding.get("epss_score") or 0.05)        # EPSS default ~population mean
    exploit_pub       = int(bool(finding.get("exploit_public", False)))
    ti_mentions       = float(finding.get("threat_intel_mentions") or 0.0)
    github_poc        = int(bool(finding.get("github_poc", False)))

    # Remediation behaviour
    escalated         = int(bool(finding.get("escalated", False)))
    manually_fixed    = int(bool(finding.get("manually_fixed", False)))

    # Deploy context
    deploy_ctx        = float(finding.get("deploy_context_score") or 0.5)

    # Engineered
    ct      = cwe_tier(cwe)
    log_age = np.log1p(min(age, 730))
    is_old  = int(age > 180)
    no_fix  = 1 - has_fix

    vector = np.array([
        ct,
        log_age,
        is_old,
        no_fix,
        verified,
        scanner_c,
        r_accept,
        epss,
        exploit_pub,
        ti_mentions,
        github_poc,
        escalated,
        manually_fixed,
        deploy_ctx,
    ], dtype=np.float32)

    return vector.reshape(1, -1)


def batch_to_features(findings: list) -> np.ndarray:
    """Transforme une liste de findings → matrice [N × n_features]."""
    return np.vstack([finding_to_features(f) for f in findings])
