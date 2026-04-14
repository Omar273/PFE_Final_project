"""
ml/features.py
──────────────
Feature engineering partagé entre l'entraînement (train.py)
et l'inférence (API).  Une seule source de vérité.
"""

import numpy as np
import pandas as pd

# ── CWE risk tiers (mirror de defectdojoApi.js) ───────────────────────────────
CWE_HIGH_RISK = frozenset([
    22, 78, 79, 89, 94, 119, 120, 134,
    190, 287, 327, 330, 400, 476, 787,
])
CWE_MED_RISK = frozenset([20, 74, 176, 248, 674, 754, 908])

SEV_MAP = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

FEATURE_COLS = [
    "sev_numeric",
    "cvss_score",
    "cwe_tier",
    "log_age",
    "has_mitigation",
    "verified",
    "scanner_confidence",
    "risk_accepted",
    "cvss_x_sev",
    "is_old",
    "no_fix",
    "high_cwe",
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
    Transforme un finding normalisé (dict) en vecteur numpy [1 × n_features].
    Compatible avec le schéma FindingInput de l'API.
    """
    sev       = finding.get("severity", "Info")
    sev_num   = SEV_MAP.get(sev, 0)
    cvss      = float(finding.get("cvss_score") or sev_num * 2.0)
    cwe       = int(finding.get("cwe") or 0)
    age       = float(finding.get("age_days") or 90)
    has_fix   = int(bool(finding.get("has_mitigation") or finding.get("mitigation")))
    verified  = int(bool(finding.get("verified", False)))
    scanner_c = int(finding.get("scanner_confidence") or 3)
    r_accept  = int(bool(finding.get("risk_accepted", False)))

    # Engineered features
    log_age    = np.log1p(min(age, 730))
    cvss_x_sev = cvss * sev_num
    is_old     = int(age > 180)
    no_fix     = 1 - has_fix
    ct         = cwe_tier(cwe)
    high_cwe   = int(ct >= 2)

    vector = np.array([
        sev_num,
        cvss,
        ct,
        log_age,
        has_fix,
        verified,
        scanner_c,
        r_accept,
        cvss_x_sev,
        is_old,
        no_fix,
        high_cwe,
    ], dtype=np.float32)

    return vector.reshape(1, -1)


def batch_to_features(findings: list[dict]) -> np.ndarray:
    """Transforme une liste de findings en matrice [N × n_features]."""
    return np.vstack([finding_to_features(f) for f in findings])
