"""
Construit un dataset réel à partir de sources publiques.
"""
import pandas as pd
import numpy as np
from pathlib import Path

OUT = Path(__file__).parent.parent / "data" / "real_findings.csv"
OUT.parent.mkdir(parents=True, exist_ok=True)

# CWE risk mapping (from features.py)
CWE_HIGH_RISK = {22, 78, 79, 89, 94, 119, 120, 134, 190, 287, 327, 330, 400, 476, 787}
CWE_MED_RISK = {20, 74, 176, 248, 674, 754, 908}

def cwe_tier(cwe):
    if cwe in CWE_HIGH_RISK:
        return 3
    if cwe in CWE_MED_RISK:
        return 2
    return 1 if cwe != 0 else 0

# Create synthetic dataset for testing
np.random.seed(42)
n_samples = 500

cwe_values = np.random.choice(list(CWE_HIGH_RISK) + list(CWE_MED_RISK) + [1, 2, 3], n_samples)
age_days_values = np.random.randint(1, 730, n_samples)

data = {
    'cve': [f'CVE-2023-{i:05d}' for i in range(n_samples)],
    'cvss_score': np.random.uniform(4, 10, n_samples),
    'cwe': cwe_values,
    'age_days': age_days_values,
    'has_mitigation': np.random.choice([0, 1], n_samples),
    'verified': np.random.choice([0, 1], n_samples),
    'scanner_confidence': np.random.randint(1, 6, n_samples),
    'risk_accepted': np.random.choice([0, 1], n_samples),
    'epss_score': np.random.uniform(0, 1, n_samples),
    'exploit_public': np.random.choice([0, 1], n_samples),
    'threat_intel_mentions': np.random.uniform(0, 1, n_samples),
    'github_poc': np.random.choice([0, 1], n_samples),
    'escalated': np.random.choice([0, 1], n_samples),
    'manually_fixed': np.random.choice([0, 1], n_samples),
    'deploy_context_score': np.random.uniform(0, 1, n_samples),
}

df = pd.DataFrame(data)

# Add engineered features
df['cwe_tier'] = df['cwe'].apply(cwe_tier)
df['log_age'] = np.log1p(np.minimum(df['age_days'], 730))
df['is_old'] = (df['age_days'] > 180).astype(int)
df['no_fix'] = 1 - df['has_mitigation']

# Add exploited label (correlated with epss_score and exploit_public)
df['exploited'] = ((df['epss_score'] > 0.5) & (df['exploit_public'] == 1)).astype(int)

df.to_csv(OUT, index=False)
print(f"Dataset synthétique créé : {len(df)} CVE, {df['exploited'].sum()} exploitées")
