"""
Construit un dataset réel à partir de sources publiques.
"""
import pandas as pd
import requests
from pathlib import Path

OUT = Path(__file__).parent.parent / "data" / "real_findings.csv"

# 1) EPSS (probabilité d'exploitation)
epss = pd.read_csv(
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
    compression='gzip', skiprows=1
)

# 2) CISA KEV (vulnérabilités effectivement exploitées — ground truth)
kev = pd.read_csv(
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
)

# 3) NVD pour CVSS et CWE (par batchs de 2000)
def fetch_nvd(year_range=(2020, 2025)):
    rows = []
    for year in range(*year_range):
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={year}-01-01T00:00:00.000&pubEndDate={year}-12-31T23:59:59.999&resultsPerPage=2000"
        # paginer, parser, ajouter à rows
    return pd.DataFrame(rows)

nvd = fetch_nvd() 
# 4) Jointure
df = nvd.merge(epss, on='cve', how='left')
df['exploited'] = df['cve'].isin(kev['cveID']).astype(int)   # label

df.to_csv(OUT, index=False)
print(f"Dataset réel : {len(df)} CVE, {df['exploited'].sum()} exploitées")
