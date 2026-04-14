# DefectDojo Risk Score — ML Backend

Backend Python autonome qui remplace le scoring rule-based du frontend
par un modèle **RandomForest / XGBoost** entraîné sur les features défectdojo.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  React Frontend                      │
│  (defectdojo-debug)                                  │
│   defectdojoApi.js → POST /predict/batch             │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP (localhost:8000)
┌──────────────────────▼──────────────────────────────┐
│           FastAPI  ML Backend  (port 8000)           │
│                                                      │
│  POST /predict             ← 1 finding               │
│  POST /predict/batch       ← N findings (vectorisé)  │
│  POST /predict/defectdojo  ← fetch + score direct    │
│  GET  /health                                        │
│  GET  /model/info                                    │
└──────────────────────┬──────────────────────────────┘
                       │ joblib.load()
┌──────────────────────▼──────────────────────────────┐
│       models/risk_model.joblib                       │
│       (XGBoost ou RandomForest — meilleur F1)        │
└─────────────────────────────────────────────────────┘
```

---

## Installation & démarrage

### 1. Prérequis
```bash
python >= 3.11
pip install -r requirements.txt
```

### 2. Générer le dataset synthétique
```bash
python ml/generate_dataset.py
# → data/findings_clean.csv  (~6 000 lignes)
```

### 3. Entraîner le modèle
```bash
python ml/train.py
# → models/risk_model.joblib
# → models/model_meta.json
```
Output attendu :
```
🏆 Meilleur modèle : XGBoost  (F1=0.87xx)
💾 Modèle sauvegardé → models/risk_model.joblib
```

### 4. Démarrer l'API
```bash
uvicorn api.main:app --reload --port 8000
```

### 5. Tester
```bash
# Health check
curl http://localhost:8000/health

# Score un seul finding
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "id": 42,
    "severity": "High",
    "cvss_score": 8.1,
    "cwe": 89,
    "age_days": 120,
    "has_mitigation": 0,
    "verified": 1,
    "scanner_confidence": 4,
    "risk_accepted": 0
  }'

# Score depuis DefectDojo directement
curl -X POST http://localhost:8000/predict/defectdojo \
  -H "Content-Type: application/json" \
  -d '{
    "defectdojo_url": "http://localhost:8080",
    "api_token": "YOUR_TOKEN"
  }'
```

### 6. Lancer les tests
```bash
pytest tests/ -v
```

---

## Intégration React

Dans `defectdojoApi.js`, remplacer `computeRiskScore(f)` par un appel API :

```javascript
// Appel batch vers le ML backend
const response = await fetch("http://localhost:8000/predict/batch", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    findings: normalized.map(f => ({
      id:                 f.id,
      severity:           f.severity,
      cvss_score:         f.cvss_score,
      cwe:                f.cwe,
      age_days:           f.date
        ? Math.floor((Date.now() - new Date(f.date)) / 86400000)
        : 90,
      has_mitigation:     f.mitigation ? 1 : 0,
      verified:           f.verified ? 1 : 0,
      scanner_confidence: f.scanner_confidence || 3,
      risk_accepted:      f.risk_accepted ? 1 : 0,
    }))
  })
});
const { results } = await response.json();

// Merge scores ML dans les findings normalisés
const scoreMap = Object.fromEntries(results.map(r => [r.id, r]));
return normalized.map(f => ({
  ...f,
  risk_score:  scoreMap[f.id]?.risk_score  ?? f.risk_score,
  risk_label:  scoreMap[f.id]?.risk_name   ?? "Unknown",
  risk_probas: scoreMap[f.id]?.probabilities ?? null,
}));
```

---

## Structure des fichiers

```
ml-backend/
├── requirements.txt
├── README.md
│
├── ml/
│   ├── generate_dataset.py   ← génération dataset synthétique
│   ├── train.py              ← entraînement RF + XGBoost, sélection, sauvegarde
│   └── features.py           ← feature engineering partagé train/inférence
│
├── api/
│   ├── main.py               ← FastAPI app + tous les endpoints
│   └── schemas.py            ← Pydantic v2 input/output schemas
│
├── tests/
│   └── test_api.py           ← pytest (unit + intégration)
│
├── data/                     ← créé par generate_dataset.py
│   └── findings_clean.csv
│
└── models/                   ← créé par train.py
    ├── risk_model.joblib
    └── model_meta.json
```

---

## Endpoints

| Méthode | Endpoint                  | Description                              |
|---------|---------------------------|------------------------------------------|
| GET     | `/health`                 | Statut + nom du modèle + F1              |
| GET     | `/model/info`             | Métadonnées complètes du modèle          |
| POST    | `/predict`                | Score 1 finding                          |
| POST    | `/predict/batch`          | Score N findings (max 500, vectorisé)    |
| POST    | `/predict/defectdojo`     | Fetch depuis DD + score tout             |
| GET     | `/docs`                   | Swagger UI auto-généré                   |

---

## Variables d'environnement (optionnel)

```bash
PORT=8000               # port uvicorn (défaut: 8000)
MODEL_PATH=models/risk_model.joblib
LOG_LEVEL=INFO
```
