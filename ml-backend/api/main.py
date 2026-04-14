"""
api/main.py
───────────
FastAPI — Risk Score ML Backend
Endpoints :
  GET  /health            → statut du service + infos modèle
  POST /predict           → score un seul finding
  POST /predict/batch     → score N findings en une requête
  POST /predict/defectdojo → fetch depuis DefectDojo + score tout
  GET  /model/info        → métadonnées du modèle entraîné
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pythonjsonlogger import jsonlogger

from api.schemas import (
    BatchPredictRequest,
    BatchPredictResponse,
    DefectDojoRequest,
    DefectDojoResponse,
    FindingInput,
    HealthResponse,
    ModelInfoResponse,
    PredictResponse,
)
from ml.features import batch_to_features, finding_to_features, LABEL_NAMES

# ── Logging ───────────────────────────────────────────────────────────────────
logger = logging.getLogger("risk_api")
handler = logging.StreamHandler()
handler.setFormatter(jsonlogger.JsonFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# ── Model paths ───────────────────────────────────────────────────────────────
ROOT       = Path(__file__).parent.parent
MODEL_PATH = ROOT / "models" / "risk_model.joblib"
META_PATH  = ROOT / "models" / "model_meta.json"

# ── App state (loaded at startup) ─────────────────────────────────────────────
_state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model once at startup."""
    if not MODEL_PATH.exists():
        raise RuntimeError(
            f"Modèle introuvable : {MODEL_PATH}\n"
            "Lancez d'abord :  python ml/generate_dataset.py && python ml/train.py"
        )
    logger.info("Chargement du modèle …", extra={"path": str(MODEL_PATH)})
    _state["model"] = joblib.load(MODEL_PATH)

    import json
    if META_PATH.exists():
        _state["meta"] = json.loads(META_PATH.read_text())
    else:
        _state["meta"] = {}

    logger.info("Modèle chargé.", extra={"model": _state["meta"].get("model_name")})
    yield
    _state.clear()


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="DefectDojo Risk Score API",
    description=(
        "Backend ML autonome pour le scoring de risque des findings DefectDojo.\n\n"
        "Modèle : RandomForest / XGBoost entraîné sur les features CVSS, CWE, âge, sévérité…"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # restreindre en production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helper ────────────────────────────────────────────────────────────────────
def _predict_single(finding_dict: dict) -> dict:
    model = _state["model"]
    X     = finding_to_features(finding_dict)
    label = int(model.predict(X)[0])
    proba = model.predict_proba(X)[0].tolist()

    # Numeric risk score 0-100  (weighted average of class probabilities)
    score = float(
        proba[0] * 10 +
        proba[1] * 35 +
        proba[2] * 65 +
        proba[3] * 95
    )
    return {
        "risk_label":    label,
        "risk_name":     LABEL_NAMES[label],
        "risk_score":    round(score, 2),
        "probabilities": {
            LABEL_NAMES[i]: round(p, 4) for i, p in enumerate(proba)
        },
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["Infra"])
def health():
    meta = _state.get("meta", {})
    return {
        "status":     "ok",
        "model_name": meta.get("model_name", "unknown"),
        "f1_score":   meta.get("f1_weighted"),
        "version":    app.version,
    }


@app.get("/model/info", response_model=ModelInfoResponse, tags=["Model"])
def model_info():
    if not _state.get("meta"):
        raise HTTPException(404, "Métadonnées modèle introuvables.")
    return _state["meta"]


@app.post("/predict", response_model=PredictResponse, tags=["Inference"])
def predict(finding: FindingInput):
    """
    Score un seul finding DefectDojo.
    Retourne : risk_label (0-3), risk_name, risk_score (0-100), probabilités.
    """
    try:
        result = _predict_single(finding.model_dump())
        logger.info("predict", extra={"id": finding.id, "risk": result["risk_name"]})
        return {**result, "id": finding.id}
    except Exception as e:
        logger.error("predict error", extra={"error": str(e)})
        raise HTTPException(500, str(e))


@app.post("/predict/batch", response_model=BatchPredictResponse, tags=["Inference"])
def predict_batch(req: BatchPredictRequest):
    """
    Score N findings en une seule requête (max 2000).
    Optimisé : inférence vectorisée sur la matrice complète.
    """
    if len(req.findings) > 2000:
        raise HTTPException(400, "Maximum 2000 findings par requête batch.")

    model   = _state["model"]
    dicts   = [f.model_dump() for f in req.findings]
    X       = batch_to_features(dicts)
    labels  = model.predict(X).astype(int)
    probas  = model.predict_proba(X)

    results = []
    for i, (finding, label, proba) in enumerate(zip(req.findings, labels, probas)):
        score = float(
            proba[0] * 10 + proba[1] * 35 + proba[2] * 65 + proba[3] * 95
        )
        results.append({
            "id":         finding.id,
            "risk_label": int(label),
            "risk_name":  LABEL_NAMES[int(label)],
            "risk_score": round(score, 2),
            "probabilities": {
                LABEL_NAMES[j]: round(float(p), 4) for j, p in enumerate(proba)
            },
        })

    logger.info("batch predict", extra={"n": len(results)})
    return {"results": results, "count": len(results)}


@app.post("/predict/defectdojo", response_model=DefectDojoResponse, tags=["Inference"])
async def predict_from_defectdojo(req: DefectDojoRequest):
    """
    Se connecte à une instance DefectDojo, récupère tous les findings actifs,
    les score avec le modèle ML et retourne les résultats triés par risk_score.

    Utilisable comme webhook ou tâche planifiée dans un pipeline DevSecOps.
    """
    import httpx

    headers = {
        "Authorization": f"Token {req.api_token}",
        "Content-Type":  "application/json",
    }
    base = req.defectdojo_url.rstrip("/")
    all_findings = []

    async with httpx.AsyncClient(timeout=30) as client:
        url = f"{base}/api/v2/findings/?active=true&duplicate=false&false_p=false&limit=100&offset=0"
        while url:
            try:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise HTTPException(502, f"DefectDojo error: {e.response.status_code}")
            except httpx.RequestError as e:
                raise HTTPException(502, f"Cannot reach DefectDojo: {e}")

            data = resp.json()
            all_findings.extend(data.get("results", []))

            next_url = data.get("next")
            if next_url:
                # Keep only path+query — works whether DD is behind a proxy or not
                from urllib.parse import urlparse
                parsed = urlparse(next_url)
                url = base + parsed.path + ("?" + parsed.query if parsed.query else "")
            else:
                url = None

    if not all_findings:
        return {"results": [], "count": 0, "defectdojo_url": base}

    # Normalize & score
    model  = _state["model"]
    scored = []
    for f in all_findings:
        finding_dict = {
            "id":                 f.get("id"),
            "severity":           f.get("severity", "Info"),
            "cvss_score":         f.get("cvssv3_score") or f.get("cvss"),
            "cwe":                f.get("cwe", 0),
            "age_days":           _age_days(f.get("date")),
            "has_mitigation":     int(bool(f.get("mitigation"))),
            "verified":           int(bool(f.get("verified"))),
            "scanner_confidence": f.get("scanner_confidence") or 3,
            "risk_accepted":      int(bool(f.get("risk_accepted"))),
        }
        result = _predict_single(finding_dict)
        scored.append({
            **result,
            "id":    f.get("id"),
            "title": f.get("title", ""),
            "file":  f.get("file_path") or "",   # None → empty string
        })

    scored.sort(key=lambda x: x["risk_score"], reverse=True)
    logger.info("defectdojo predict", extra={"n": len(scored), "url": base})
    return {"results": scored, "count": len(scored), "defectdojo_url": base}


def _age_days(date_str) -> float:
    if not date_str:
        return 90.0
    from datetime import date, datetime
    try:
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        return float((date.today() - d).days)
    except Exception:
        return 90.0
