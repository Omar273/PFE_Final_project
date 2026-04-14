"""
tests/test_api.py
─────────────────
Tests unitaires & d'intégration pour le backend FastAPI.
Lance avec :  pytest tests/ -v
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

# ── Fixtures ──────────────────────────────────────────────────────────────────

MOCK_MODEL = MagicMock()
MOCK_MODEL.predict.return_value       = np.array([2])          # "High"
MOCK_MODEL.predict_proba.return_value = np.array([[0.05, 0.15, 0.60, 0.20]])

MOCK_META = {
    "model_name":         "XGBoost",
    "f1_weighted":        0.87,
    "rf_cv_f1":           0.84,
    "xgb_cv_f1":          0.87,
    "feature_cols":       ["sev_numeric", "cvss_score"],
    "label_names":        ["Low", "Medium", "High", "Critical"],
    "n_train_samples":    6000,
    "n_test_samples":     1400,
    "feature_importance": {"sev_numeric": 0.35, "cvss_score": 0.28},
}


@pytest.fixture(scope="module")
def client():
    """Client de test avec le modèle mocké (pas besoin du vrai .joblib)."""
    with patch("api.main.MODEL_PATH", new=Path("/fake/model.joblib")), \
         patch("api.main.META_PATH",  new=Path("/fake/meta.json")):

        from api.main import app, _state
        _state["model"] = MOCK_MODEL
        _state["meta"]  = MOCK_META

        with TestClient(app) as c:
            yield c


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"]     == "ok"
    assert body["model_name"] == "XGBoost"


def test_model_info(client):
    r = client.get("/model/info")
    assert r.status_code == 200
    body = r.json()
    assert "feature_importance" in body
    assert body["f1_weighted"]  == 0.87


def test_predict_single(client):
    payload = {
        "id":                42,
        "severity":          "High",
        "cvss_score":        8.1,
        "cwe":               89,
        "age_days":          120,
        "has_mitigation":    0,
        "verified":          1,
        "scanner_confidence": 4,
        "risk_accepted":     0,
    }
    r = client.post("/predict", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["id"]         == 42
    assert body["risk_name"]  == "High"
    assert 0 <= body["risk_score"] <= 100
    assert set(body["probabilities"].keys()) == {"Low", "Medium", "High", "Critical"}


def test_predict_missing_optional_fields(client):
    """Les champs optionnels doivent avoir des valeurs par défaut sensées."""
    r = client.post("/predict", json={"severity": "Medium"})
    assert r.status_code == 200


def test_predict_invalid_severity(client):
    r = client.post("/predict", json={"severity": "ULTRA_CRITICAL"})
    assert r.status_code == 422   # Pydantic validation error


def test_predict_batch(client):
    MOCK_MODEL.predict.return_value       = np.array([1, 2, 3])
    MOCK_MODEL.predict_proba.return_value = np.array([
        [0.10, 0.60, 0.20, 0.10],
        [0.05, 0.15, 0.60, 0.20],
        [0.02, 0.05, 0.13, 0.80],
    ])
    payload = {
        "findings": [
            {"id": 1, "severity": "Low",      "cvss_score": 3.0, "cwe": 0},
            {"id": 2, "severity": "High",     "cvss_score": 7.5, "cwe": 89},
            {"id": 3, "severity": "Critical", "cvss_score": 9.8, "cwe": 78},
        ]
    }
    r = client.post("/predict/batch", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["count"]    == 3
    assert len(body["results"]) == 3
    assert body["results"][2]["risk_name"] == "Critical"


def test_predict_batch_too_large(client):
    findings = [{"severity": "Low"} for _ in range(501)]
    r = client.post("/predict/batch", json={"findings": findings})
    assert r.status_code == 400


def test_predict_batch_empty(client):
    r = client.post("/predict/batch", json={"findings": []})
    assert r.status_code == 422   # min_length=1


def test_docs_available(client):
    r = client.get("/docs")
    assert r.status_code == 200
