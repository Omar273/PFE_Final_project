"""
Tests d'intégration SANS mock — chargent le vrai modèle et vérifient
la cohérence du pipeline complet.
Aurait détecté le bug B1 immédiatement.
"""
import subprocess
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).parent.parent


def test_train_pipeline_runs_end_to_end(tmp_path, monkeypatch):
    """Génère un mini-dataset puis entraîne — détecte les incohérences de features."""
    monkeypatch.chdir(ROOT)
    result = subprocess.run(
        [sys.executable, "ml/generate_dataset.py"],
        capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, f"generate_dataset failed: {result.stderr}"
    result = subprocess.run(
        [sys.executable, "ml/train.py"],
        capture_output=True, text=True, timeout=600,
    )
    assert result.returncode == 0, f"train failed: {result.stderr}"
    assert (ROOT / "models" / "risk_model.joblib").exists()
def test_features_alignment():
    """features.py et train.py doivent déclarer les mêmes colonnes."""
    from ml.features import FEATURE_COLS as f_features
    from ml.train import FEATURE_COLS as f_train
    assert f_features == f_train, \
        f"Misalignement features.py vs train.py : {set(f_train) ^ set(f_features)}"


def test_api_predict_with_real_model():
    """Charge le vrai modèle et fait une vraie prédiction."""
    from api.main import app
    client = TestClient(app)
    payload = {
        "id": 1, "cwe": 89, "age_days": 30, "epss_score": 0.7,
        "exploit_public": 1, "scanner_confidence": 4,
        "deploy_context_score": 1.0,
    }
    r = client.post("/predict", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert 0 <= body["risk_score"] <= 100
    assert body["risk_name"] in ["Low", "Medium", "High", "Critical"]
