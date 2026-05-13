"""
ml/train.py
───────────
Entraîne deux modèles (RandomForest + XGBoost), compare leurs performances,
sélectionne le meilleur et le sauvegarde dans models/risk_model.joblib.

Usage :
    python ml/train.py [--data data/findings_clean.csv] [--output models/]
"""

import argparse
import json
import time
from pathlib import Path 
from ml.features import FEATURE_COLS, LABEL_NAMES  # new imports


import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).parent.parent
DATA_PATH  = ROOT / "data"  / "findings_clean.csv"
MODEL_DIR  = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "risk_model.joblib"
META_PATH  = MODEL_DIR / "model_meta.json"

# ── Feature columns (must match API input schema) ─────────────────────────────
FEATURE_COLS = [
    "cwe_tier",
    "log_age",
    "is_old",
    "no_fix",
    "verified",
    "scanner_confidence",
    "risk_accepted",
    "epss_score",
    "exploit_public",
    "threat_intel_mentions",
    "github_poc",
    "escalated",
    "manually_fixed",
    "deploy_context_score",
]
TARGET_COL  = "risk_label"
LABEL_NAMES = ["Low", "Medium", "High", "Critical"]


def load_data(path: Path):
    df = pd.read_csv(path)
    missing = [c for c in FEATURE_COLS + [TARGET_COL] if c not in df.columns]
    if missing:
        raise ValueError(f"Colonnes manquantes dans le CSV : {missing}")
    X = df[FEATURE_COLS].values.astype(np.float32)
    y = df[TARGET_COL].values.astype(int)
    return X, y


def build_rf():
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=400,
            max_depth=12,
            min_samples_leaf=5,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])


def build_xgb():
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )),
    ])


def evaluate(name, pipeline, X_test, y_test):
    y_pred = pipeline.predict(X_test)
    f1     = f1_score(y_test, y_pred, average="weighted")
    print(f"\n{'─'*50}")
    print(f"  {name}")
    print(f"{'─'*50}")
    print(classification_report(y_test, y_pred, target_names=LABEL_NAMES))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    return f1


def cross_validate(name, pipeline, X, y, n_splits=5):
    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores = cross_val_score(pipeline, X, y, cv=cv,
                             scoring="f1_weighted", n_jobs=-1)
    print(f"  {name} CV F1 : {scores.mean():.4f} ± {scores.std():.4f}")
    return scores.mean()


def get_feature_importance(pipeline, model_name):
    clf = pipeline.named_steps["clf"]
    if hasattr(clf, "feature_importances_"):
        imp = clf.feature_importances_
        return dict(zip(FEATURE_COLS, [round(float(v), 4) for v in imp]))
    return {}


def main(data_path: Path, output_dir: Path):
    print(f"\n📂 Chargement des données : {data_path}")
    X, y = load_data(data_path)
    print(f"   {len(X)} samples · {X.shape[1]} features · {len(set(y))} classes")

    # ── Train/test split ───────────────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # ── SMOTE : équilibrage des classes sur le train set ──────────────────────
    print("\n⚖  Application de SMOTE …")
    sm = SMOTE(random_state=42)
    X_train_sm, y_train_sm = sm.fit_resample(X_train, y_train)
    print(f"   Avant SMOTE : {len(X_train)} · Après : {len(X_train_sm)}")

    # ── Cross-validation comparison ────────────────────────────────────────────
    print("\n🔁 Cross-validation (5-fold) …")
    rf_pipeline  = build_rf()
    xgb_pipeline = build_xgb()
    rf_cv_f1  = cross_validate("RandomForest", rf_pipeline,  X_train_sm, y_train_sm)
    xgb_cv_f1 = cross_validate("XGBoost",      xgb_pipeline, X_train_sm, y_train_sm)

    # ── Full training ──────────────────────────────────────────────────────────
    print("\n🏋  Entraînement final …")
    t0 = time.time()
    rf_pipeline.fit(X_train_sm, y_train_sm)
    print(f"   RandomForest  : {time.time()-t0:.1f}s")

    t0 = time.time()
    xgb_pipeline.fit(X_train_sm, y_train_sm)
    print(f"   XGBoost       : {time.time()-t0:.1f}s")

    # ── Evaluation ────────────────────────────────────────────────────────────
    print("\n📊 Évaluation sur le test set :")
    rf_f1  = evaluate("RandomForest", rf_pipeline,  X_test, y_test)
    xgb_f1 = evaluate("XGBoost",     xgb_pipeline, X_test, y_test)

    # ── Select best model ─────────────────────────────────────────────────────
    if xgb_f1 >= rf_f1:
        best_pipeline = xgb_pipeline
        best_name     = "XGBoost"
        best_f1       = xgb_f1
    else:
        best_pipeline = rf_pipeline
        best_name     = "RandomForest"
        best_f1       = rf_f1

    print(f"\n🏆 Meilleur modèle : {best_name}  (F1={best_f1:.4f})")

    # ── Save model ────────────────────────────────────────────────────────────
    model_path = output_dir / "risk_model.joblib"
    joblib.dump(best_pipeline, model_path)
    print(f"💾 Modèle sauvegardé → {model_path}")

    # ── Save metadata (used by API at startup) ────────────────────────────────
    meta = {
        "model_name":       best_name,
        "f1_weighted":      round(best_f1, 4),
        "rf_cv_f1":         round(rf_cv_f1, 4),
        "xgb_cv_f1":        round(xgb_cv_f1, 4),
        "feature_cols":     FEATURE_COLS,
        "label_names":      LABEL_NAMES,
        "n_train_samples":  int(len(X_train_sm)),
        "n_test_samples":   int(len(X_test)),
        "feature_importance": get_feature_importance(best_pipeline, best_name),
    }
    meta_path = output_dir / "model_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2))
    print(f"📋 Métadonnées     → {meta_path}")

    print("\n✅ Entraînement terminé.")
    return meta


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data",   type=Path, default=DATA_PATH)
    parser.add_argument("--output", type=Path, default=MODEL_DIR)
    args = parser.parse_args()
    main(args.data, args.output)
