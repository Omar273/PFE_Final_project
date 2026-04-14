"""
api/schemas.py
──────────────
Schémas Pydantic v2 pour tous les endpoints de l'API.
"""

from typing import Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator


# ── Input ─────────────────────────────────────────────────────────────────────

class FindingInput(BaseModel):
    """Un finding DefectDojo à scorer."""
    id:                  Optional[int]   = Field(None,  description="ID DefectDojo")
    severity:            Optional[str]   = Field("Info", description="Info|Low|Medium|High|Critical")
    cvss_score:          Optional[float] = Field(None)   # no ge/le — null is valid
    cwe:                 Optional[int]   = Field(0)
    age_days:            Optional[float] = Field(90)
    has_mitigation:      Optional[int]   = Field(0)
    verified:            Optional[int]   = Field(0)
    scanner_confidence:  Optional[int]   = Field(3)
    risk_accepted:       Optional[int]   = Field(0)

    @field_validator("severity", mode="before")
    @classmethod
    def coerce_severity(cls, v):
        valid = {"Info", "Low", "Medium", "High", "Critical"}
        if not v or v not in valid:
            return "Info"
        return v

    @field_validator("cvss_score", mode="before")
    @classmethod
    def coerce_cvss(cls, v):
        if v is None:
            return None
        try:
            val = float(v)
            return max(0.0, min(10.0, val))
        except (TypeError, ValueError):
            return None

    @field_validator("cwe", "age_days", "has_mitigation", "verified",
                     "scanner_confidence", "risk_accepted", mode="before")
    @classmethod
    def coerce_int_fields(cls, v):
        if v is None:
            return 0
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return 0

    model_config = {
        "json_schema_extra": {
            "example": {
                "id":                 42,
                "severity":           "High",
                "cvss_score":         8.1,
                "cwe":                89,
                "age_days":           120,
                "has_mitigation":     0,
                "verified":           1,
                "scanner_confidence": 4,
                "risk_accepted":      0,
            }
        }
    }


class BatchPredictRequest(BaseModel):
    findings: list[FindingInput] = Field(..., min_length=1, max_length=500)


class DefectDojoRequest(BaseModel):
    defectdojo_url: str = Field(..., description="URL de l'instance DefectDojo (ex: http://localhost:8080)")
    api_token:      str = Field(..., description="Token API DefectDojo v2")

    model_config = {
        "json_schema_extra": {
            "example": {
                "defectdojo_url": "http://localhost:8080",
                "api_token":      "your-defectdojo-api-token",
            }
        }
    }


# ── Output ────────────────────────────────────────────────────────────────────

class RiskProbabilities(BaseModel):
    Low:      float
    Medium:   float
    High:     float
    Critical: float


class PredictResponse(BaseModel):
    id:            Optional[int]
    risk_label:    int   = Field(..., ge=0, le=3, description="0=Low 1=Medium 2=High 3=Critical")
    risk_name:     str
    risk_score:    float = Field(..., ge=0, le=100, description="Score numérique 0-100")
    probabilities: RiskProbabilities


class BatchPredictItem(BaseModel):
    id:            Optional[int]
    risk_label:    int
    risk_name:     str
    risk_score:    float
    probabilities: RiskProbabilities


class BatchPredictResponse(BaseModel):
    results: list[BatchPredictItem]
    count:   int


class DefectDojoResultItem(BaseModel):
    id:            Optional[int]
    title:         str
    file:          Optional[str] = ""
    risk_label:    int
    risk_name:     str
    risk_score:    float
    probabilities: RiskProbabilities


class DefectDojoResponse(BaseModel):
    results:        list[DefectDojoResultItem]
    count:          int
    defectdojo_url: str


class HealthResponse(BaseModel):
    status:     str
    model_name: str
    f1_score:   Optional[float]
    version:    str


class ModelInfoResponse(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_name:          str
    f1_weighted:         float
    rf_cv_f1:            float
    xgb_cv_f1:           float
    feature_cols:        list[str]
    label_names:         list[str]
    n_train_samples:     int
    n_test_samples:      int
    feature_importance:  dict
