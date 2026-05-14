# DefectDojo Security Dashboard

An intelligent vulnerability management system that combines machine learning-based risk assessment with a modern web dashboard for security findings prioritization.

## 🎯 Project Overview

This project provides an AI-powered solution to help security teams prioritize vulnerability remediation efforts. It replaces traditional CVSS-only scoring with a **machine learning model** (XGBoost/RandomForest) trained on real-world vulnerability exploitation data, combining:

- **DefectDojo integration** — Multi-source vulnerability management
- **ML-based risk scoring** — Predictive model trained on NVD/KEV data
- **React Dashboard** — Interactive visualization of findings and metrics
- **FastAPI Backend** — High-performance ML inference service
- **Docker & Kubernetes** — Production-ready deployment

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│          React Dashboard (Port 80/8080)                  │
│  - Findings visualization                               │
│  - Metrics & statistics                                 │
│  - Agent & LLM configuration                            │
└──────────────────────┬──────────────────────────────────┘
                       │
       ┌───────────────┴───────────────┐
       │                               │
       ▼                               ▼
┌──────────────────┐         ┌──────────────────┐
│   FastAPI        │         │  DefectDojo      │
│  ML Backend      │         │  (Port 8080)     │
│  (Port 8000)     │         │                  │
│  - /predict      │         │  - Findings DB   │
│  - /health       │         │  - Integrations  │
│  - /model/info   │         └──────────────────┘
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────┐
│  XGBoost/RandomForest Model          │
│  (models/risk_model.joblib)          │
│  - Vulnerability classification      │
│  - Risk score prediction             │
└──────────────────────────────────────┘
```

## 📋 Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Docker & Docker Compose** (for containerized deployment)
- **PostgreSQL 14** (used by DefectDojo)
- **Redis 7** (used by DefectDojo)

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone and navigate to project
cd pfe_project

# Start all services (frontend, backend, DefectDojo, database)
docker-compose up --build

# Services will be available at:
# - Frontend:   http://localhost (Nginx)
# - Dashboard:  http://localhost:80
# - ML Backend: http://localhost:8000 (Swagger docs: /docs)
# - DefectDojo: http://localhost:8080
```

### Option 2: Local Development

#### Backend Setup

```bash
cd ml-backend

# Install Python dependencies
pip install -r requirements.txt

# Generate synthetic training dataset
python ml/generate_dataset.py

# Train the ML model
python ml/train.py

# Start FastAPI server
uvicorn api.main:app --reload --port 8000
```

#### Frontend Setup

```bash
cd defectdojo-dashboard

# Install dependencies
npm install

# Start development server (Vite)
npm run dev
# Or build for production
npm run build
```

## 📁 Project Structure

```
pfe_project/
├── github/workflows/
|         ├── code-quality.yml
|         ├── dashboard-ci.yml         # CI pipeline
|         ├── docker-build.yml
|         ├── integration-tests.yml
|         ├── kubernetes-deploy.yml
|         ├── kubernetes-deploy.yml
|         ├──ml-backend-ci.yml     
|          
├── README.md                          # This file
├── docker-compose.yaml                # Full stack orchestration
│
├── defectdojo-dashboard/              # React frontend
│   ├── dockerfile
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── components/                # React components
│   │   │   ├── Dashboard.jsx          # Main dashboard
│   │   │   ├── FindingsTable.jsx      # Findings list
│   │   │   ├── ChartsPanel.jsx        # Visualization
│   │   │   ├── FiltersBar.jsx         # Filter controls
│   │   │   ├── NavBar.jsx             # Navigation
│   │   │   ├── AgentPage.jsx          # Agent config
│   │   │   ├── LLMPage.jsx            # LLM settings
│   │   │   ├── Badges.jsx             # Status badges
│   │   │   ├── MetricsRow.jsx         # Metrics display
│   │   │   └── Connect.jsx            # Connection setup
│   │   ├── hooks/
│   │   │   └── useFindings.js         # Data fetching hook
│   │   └── services/
│   │       └── defectdojoApi.js       # API client
│   └── docs/
│       └── evaluation.md              # Model evaluation report
│
├── ml-backend/                        # Python ML service
│   ├── dockerfile
│   ├── requirements.txt
│   ├── README.md
│   ├── api/
│   │   ├── main.py                    # FastAPI application
│   │   └── schemas.py                 # Pydantic models
│   ├── ml/
│   │   ├── train.py                   # Model training
│   │   ├── evaluate.py                # Model evaluation
│   │   ├── features.py                # Feature engineering
│   │   └── generate_dataset.py        # Synthetic data generation
│   ├── models/
│   │   ├── risk_model.joblib          # Trained ML model
│   │   └── model_meta.json            # Model metadata
│   ├── data/
│   │   └── real_findings.csv          # Training data
│   ├── scripts/
│   │   └── fetch_real_data.py         # Data collection
│   └── tests/
│       ├── test_api.py                # API tests
│       └── test_integration.py        # Integration tests
│
└── kubernetes/                        # K8s deployment configs
    ├── namespace.yaml                 # K8s namespace
    ├── deployments.yaml               # Service deployments
    ├── configmaps.yaml                # Configuration
    ├── secretes.yaml                  # Secrets management
    └── volumes.yaml                   # Persistent volumes
```

## 🔌 API Endpoints

### ML Backend (FastAPI)

**Base URL:** `http://localhost:8000`

```
POST   /predict               - Score a single finding
POST   /predict/batch         - Score multiple findings
POST   /predict/defectdojo    - Fetch & score from DefectDojo
GET    /health                - Health check
GET    /model/info            - Model metadata
GET    /docs                  - Interactive API documentation (Swagger UI)
```

### Frontend

**Base URL:** `http://localhost` or `http://localhost:80`

- `/dashboard` — Main findings dashboard
- `/agent` — Agent configuration
- `/llm` — LLM settings
- `/connect` — DefectDojo connection

## 🤖 Machine Learning Model

### Data Sources

- **NVD (National Vulnerability Database)** — CVE data, CVSS scores, CWE, descriptions
- **KEV (Known Exploited Vulnerabilities)** — Real-world exploitation records

### Model Details

- **Algorithm:** XGBoost / RandomForest
- **Task:** Binary classification (exploitable vs non-exploitable)
- **Features:** CVSS metrics, CWE type, vulnerability age, vendor reputation, etc.
- **Training:** SMOTE for class balancing

For detailed evaluation metrics, see [defectdojo-dashboard/docs/evaluation.md](defectdojo-dashboard/docs/evaluation.md).

## 📊 Technologies Used

### Frontend
- **React 18** — UI framework
- **Vite 5** — Build tool
- **React Router** — Navigation
- **Recharts** — Data visualization
- **Nginx** — Web server (production)

### Backend
- **FastAPI** — Web framework
- **Uvicorn** — ASGI server
- **XGBoost / Scikit-learn** — ML libraries
- **Pandas / NumPy** — Data processing
- **Pydantic** — Data validation
- **Pytest** — Testing

### Infrastructure
- **Docker & Docker Compose** — Containerization
- **Kubernetes** — Orchestration
- **PostgreSQL** — Database
- **Redis** — Caching / sessions

## 🔧 Configuration

### Environment Variables

**ML Backend** (ml-backend):
```env
LOG_LEVEL=INFO
PYTHONUNBUFFERED=1
```

**DefectDojo** (docker-compose):
- Database URL, credentials, Redis URL (auto-configured in compose)

### Model Configuration

Edit `ml-backend/models/model_meta.json` to configure:
- Model selection (xgboost/randomforest)
- Feature list
- Threshold tuning
- Class weights

## 📝 Development Workflow

### Running Tests

```bash
# Backend tests
cd ml-backend
pytest tests/

# Frontend tests (if configured)
cd defectdojo-dashboard
npm test
```

### Training a New Model

```bash
cd ml-backend

# Generate new dataset (or use existing)
python ml/generate_dataset.py

# Train model
python ml/train.py

# Evaluate
python ml/evaluate.py
```

### Development Mode

**Frontend (with hot reload):**
```bash
cd defectdojo-dashboard
npm run dev
```

**Backend (with auto-reload):**
```bash
cd ml-backend
uvicorn api.main:app --reload
```

## 🐳 Docker Commands

```bash
# Build all services
docker-compose build

# Start services
docker-compose up

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Remove volumes (careful!)
docker-compose down -v
```

## ☸️ Kubernetes Deployment

```bash
# Create namespace
kubectl apply -f kubernetes/namespace.yaml

# Deploy services
kubectl apply -f kubernetes/deployments.yaml
kubectl apply -f kubernetes/configmaps.yaml
kubectl apply -f kubernetes/secretes.yaml
kubectl apply -f kubernetes/volumes.yaml

# Check status
kubectl get all -n defectdojo-dashboard

# Port forward to access frontend
kubectl port-forward svc/frontend 80:80 -n defectdojo-dashboard
```

## 📚 Documentation

- [ML Backend README](ml-backend/README.md) — Detailed backend documentation
- [Model Evaluation Report](defectdojo-dashboard/docs/evaluation.md) — Performance metrics & analysis
- **Swagger UI:** http://localhost:8000/docs (when backend is running)

## 🐛 Troubleshooting

### Backend won't start
```bash
# Check if port 8000 is in use
netstat -an | grep 8000

# Verify dependencies
pip list | grep -E "(fastapi|xgboost|pandas)"
```

### Frontend can't connect to backend
- Ensure ML backend is running: `http://localhost:8000/health`
- Check CORS settings in `ml-backend/api/main.py`
- Verify network connectivity if using Docker

### Model not loading
```bash
cd ml-backend
python -c "import joblib; joblib.load('models/risk_model.joblib')"
```

## 📝 License

This project is part of a professional engagement. See LICENSE file for details.

## 👥 Contributors

- Development Team

## 📧 Support

For issues and questions:
1. Check existing documentation in `/docs` folders
2. Review DefectDojo [official documentation](https://defectdojo.readthedocs.io/)
3. Check ML backend logs: `docker-compose logs ml-backend`

---

**Last Updated:** May 2026
