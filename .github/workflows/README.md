# GitHub Actions CI/CD Workflows

This directory contains automated CI/CD pipelines for the DefectDojo Dashboard project.

## 📋 Workflow Overview

### 1. **ml-backend-ci.yml** — ML Backend Testing & Building
Triggered on changes to `ml-backend/` directory.

**Jobs:**
- `test` — Run pytest on Python 3.11 & 3.12
- `build` — Build Docker image for ML backend
- `code-quality` — Pylint analysis

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests affecting `ml-backend/`

---

### 2. **dashboard-ci.yml** — Frontend Testing & Building
Triggered on changes to `defectdojo-dashboard/` directory.

**Jobs:**
- `lint-and-test` — Build with Vite on Node 18.x & 20.x
- `build` — Create production bundle, upload artifacts
- `docker-build` — Build Docker image for dashboard

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests affecting `defectdojo-dashboard/`

---

### 3. **docker-build.yml** — Build & Push Docker Images
Builds and pushes Docker images to GitHub Container Registry.

**Strategy:**
- Build both `ml-backend` and `defectdojo-dashboard` images
- Tag with branch, semantic version, SHA, and latest
- Push only on main branch (not on PRs)
- Validate `docker-compose.yaml`

**Triggers:**
- Push to `main` branch
- Git tags matching `v*.*.*` (semantic versioning)
- Manual trigger (`workflow_dispatch`)

---

### 4. **integration-tests.yml** — Full Stack Integration Testing
Runs end-to-end tests with services started locally.

**Services:**
- PostgreSQL 14 (for compatibility testing)
- ML Backend (uvicorn)
- Dashboard (build verification)

**Jobs:**
- `integration-test` — Health checks, API tests
- `security-scan` — Bandit, safety, npm audit

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Manual trigger

---

### 5. **kubernetes-deploy.yml** — Kubernetes Deployment
Deploys to Kubernetes cluster (staging/production).

**Features:**
- Creates namespace and resources
- Updates image references with proper tags
- Monitors rollout status
- Displays deployment info

**Requires:**
- `KUBE_CONFIG` secret (base64-encoded kubeconfig)

**Triggers:**
- Push to `main` (staging by default)
- Git tags (production)
- Manual trigger with environment selection

---

### 6. **code-quality.yml** — Code Coverage & Quality
Generates code coverage reports and security scans.

**Jobs:**
- `coverage` — Pytest coverage with Codecov upload
- `sonarqube` — SonarQube analysis (optional)
- `dependency-check` — Trivy vulnerability scan
- `documentation` — Auto-generate API docs

**Optional:**
- Upload to Codecov (requires token)
- SonarQube scan (requires credentials)

**Triggers:**
- Push to `main` or `develop`
- Pull requests

---

## 🔐 Required Secrets

### For Docker Push (docker-build.yml)
- `GITHUB_TOKEN` — Auto-provided by GitHub Actions

### For Kubernetes Deployment (kubernetes-deploy.yml)
- `KUBE_CONFIG` — Base64-encoded kubeconfig file
  ```bash
  cat ~/.kube/config | base64 -w 0 | xclip -selection clipboard
  ```

### Optional: Code Quality (code-quality.yml)
- `SONAR_HOST_URL` — SonarQube server URL
- `SONAR_LOGIN` — SonarQube token

---

## 🚀 Setup Instructions

### 1. Add Secrets to Repository
1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Add required secrets:

```bash
# Example: Add KUBE_CONFIG
cat ~/.kube/config | base64 -w 0
# Copy output and paste as KUBE_CONFIG value
```

### 2. Enable Workflows
Workflows are automatically enabled. To verify:
1. Go to **Actions** tab
2. Select a workflow
3. Workflows should show as enabled

### 3. Protect Main Branch
1. Go to **Settings** → **Branches**
2. Add branch protection for `main`:
   - ✅ Require PR reviews
   - ✅ Require status checks to pass
   - ✅ Require branches to be up to date

---

## 📊 Monitoring & Troubleshooting

### View Workflow Runs
- Go to **Actions** tab
- Click workflow name to see all runs
- Click a run to see detailed logs

### Debug Failed Jobs
1. Click the failed job
2. Expand `Run` section to see error details
3. Common issues:
   - Missing Python/Node dependencies
   - Port conflicts (8000, 5432)
   - Missing secrets
   - Insufficient disk space

### Re-run Failed Workflows
- Click **Re-run failed jobs** on workflow page
- Or re-run all jobs

---

## 📝 Customization

### Change Trigger Conditions
Edit the `on:` section in any workflow:

```yaml
on:
  push:
    branches: [ main, staging ]  # Add staging branch
    paths:
      - 'ml-backend/**'
  pull_request:
    branches: [ main, develop ]
```

### Modify Test Commands
Edit job steps:

```yaml
- name: Run tests
  working-directory: ml-backend
  run: pytest tests/ -v  # Change command here
```

### Add New Workflows
Create new `.yml` file in `.github/workflows/`:

```yaml
name: My Custom Workflow

on:
  push:
    branches: [ main ]

jobs:
  my-job:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Do something
        run: echo "Hello, World!"
```

---

## ✅ Best Practices

1. **Keep workflows fast**
   - Minimize dependencies
   - Use caching (pip, npm)
   - Parallelize jobs when possible

2. **Log everything**
   - Use descriptive step names
   - Echo status messages
   - Capture failures

3. **Security**
   - Use secrets for sensitive data
   - Don't log credentials
   - Pin action versions

4. **Testing**
   - Run tests locally before push
   - Test all matrix versions
   - Use `continue-on-error` carefully

5. **Documentation**
   - Comment complex workflows
   - Document required secrets
   - Link to relevant docs

---

## 📚 Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax Reference](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [Actions Marketplace](https://github.com/marketplace?type=actions)

---

## 📞 Support

For workflow issues:
1. Check GitHub Actions logs
2. Review this documentation
3. Test locally before pushing
4. Enable debug logging if needed

```bash
# Enable debug logging (add to workflow)
- name: Enable debug logging
  run: |
    echo "ACTIONS_STEP_DEBUG=true" >> $GITHUB_ENV
```

---

**Last Updated:** May 2026
