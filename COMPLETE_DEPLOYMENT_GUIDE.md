# 🚀 TrojanHorse.js - Complete Deployment Guide

**The Ultimate Guide to Building, Publishing, and Deploying TrojanHorse.js**

Repository: [https://github.com/sc4rfurry/TrojanHorse.js](https://github.com/sc4rfurry/TrojanHorse.js)

---

## 📋 **Table of Contents**

1. [Pre-Deployment Setup](#pre-deployment-setup)
2. [Building the Project](#building-the-project)
3. [NPM Publishing](#npm-publishing)
4. [CDN Publishing (unpkg/jsdelivr)](#cdn-publishing)
5. [Docker Deployment](#docker-deployment)
6. [GitHub Actions CI/CD](#github-actions-cicd)
7. [ReadTheDocs Deployment](#readthedocs-deployment)
8. [Kubernetes Deployment](#kubernetes-deployment)
9. [Production Monitoring](#production-monitoring)
10. [Troubleshooting](#troubleshooting)

---

## 🛠️ **Pre-Deployment Setup**

### **1. Repository Setup**

```bash
# Clone your repository
git clone https://github.com/sc4rfurry/TrojanHorse.js.git
cd TrojanHorse.js

# Install dependencies
npm install

# Verify all builds work
npm run build:all
```

### **2. Environment Variables**

🚨 **SECURITY CRITICAL**: Never commit API keys to git!

```bash
# Copy example configuration
cp trojanhorse.config.example.js trojanhorse.config.js

# Edit with your real API keys (this file is git-ignored)
nano trojanhorse.config.js
```

Create `.env` file for development:

```env
# API Keys (for testing) - NEVER COMMIT THIS FILE!
ALIENVAULT_API_KEY=your-dev-key
ABUSEIPDB_API_KEY=your-dev-key
VIRUSTOTAL_API_KEY=your-dev-key

# NPM Publishing
NPM_TOKEN=your-npm-token

# Docker Registry
DOCKER_USERNAME=your-docker-username
DOCKER_PASSWORD=your-docker-password

# GitHub
GITHUB_TOKEN=your-github-token
```

**⚠️ IMPORTANT**: Add `.env` and `trojanhorse.config.js` to `.gitignore` (already done)

### **3. Clean Build Environment**

```bash
# Remove all build artifacts and dependencies
rm -rf dist/ coverage/ node_modules/
npm cache clean --force

# Fresh install
npm install

# Verify clean build
npm run build:all
npm test
```

---

## 🔨 **Building the Project**

### **1. Development Build**

```bash
# Build for development
npm run build

# Watch mode for development
npm run dev
```

### **2. Production Build**

```bash
# Complete production build
npm run build:all

# Verify build outputs
ls -la dist/
# Should contain:
# - trojanhorse.js (CommonJS)
# - trojanhorse.esm.js (ES Modules)
# - trojanhorse.browser.min.js (Browser minified)
# - trojanhorse.browser.umd.js (UMD)
# - trojanhorse.browser.esm.js (Browser ES modules)
# - trojanhorse.browser.iife.js (IIFE)
# - types/ (TypeScript definitions)
```

### **3. Build Verification**

```bash
# Test all builds
npm test

# Security audit
npm audit
npm audit signatures

# Lint check
npm run lint

# Bundle size analysis
npx bundlesize

# Performance test
npm run test:performance
```

---

## 📦 **NPM Publishing**

### **1. NPM Account Setup**

```bash
# Create NPM account (if needed)
# Visit: https://www.npmjs.com/signup

# Login to NPM
npm login
# Enter your credentials

# Verify login
npm whoami
```

### **2. Package Preparation**

```bash
# Verify package.json
cat package.json | grep -E '"name"|"version"|"repository"'

# Check files that will be published
npm pack --dry-run

# Verify no sensitive files are included
cat .npmignore
```

### **3. Version Management**

```bash
# Semantic versioning
npm version patch  # 1.0.0 -> 1.0.1 (bug fixes)
npm version minor  # 1.0.0 -> 1.1.0 (new features)
npm version major  # 1.0.0 -> 2.0.0 (breaking changes)

# Or manually update version in package.json
# Current version: 1.0.0
```

### **4. Publishing to NPM**

```bash
# Dry run first
npm publish --dry-run

# Publish to NPM (public)
npm publish --access public

# Verify publication
npm view trojanhorse-js

# Test installation
cd /tmp
npm install trojanhorse-js
node -e "console.log(require('trojanhorse-js'))"
```

### **5. NPM Publishing Script**

Create `scripts/publish-npm.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 Starting NPM publication process..."

# Clean and build
npm run clean
npm install
npm run build:all

# Run tests
npm test
npm run lint
npm audit

# Version bump (optional)
read -p "Bump version? (patch/minor/major/skip): " version_bump
if [[ "$version_bump" != "skip" ]]; then
    npm version $version_bump
fi

# Publish
echo "📦 Publishing to NPM..."
npm publish --access public

# Verify
package_name=$(cat package.json | grep '"name"' | cut -d'"' -f4)
echo "✅ Published $package_name successfully!"
echo "🔗 View at: https://www.npmjs.com/package/$package_name"

echo "🎉 NPM publication complete!"
```

---

## 🌐 **CDN Publishing (unpkg/jsdelivr)**

### **Automatic CDN Updates**

Once published to NPM, your package is automatically available on CDNs:

#### **unpkg CDN**

```html
<!-- Latest version -->
<script src="https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>

<!-- Specific version -->
<script src="https://unpkg.com/trojanhorse-js@1.0.0/dist/trojanhorse.browser.min.js"></script>

<!-- ES Modules -->
<script type="module">
  import { TrojanHorse } from 'https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.esm.js';
</script>
```

#### **jsDelivr CDN**

```html
<!-- Latest version -->
<script src="https://cdn.jsdelivr.net/npm/trojanhorse-js@latest/dist/trojanhorse.browser.min.js"></script>

<!-- Specific version -->
<script src="https://cdn.jsdelivr.net/npm/trojanhorse-js@1.0.0/dist/trojanhorse.browser.min.js"></script>
```

### **CDN Verification Script**

Create `scripts/verify-cdn.sh`:

```bash
#!/bin/bash

package_name="trojanhorse-js"
version=$(cat package.json | grep '"version"' | cut -d'"' -f4)

echo "🔍 Verifying CDN availability..."

# Check unpkg
echo "📦 Checking unpkg..."
curl -I "https://unpkg.com/$package_name@$version/dist/trojanhorse.browser.min.js"

# Check jsDelivr
echo "📦 Checking jsDelivr..."
curl -I "https://cdn.jsdelivr.net/npm/$package_name@$version/dist/trojanhorse.browser.min.js"

echo "✅ CDN verification complete!"
```

---

## 🐳 **Docker Deployment**

### **1. Docker Hub Setup**

```bash
# Login to Docker Hub
docker login
# Enter your credentials

# Or use GitHub Container Registry
echo $GITHUB_TOKEN | docker login ghcr.io -u sc4rfurry --password-stdin
```

### **2. Build Docker Images**

```bash
# Build production image
docker build -t trojanhorse-js:latest .
docker build -t trojanhorse-js:1.0.0 .

# Build for multiple platforms
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 -t trojanhorse-js:latest .
```

### **3. Docker Hub Publishing**

```bash
# Tag for Docker Hub
docker tag trojanhorse-js:latest sc4rfurry/trojanhorse-js:latest
docker tag trojanhorse-js:1.0.0 sc4rfurry/trojanhorse-js:1.0.0

# Push to Docker Hub
docker push sc4rfurry/trojanhorse-js:latest
docker push sc4rfurry/trojanhorse-js:1.0.0

# Verify
docker run --rm sc4rfurry/trojanhorse-js:latest --version
```

### **4. GitHub Container Registry**

```bash
# Tag for GitHub Container Registry
docker tag trojanhorse-js:latest ghcr.io/sc4rfurry/trojanhorse-js:latest
docker tag trojanhorse-js:1.0.0 ghcr.io/sc4rfurry/trojanhorse-js:1.0.0

# Push to GitHub Container Registry
docker push ghcr.io/sc4rfurry/trojanhorse-js:latest
docker push ghcr.io/sc4rfurry/trojanhorse-js:1.0.0
```

### **5. Docker Compose for Production**

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  trojanhorse-api:
    image: sc4rfurry/trojanhorse-js:latest
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - ALIENVAULT_API_KEY=${ALIENVAULT_API_KEY}
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    volumes:
      - grafana_data:/var/lib/grafana
    restart: unless-stopped

volumes:
  redis_data:
  prometheus_data:
  grafana_data:
```

### **6. Docker Publishing Script**

Create `scripts/publish-docker.sh`:

```bash
#!/bin/bash
set -e

echo "🐳 Starting Docker publication process..."

# Get version from package.json
version=$(cat package.json | grep '"version"' | cut -d'"' -f4)

# Build multi-platform images
echo "🔨 Building Docker images..."
docker buildx build --platform linux/amd64,linux/arm64 \
  -t sc4rfurry/trojanhorse-js:latest \
  -t sc4rfurry/trojanhorse-js:$version \
  -t ghcr.io/sc4rfurry/trojanhorse-js:latest \
  -t ghcr.io/sc4rfurry/trojanhorse-js:$version \
  --push .

echo "✅ Docker images published successfully!"
echo "🔗 Docker Hub: https://hub.docker.com/r/sc4rfurry/trojanhorse-js"
echo "🔗 GitHub: https://github.com/sc4rfurry/TrojanHorse.js/pkgs/container/trojanhorse-js"

echo "🎉 Docker publication complete!"
```

---

## ⚙️ **GitHub Actions CI/CD**

### **1. GitHub Actions Setup**

Create `.github/workflows/ci-cd.yml`:

```yaml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  release:
    types: [ published ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [16.x, 18.x, 20.x]
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Use Node.js ${{ matrix.node-version }}
      uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Run linting
      run: npm run lint
    
    - name: Run tests
      run: npm test
    
    - name: Run security audit
      run: npm audit
    
    - name: Build project
      run: npm run build:all
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage/lcov.info

  build-and-publish:
    needs: test
    runs-on: ubuntu-latest
    if: github.event_name == 'release'
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Use Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18.x'
        registry-url: 'https://registry.npmjs.org'
    
    - name: Install dependencies
      run: npm ci
    
    - name: Build project
      run: npm run build:all
    
    - name: Publish to NPM
      run: npm publish --access public
      env:
        NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Login to Docker Hub
      uses: docker/login-action@v3
      with:
        username: ${{ secrets.DOCKER_USERNAME }}
        password: ${{ secrets.DOCKER_PASSWORD }}
    
    - name: Login to GitHub Container Registry
      uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: |
          sc4rfurry/trojanhorse-js
          ghcr.io/sc4rfurry/trojanhorse-js
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
    
    - name: Build and push Docker image
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
```

### **2. GitHub Secrets Setup**

Add these secrets to your GitHub repository:

- `NPM_TOKEN`: Your NPM authentication token
- `DOCKER_USERNAME`: Your Docker Hub username
- `DOCKER_PASSWORD`: Your Docker Hub password
- `GRAFANA_PASSWORD`: Password for Grafana dashboard

### **3. Branch Protection Rules**

Set up branch protection for `main`:

1. Go to Settings → Branches
2. Add rule for `main` branch
3. Enable:
   - Require pull request reviews
   - Require status checks to pass
   - Require up-to-date branches
   - Include administrators

---

## 📚 **ReadTheDocs Deployment**

### **1. ReadTheDocs Account Setup**

1. Visit [https://readthedocs.org](https://readthedocs.org)
2. Sign up with GitHub account
3. Import your project: `https://github.com/sc4rfurry/TrojanHorse.js`

### **2. ReadTheDocs Configuration**

Create `.readthedocs.yaml`:

```yaml
version: 2

build:
  os: ubuntu-22.04
  tools:
    python: "3.11"
    nodejs: "18"

mkdocs:
  configuration: mkdocs.yml

python:
  install:
    - requirements: docs/requirements.txt
```

Create `docs/requirements.txt`:

```
mkdocs>=1.5.0
mkdocs-material>=9.0.0
mkdocs-git-revision-date-localized-plugin>=1.2.0
mkdocs-minify-plugin>=0.7.0
pymdown-extensions>=10.0.0
```

### **3. Custom Domain Setup**

1. Add CNAME record: `docs.trojanhorse-js.com → trojanhorse-js.readthedocs.io`
2. In ReadTheDocs admin → Domains → Add domain
3. Enable HTTPS

### **4. Documentation Verification**

```bash
# Local testing
cd docs/
pip install -r requirements.txt
mkdocs serve

# Build test
mkdocs build

# Deploy test
mkdocs gh-deploy --force
```

---

## ☸️ **Kubernetes Deployment**

### **1. Kubernetes Manifests**

All manifests are in `k8s/` directory:

```bash
# Deploy everything
kubectl apply -f k8s/

# Or deploy step by step
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml
```

### **2. Helm Chart Deployment**

```bash
# Add helm repository (when available)
helm repo add trojanhorse https://sc4rfurry.github.io/TrojanHorse.js

# Install with default values
helm install trojanhorse trojanhorse/trojanhorse-js

# Install with custom values
helm install trojanhorse trojanhorse/trojanhorse-js \
  --set image.tag=1.0.0 \
  --set service.type=LoadBalancer \
  --set resources.requests.memory=512Mi
```

### **3. Production Kubernetes Setup**

Create `k8s/production/` directory with:

```bash
# Production namespace
kubectl create namespace trojanhorse-prod

# Production deployment
kubectl apply -f k8s/production/ -n trojanhorse-prod

# Monitor deployment
kubectl get pods -n trojanhorse-prod -w
```

---

## 📊 **Production Monitoring**

### **1. Health Check Endpoints**

Your application provides these endpoints:

- `GET /health` - Application health
- `GET /ready` - Readiness probe
- `GET /metrics` - Prometheus metrics

### **2. Monitoring Stack**

```bash
# Deploy monitoring with Docker Compose
docker-compose -f docker-compose.prod.yml up -d

# Access monitoring
echo "Grafana: http://localhost:3001 (admin/password)"
echo "Prometheus: http://localhost:9090"
```

### **3. Alerting Rules**

Create `monitoring/alerting-rules.yml`:

```yaml
groups:
- name: trojanhorse
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
    for: 5m
    annotations:
      summary: "High error rate detected"
  
  - alert: HighLatency
    expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
    for: 5m
    annotations:
      summary: "High latency detected"
```

---

## 🔧 **Troubleshooting**

### **Common Issues**

#### **NPM Publishing Issues**

```bash
# Permission denied
npm login
npm whoami

# Package already exists
# Update version in package.json
npm version patch
npm publish

# 2FA issues
npm publish --otp=123456
```

#### **Docker Build Issues**

```bash
# Permission denied
sudo usermod -aG docker $USER
newgrp docker

# Build context too large
echo "node_modules/" >> .dockerignore
echo "coverage/" >> .dockerignore

# Multi-platform build fails
docker buildx create --use
docker buildx inspect --bootstrap
```

#### **Kubernetes Deployment Issues**

```bash
# Check pod status
kubectl describe pod <pod-name>

# Check logs
kubectl logs -f deployment/trojanhorse-app

# Debug container
kubectl exec -it <pod-name> -- /bin/sh
```

### **Health Check Script**

Create `scripts/health-check.sh`:

```bash
#!/bin/bash

echo "🔍 TrojanHorse.js Health Check"

# Check NPM package
npm_status=$(curl -s https://registry.npmjs.org/trojanhorse-js | jq -r '.versions | keys[-1]')
echo "📦 NPM latest version: $npm_status"

# Check CDN availability
unpkg_status=$(curl -s -o /dev/null -w "%{http_code}" https://unpkg.com/trojanhorse-js@latest/package.json)
echo "🌐 unpkg CDN status: $unpkg_status"

# Check Docker Hub
docker_status=$(curl -s https://registry.hub.docker.com/v2/repositories/sc4rfurry/trojanhorse-js/tags/ | jq -r '.results[0].name')
echo "🐳 Docker latest tag: $docker_status"

# Check GitHub releases
gh_status=$(curl -s https://api.github.com/repos/sc4rfurry/TrojanHorse.js/releases/latest | jq -r '.tag_name')
echo "🏷️  GitHub latest release: $gh_status"

echo "✅ Health check complete!"
```

---

## 🚀 **Quick Deployment Commands**

### **All-in-One Deployment**

```bash
# Complete deployment pipeline
./scripts/deploy-all.sh
```

Create `scripts/deploy-all.sh`:

```bash
#!/bin/bash
set -e

echo "🚀 Starting complete deployment pipeline..."

# 1. Clean and build
echo "🔨 Building project..."
npm run clean
npm install
npm run build:all

# 2. Run tests
echo "🧪 Running tests..."
npm test
npm run lint
npm audit

# 3. Version bump
echo "📈 Version management..."
read -p "Bump version? (patch/minor/major/skip): " version_bump
if [[ "$version_bump" != "skip" ]]; then
    npm version $version_bump
    git push origin main --tags
fi

# 4. NPM publishing
echo "📦 Publishing to NPM..."
npm publish --access public

# 5. Docker publishing
echo "🐳 Publishing Docker images..."
./scripts/publish-docker.sh

# 6. GitHub release
echo "🏷️  Creating GitHub release..."
version=$(cat package.json | grep '"version"' | cut -d'"' -f4)
gh release create "v$version" --generate-notes

echo "🎉 Deployment pipeline complete!"
echo "📦 NPM: https://www.npmjs.com/package/trojanhorse-js"
echo "🐳 Docker: https://hub.docker.com/r/sc4rfurry/trojanhorse-js"
echo "📚 Docs: https://trojanhorse-js.readthedocs.io"
```

### **Quick Commands Reference**

```bash
# Development
npm install           # Install dependencies
npm run dev          # Start development server
npm test             # Run tests
npm run lint         # Check code quality

# Building
npm run build        # Build for Node.js
npm run build:browser # Build for browser
npm run build:all    # Build all formats

# Publishing
npm publish          # Publish to NPM
docker build . -t trojanhorse-js:latest  # Build Docker
kubectl apply -f k8s/  # Deploy to Kubernetes

# Monitoring
docker-compose -f docker-compose.prod.yml up -d  # Start monitoring
kubectl get pods -w  # Watch Kubernetes pods
```

---

## 🎯 **Deployment Checklist**

### **Pre-Deployment**
- [ ] All tests passing
- [ ] Code linting clean
- [ ] Security audit clean
- [ ] Documentation updated
- [ ] Version number updated
- [ ] GitHub repository clean

### **NPM Deployment**
- [ ] NPM account verified
- [ ] Package.json configured
- [ ] Build artifacts ready
- [ ] Published to NPM
- [ ] CDN availability verified

### **Docker Deployment**
- [ ] Dockerfile optimized
- [ ] Multi-platform build
- [ ] Published to Docker Hub
- [ ] Published to GitHub Container Registry
- [ ] Docker Compose tested

### **Documentation**
- [ ] ReadTheDocs configured
- [ ] Documentation building
- [ ] Custom domain setup
- [ ] Links verified

### **Monitoring**
- [ ] Health checks implemented
- [ ] Metrics collection setup
- [ ] Alerting configured
- [ ] Dashboards created

---

## 🎉 **Success! Your TrojanHorse.js is Now Deployed**

**Your package is now available at:**

- 📦 **NPM**: `npm install trojanhorse-js`
- 🌐 **CDN**: `https://unpkg.com/trojanhorse-js@latest/dist/trojanhorse.browser.min.js`
- 🐳 **Docker**: `docker run sc4rfurry/trojanhorse-js:latest`
- 📚 **Docs**: ReadTheDocs deployment ready
- ☸️ **Kubernetes**: `kubectl apply -f k8s/`

**Repository**: [https://github.com/sc4rfurry/TrojanHorse.js](https://github.com/sc4rfurry/TrojanHorse.js)

---

*Built with ❤️ for the cybersecurity community*

**Ready to protect digital fortresses worldwide! 🏰⚔️**