# SPAIDER — AI Cybersecurity Command Platform
# Security Platform for AI-driven Detection, Investigation, Exploitation, Analysis, Defense & Response

<div align="center">
  <h1>🕷️ SPAIDER</h1>
  <p><strong>AI-Powered Cybersecurity Command Platform</strong></p>
  <p>RED · BLUE · PURPLE</p>
</div>

---

## Architecture

```
SPAIDER
│
├── 🧠 AI Security Brain      ← Multi-layer LLM + RAG + ML
├── 🌐 Attack Surface         ← Asset discovery and mapping
├── 🔎 Vulnerability Scanner  ← Nmap, Nuclei, custom checks
├── 🕷️ Web/API Security       ← Burp, Caido integration
├── 📡 Network Discovery      ← Nmap, ARP, DNS, topology
├── 📦 Packet Intelligence    ← Zeek, Suricata, tshark
├── 🦠 Malware Analysis       ← Static, YARA, sandbox
├── 🛡️ Network Defense        ← NDR, anomaly detection
├── 📊 SIEM / Log Intelligence ← Wazuh, syslog, cloud logs
├── 🎯 Threat Hunting         ← IOC, behavioral hunting
├── 🔴 Red Team               ← Authorized pentest workflows
├── 🔵 Blue Team              ← Detection and response
├── 🟣 Purple Team            ← Attack validation vs detection
├── 🧬 MITRE ATT&CK           ← Full matrix mapping
├── 🕸️ Security Graph         ← Asset relationship graph
├── 🌍 3D Cyber Map           ← Three.js network visualization
├── 🤖 AI SOC Analyst         ← Incident reasoning and triage
├── 📑 Report Generator       ← Executive, Technical, SOC
└── 🔌 Plugin Marketplace     ← Extensible security engine SDK
```

## Quick Start

```bash
# Clone and configure
cp .env.example .env
# Edit .env with your API keys

# Launch all services
docker-compose up -d

# Frontend dev (without Docker)
cd frontend && npm install && npm run dev

# Backend dev (without Docker)
cd backend && pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Services

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | React dashboard |
| API | http://localhost:8000 | FastAPI backend |
| API Docs | http://localhost:8000/api/docs | Swagger UI |
| Flower | http://localhost:5555 | Celery worker monitor |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6379 | Cache + broker |
| OpenSearch | http://localhost:9200 | Log search |

## Technology Stack

**Frontend:** React 18 · TypeScript · Vite · Three.js · Canvas 2D · React Query · Zustand · Framer Motion

**Backend:** FastAPI · Python 3.12 · SQLAlchemy (async) · Celery · PostgreSQL · Redis · OpenSearch

**AI:** OpenAI GPT-4o / Anthropic Claude · LangChain · RAG · Embeddings · ML anomaly detection

**Security Engines:** Nmap · Nuclei · Zeek · Suricata · YARA · Wazuh · Burp (plugin) · Caido (plugin)

**Infrastructure:** Docker Compose · Nginx · Kubernetes-ready

## Plugin SDK

Every plugin implements:
```python
discover()   # Find assets/services
scan()       # Active security testing
analyze()    # Process results
collect()    # Gather evidence
normalize()  # Standardize to SPAIDER schema
report()     # Output findings
```

## Safety & Authorization

SPAIDER enforces:
- Scope validation before every active test
- Authorization document requirement
- Rate limiting and safe mode
- Destructive testing gated behind explicit config
- Audit trail for all actions

## SPAIDER's Killer Feature: Find → Understand → Validate → Detect → Remediate → Verify

```
SPAIDER discovers exposed service
             ↓
AI identifies potential vulnerability (reasoning chain)
             ↓
Scanner validates safely within scope
             ↓
Purple engine checks defensive visibility
             ↓
Wazuh/Zeek/Suricata evidence correlated
             ↓
Detection gap identified
             ↓
AI recommends remediation + detection rule
             ↓
Engineer fixes issue
             ↓
SPAIDER rescans → SECURITY POSTURE IMPROVED
```

## Environment Variables

See `.env.example` for all configuration options.

Critical variables:
- `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` — for AI analysis
- `POSTGRES_PASSWORD` — database password
- `SECRET_KEY` — JWT signing key (change in production!)

## 🐧 Linux Tool Format (CLI & Systemd)

SPAIDER includes a dedicated Linux command-line cybersecurity tool:

### 1-Line Installation on Linux (Ubuntu / Debian / Kali / Parrot / Arch / Fedora):
```bash
chmod +x install.sh
./install.sh
```
This automatically installs prerequisites, creates a virtual environment, and symlinks `/usr/local/bin/spaider`.

### CLI Commands:
```bash
# Network & Port Scanning
spaider scan 192.168.1.1
spaider scan example.com --type full -p 80,443,8080

# AI Security Analyst (Offensive, Defensive, Purple)
spaider ai "Analyze suspicious outbound DNS traffic on port 53" --mode PURPLE

# Static Malware & Binary Analysis
spaider malware /path/to/suspicious_sample.exe

# Interactive Cyber Command Shell (MSFConsole style)
spaider console

# Health Check & Service Management
spaider status
spaider serve --port 8001
spaider web --port 3000
```

### Systemd Linux Service:
```bash
sudo systemctl start spaider
sudo systemctl enable spaider
sudo systemctl status spaider
```

---

## 🌐 Publish Website

SPAIDER's command dashboard can be published online in multiple formats:

### 1. GitHub Pages (Automated via GitHub Actions)
Every push to `main` automatically triggers `.github/workflows/deploy-pages.yml` to build and publish the frontend to:
`https://<your-username>.github.io/<your-repo>/`

### 2. Vercel / Netlify (1-Click Deployment)
- **Vercel:** Import your GitHub repository; `vercel.json` is preconfigured.
- **Netlify:** Import your repository; `netlify.toml` handles build and single-page routing automatically.

### 3. Docker / Self-Hosted VPS
```bash
docker-compose up -d
```
Access the web dashboard at `http://<your-server-ip>:3000`.

---

## 🐙 Add to GitHub Repository

To push this project to your GitHub account:

```bash
git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
git branch -M main
git push -u origin main
```

---

Built with ❤️ by the SPAIDER team · Licensed under MIT
