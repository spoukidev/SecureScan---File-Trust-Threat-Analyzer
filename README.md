# 🛡️ SecureScan — File Trust & Threat Analyzer

Analyze files for malware, suspicious patterns, and behavioral threats. Upload a file and get a trust score (0–100), threat indicators across 5 analysis engines, and a downloadable PDF report.

![SecureScan](https://img.shields.io/badge/status-active-success)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![React](https://img.shields.io/badge/react-18-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-success)

---

## Features

- **File Upload** — Drag & drop or browse (PDF, EXE, DLL, Office docs, scripts, archives; max 25MB)
- **5 Parallel Analysis Engines**:
  - **Static Analysis** — Entropy calculation, suspicious string detection, PE header parsing
  - **YARA Scanner** — 6 built-in rule categories (PowerShell, network C2, memory injection, persistence, obfuscation, office macros)
  - **Hash Lookup** — SHA256/MD5 hashing with simulated VirusTotal-style threat intelligence
  - **Metadata Extractor** — PDF JavaScript detection, VBA macro analysis, PE metadata, script analysis
  - **Behavioral Analysis** — 8 behavior categories (file ops, network, process injection, registry, crypto, anti-debug, privilege escalation, keylogging)
- **Scoring Engine** — Weighted combination of all engine results → 0–100 trust score
- **Results Dashboard** — Radar chart, severity distribution, engine breakdown, threat details
- **PDF Report** — Downloadable analysis report
- **Dark Theme** — Pure black UI with green accents
- **Real-time Progress** — Upload progress + analysis stage tracking

---

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 18+

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

### API Documentation

With the backend running, visit **http://localhost:8000/docs** for interactive Swagger docs.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/analyze` | Upload & analyze a file |
| `GET` | `/api/results` | List recent analyses |
| `GET` | `/api/results/{id}` | Get analysis details |
| `GET` | `/api/report/{id}` | Download PDF report |
| `GET` | `/api/health` | Health check |

---

## Project Structure

```
securescan/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI entry point
│   │   ├── config.py                  # Settings
│   │   ├── database.py                # SQLite + SQLAlchemy async
│   │   ├── models.py                  # AnalysisRecord model
│   │   ├── schemas.py                 # Pydantic models
│   │   ├── scoring.py                 # Trust score calculator
│   │   ├── analysis/                  # Analysis engines
│   │   │   ├── pipeline.py            # Parallel orchestrator
│   │   │   ├── static_analysis.py     # Entropy, strings, PE
│   │   │   ├── yara_scanner.py        # YARA pattern matching
│   │   │   ├── hash_lookup.py         # Hash threat intel
│   │   │   ├── metadata_extractor.py  # PDF/Office/PE metadata
│   │   │   └── sandbox.py             # Behavioral analysis
│   │   └── routers/
│   │       ├── upload.py              # Upload endpoint
│   │       └── reports.py             # Results & PDF report
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx                    # Main app
│   │   ├── App.css                    # Dark theme styles
│   │   ├── api/client.js              # API client
│   │   └── components/
│   │       ├── FileUpload.jsx         # Drag & drop upload
│   │       ├── ProgressTracker.jsx    # Analysis progress
│   │       ├── ResultsDashboard.jsx   # Results with charts
│   │       └── ThreatDetails.jsx      # Threat indicators
│   ├── package.json
│   └── vite.config.js
```

---

## Use Cases

- **Email Attachment Screening** — Scan incoming attachments for phishing and malware
- **File Upload Portals** — Analyze user-submitted content before storage
- **Incident Response** — Triage suspicious files during investigations
- **CI/CD Security** — Scan build artifacts before deployment
- **Threat Intelligence** — Analyze samples against YARA rules and hash databases
- **Security Training** — Demonstrate malware detection techniques safely

---

## Architecture

```
User Browser → React Frontend → FastAPI Backend → Analysis Pipeline (parallel)
                                                      ├── Static Analysis
                                                      ├── YARA Scanner
                                                      ├── Hash Lookup
                                                      ├── Metadata Extractor
                                                      └── Sandbox (behavioral)
                                                      ↓
                                                Scoring Engine → 0–100 Trust Score
                                                      ↓
                                                SQLite Database → JSON Response → Frontend
```

---

## License

MIT
