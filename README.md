# Security Risk Assessment Tool (FastAPI + React)

A web-based **passive** security risk assessment tool that checks:
- HTTPS/TLS posture
- Security headers (HSTS, CSP, etc.)
- Cookie security flags
- Basic info leakage headers

> Passive checks only. Use only targets you own or have permission to test.

## Run Backend
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
