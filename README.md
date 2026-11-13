# FileGuard - Cryptographic File Integrity Monitor (FIM)

FileGuard is a production-grade cryptographic file integrity monitoring platform built with FastAPI and SQLite WAL. It monitors critical file system directories using recursive SHA-256 baseline hashing to identify unauthorized modifications, deletions, and malicious file creation in real time.

## Architectural Highlights
- **Cryptographic Baseline Hashing:** Generates immutable SHA-256 digests and POSIX metadata snapshots for monitored directory paths.
- **Diff Detection Engine:** Detects modifications, unauthorized creations, and deletions with severity scoring (Critical, High, Medium, Low).
- **Zero-Trust Audit Log:** Stores integrity drift logs and verification telemetry in SQLite with Write-Ahead Logging (WAL).
- **Incident Response Dashboard:** Real-time web portal displaying alert severity, hash differences, and one-click incident acknowledgement.

## Technology Stack
- **Backend:** Python 3.11+, FastAPI, Pydantic v2, Pytest
- **Database:** SQLite (WAL mode)
- **Frontend:** Vanilla ES6+, CSS Grid/Flexbox, Dark Cyber-Defense UI
- **DevOps:** Docker, Docker Compose, GitHub Actions CI

## Quickstart

```bash
# Clone the repository
git clone https://github.com/Soulofghost/fileguard.git
cd fileguard

# Install dependencies
pip install -r backend/requirements.txt

# Run test suite
pytest -v

# Start development server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

## API Reference
- `GET /api/health` - Service health and hashing engine status.
- `GET /api/stats` - Monitored file count and active breach summaries.
- `GET /api/baselines` - List registered file baselines.
- `POST /api/baselines` - Register and snapshot a new directory baseline.
- `POST /api/scan` - Execute cryptographic diff audit against baseline.
- `GET /api/alerts` - List active and historical integrity breach alerts.
- `POST /api/alerts/{id}/ack` - Acknowledge and resolve an integrity alert.

## Author
Developed by Alvin MS ([@Soulofghost](https://github.com/Soulofghost)).
