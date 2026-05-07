# CVE3PO

[![Django](https://img.shields.io/badge/Framework-Django%205.2-092e20?logo=django)](https://www.djangoproject.com/)
[![Tailwind CSS](https://img.shields.io/badge/Design-Tailwind%20CSS-06b6d4?logo=tailwind-css)](https://tailwindcss.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003b57?logo=sqlite)](https://www.sqlite.org/)

**CVE3PO** ist eine kompakte Vulnerability-Management-Plattform für Infrastruktur, Software-Inventar und Supply-Chain-Risiken.

## Features

### Scanner & Imports
- Nmap
- Nuclei
- OpenVAS
- Semgrep (SAST)
- OSV + NVD Enrichment
- CycloneDX / Syft (SBOM JSON)
- Wazuh Webhook Feed

### Asset- & Vulnerability-Management
- Host-/Port-/Software-Inventar
- Vulnerability-Lifecycle (Open, In Progress, Fixed, Risk Accepted, False Positive)
- Severity- und Suchfilter in den wichtigsten Ansichten
- Scan-Diff zwischen Scans gleichen Typs
- Manuelle Vulnerability-Erfassung + CVE-Enrichment
- Host-Metadaten inkl. Criticality und Exposed-Flag

### Automatisierung & Module
- CVE3PO Agent API (Snapshot-Sync für Software-Inventar)
- AI Triage (OpenRouter oder Azure)
- Wrike Integration
- Email Reporting (PDF Report Versand)
- Passwort-Reset Flows

### Reporting & Dashboard
- KPI Dashboard (u. a. Remediation/Exposure/SLA)
- KI Dashboard
- PDF Export

## Betrieb mit GHCR Image

Image:
```bash
docker pull ghcr.io/michaelheu4/cve3po:latest
```

### Variante 1: Docker Run
```bash
docker run -d \
  --name cve3po \
  -p 8000:8000 \
  -e DJANGO_SECRET_KEY='change-me' \
  -e DEBUG='False' \
  -e DJANGO_ALLOWED_HOSTS='localhost 127.0.0.1' \
  -e CSRF_TRUSTED_ORIGINS='http://localhost:8000' \
  -e DISABLE_REGISTER='False' \
  -e DATABASE_PATH='/app/data/db.sqlite3' \
  -v cve3po-data:/app/data \
  -v cve3po-media:/app/media \
  ghcr.io/michaelheu4/cve3po:latest
```

### Variante 2: Docker Compose
```yaml
services:
  cve3po:
    image: ghcr.io/michaelheu4/cve3po:latest
    container_name: cve3po
    ports:
      - "8000:8000"
    environment:
      DJANGO_SECRET_KEY: ${DJANGO_SECRET_KEY}
      DEBUG: ${DEBUG:-False}
      DJANGO_ALLOWED_HOSTS: ${DJANGO_ALLOWED_HOSTS:-localhost 127.0.0.1}
      CSRF_TRUSTED_ORIGINS: ${CSRF_TRUSTED_ORIGINS:-http://localhost:8000}
      DISABLE_REGISTER: ${DISABLE_REGISTER:-False}
      DATABASE_PATH: /app/data/db.sqlite3
    volumes:
      - cve3po-data:/app/data
      - cve3po-media:/app/media

volumes:
  cve3po-data:
  cve3po-media:
```

Start:
```bash
docker compose up -d
```

## Erste Inbetriebnahme

1. Anwendung öffnen: `http://localhost:8000`
2. Account erstellen über `/register` (falls `DISABLE_REGISTER=False`)
3. Optional Module unter `/modules` aktivieren (Agent, Wazuh, AI, Email, Wrike)

Hinweis: Beim Container-Start werden Migrationen automatisch ausgeführt.

## Optionale Konfiguration

- `NVD_API_KEY`: Höhere Limits bei NVD Enrichment
- SMTP für Passwort-Reset / Email Reporting:
  - `EMAIL_BACKEND`
  - `EMAIL_HOST`
  - `EMAIL_PORT`
  - `EMAIL_HOST_USER`
  - `EMAIL_HOST_PASSWORD`
  - `EMAIL_USE_TLS`
  - `DEFAULT_FROM_EMAIL`

## Agent Artefakte

Wenn das Agent-Modul aktiv ist, sind die Agent-Dateien verfügbar unter:
- `/agent/latest/install.sh`
- `/agent/latest/cve3po-agent-linux-amd64`
- `/agent/latest/cve3po-agent-linux-amd64.sha256`
