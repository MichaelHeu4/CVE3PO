# CVE3PO

[![Django](https://img.shields.io/badge/Framework-Django%205.2-092e20?logo=django)](https://www.djangoproject.com/)
[![Tailwind CSS](https://img.shields.io/badge/Design-Tailwind%20CSS-06b6d4?logo=tailwind-css)](https://tailwindcss.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003b57?logo=sqlite)](https://www.sqlite.org/)

**CVE3PO** ist eine kompakte Vulnerability-Management-Plattform für Infrastruktur, Software-Inventar und Supply-Chain-Risiken.

## Features

### CTI Inbox und Benachrichtigungsregeln

- Das CTI-Modul ruft konfigurierte öffentliche HTTPS-RSS-/Atom-Feeds regelmäßig ab. Heise Security Alerts und Security News sind voreingestellt. Unter „Modules → CTI Inbox“ können Admins das Modul sowie einzelne Feeds aktivieren, eigene Feeds hinzufügen und bearbeiten und einen Abruf manuell anstoßen. Deaktivieren des Moduls pausiert Abrufe und CTI-Benachrichtigungen; die gespeicherten Daten bleiben erhalten. Die Inbox speichert Titel, Feed-Anrisstext und den Link zum Originalartikel.
- Meldungen können ohne CVE vorliegen. Produktnamen und vorhandene CVE-Findings liefern Vorschläge für den Inventarabgleich; Produktnamen allein bestätigen keine Betroffenheit oder Version. Die Oberfläche erlaubt das Prüfen, Verwerfen und explizite Erstellen bzw. Verknüpfen eines Findings. Ein Wrike-Ticket wird ausschließlich über die vorhandene manuelle Ticketfunktion erstellt.
- Unter „Notification Rules“ können Admins Regeln für CTI-Inventartreffer, neue oder wieder eröffnete Findings, neu im KEV-Katalog gelistete CVEs und morgen fällige SLAs anlegen. Bedingungen umfassen Severity sowie kritische und internetexponierte Hosts; beide Hostbedingungen beziehen sich auf denselben Host. Severity gilt für Finding-Ereignisse, nicht für reine CTI-Meldungen.
- Ziel ist eine E-Mail-Adresse, eine Webhook-URL oder beides. E-Mail benötigt eine konfigurierte SMTP-Verbindung. Zustellstatus und Fehler stehen bei den Regeln; fehlgeschlagene Zustellungen werden bis zu fünfmal versucht. Webhook-Nachrichten enthalten eine stabile `delivery_id`, mit der Empfänger Wiederholungen erkennen können. Regeln greifen nur für neue Ereignisse; beim Deaktivieren oder Ändern werden ausstehende Zustellungen abgebrochen. Die älteren SLA-Erinnerungen funktionieren unabhängig davon und sollten bei Bedarf abgeschaltet werden, um Doppelbenachrichtigungen zu vermeiden.
- Der eingebaute Scheduler prüft aktive Feeds stündlich und Benachrichtigungen ungefähr alle fünf Minuten, solange die Anwendung läuft. Inventar-Vorschläge beruhen auf CVE- und exakten Produktnamen und sind keine automatisierte Versionsprüfung.

### Scanner & Imports
- Nmap
- Nuclei
- OpenVAS
- Semgrep (SAST)
- OSV + NVD Enrichment
- CycloneDX / Syft (SBOM JSON)
- Wazuh Webhook Feed
- Shodan Port-/Exposure-Lookup

### Asset- & Vulnerability-Management
- Host-/Port-/Software-Inventar
- Vulnerability-Lifecycle (Open, In Progress, Fixed, Risk Accepted, False Positive)
- Severity- und Suchfilter in den wichtigsten Ansichten
- Scan-Diff zwischen Scans gleichen Typs
- Manuelle Vulnerability-Erfassung + CVE-Enrichment
- Host-Metadaten inkl. Criticality und Exposed-Flag

### Automatisierung & Module
- CVE3PO Agent API (Snapshot-Sync für Software-Inventar)
- Auto Enrichment (wiederkehrender Scheduler: OSV/NVD/KEV/EPSS + optional Shodan)
- Shodan Modul (Port-Discovery, automatisches Setzen von Internet Exposure)
- AI Triage (OpenRouter oder Azure)
- Wrike Integration
- Email Reporting (PDF Report Versand)
- Passwort-Reset Flows

### Reporting & Dashboard
- KPI Dashboard (u. a. Remediation/Exposure/SLA)
- KI Dashboard
- PDF Export

### Workflows und Datenqualität

- In der Vulnerability-Detailansicht können Verantwortliche, Team, Fälligkeit, Behebungs- und Verifikationsnachweise gepflegt werden. Kritische und hohe neue Findings erhalten standardmäßig eine Fälligkeit nach den konfigurierten SLA-Tagen; sie kann angepasst werden.
- Die Vulnerability-Liste bietet Arbeitsfilter für eigene, überfällige und bald fällige Findings sowie zur Prüfung anstehende Ausnahmen. „Verification Pending“ steht auch auf dem Kanban-Board zur Verfügung.
- Für Risikoakzeptanz und False Positives kann ein Prüf-/Ablaufdatum gesetzt werden. Unveränderte erneute Meldungen behalten die Entscheidung; nach Ablauf öffnet der Scheduler das Finding wieder. Ohne Datum läuft eine Ausnahme nicht automatisch ab.
- „Coverage“ zeigt Agent-Kontakte ab Installation dieser Version, fehlende Softwareversionen und verfügbare Informationen über Scan- und Feed-Läufe. Ein fehlender Agent-Kontakt bedeutet nicht zwingend, dass ein Host einen Agent benötigt.
- Die Detailansicht zeigt lokal gespeicherte KEV-/EPSS-Daten. EPSS-Werte werden bei einem Feed-Lauf nach einem Tag erneuert; die Coverage-Seite zeigt KEV-/EPSS-Läufe und Importfehler.
- Neue Quellen mit derselben CVE und exakt derselben Softwareversion, demselben Host und Port werden nur bei einem eindeutigen offenen Treffer automatisch zusammengeführt. Andere identische Ziele können nach Prüfung manuell zusammengeführt werden; widersprüchliche Status, Bearbeitungsdaten und doppelte Quellen verhindern die Zusammenführung. Beobachtungen und Audit-Ereignisse bleiben erhalten.
- Findings, die nach erfolgreicher Feed-Abfrage nicht mehr gemeldet werden, gehen in die Verifikation; eine ausbleibende Meldung allein ist kein Beleg für eine Behebung. Bei mehreren Quellen wird nicht automatisch geschlossen.
- Unter „Users“ können tägliche E-Mail-Erinnerungen und eine Eskalation an zusätzliche Empfänger aktiviert werden. Dafür müssen SMTP und die E-Mail-Adresse der zuständigen Person konfiguriert sein; die Funktion ist standardmäßig aus.

Nach einem Update müssen die Django-Migrationen ausgeführt werden (`python manage.py migrate`); beim Container-Start geschieht dies automatisch.

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
3. Optional Module unter `/modules` aktivieren (Agent, Wazuh, AI, Email, Wrike, Auto Enrichment, Shodan)

### Auto Enrichment & Shodan

- **Auto Enrichment**: Unter `/modules` aktivieren und ein Intervall (Stunden, Default 24) setzen. Ein interner Scheduler prüft dann wiederkehrend das gesamte Software-Inventar gegen OSV/NVD und aktualisiert CISA KEV + EPSS, damit neue CVEs automatisch erkannt werden. Mit „Run Enrichment Now" lässt sich ein Lauf sofort anstoßen. Alternativ extern per Cron: `python manage.py enrich_feeds`.
- **Shodan**: Modul aktivieren und den Shodan API Key hinterlegen. „Scan All Hosts Now" prüft alle Hosts, auf der Host-Detailseite gibt es „Fetch ports from Shodan" pro Host. Wird ein Host bei Shodan gefunden, werden dessen Ports importiert und `Internet Exposure` automatisch auf True gesetzt. Bei aktivem Shodan-Modul läuft der Shodan-Refresh auch im Auto-Enrichment-Task mit.

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
