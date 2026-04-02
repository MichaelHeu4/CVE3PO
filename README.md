# CVE3PO | The Vigilant Architect

[![Django](https://img.shields.io/badge/Framework-Django%205.2-092e20?logo=django)](https://www.djangoproject.com/)
[![Tailwind CSS](https://img.shields.io/badge/Design-Tailwind%20CSS-06b6d4?logo=tailwind-css)](https://tailwindcss.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003b57?logo=sqlite)](https://www.sqlite.org/)

**CVE3PO** is modern simplistic Vulnerability Management platform designed to be easy understandable and easy to maintain. 

![Vigilant Architect Design](stitch/screen.png)

## 🚀 Core Features

### 📡 Multi-Scanner Intelligence
Ingest and parse technical manifests from industry-standard security tools:
- **Nmap**: Full network discovery and service mapping.
- **Nuclei**: Template-based vulnerability scanning with automated POC extraction.
- **OpenVAS (GVM)**: Deep infrastructure security reports.
- **Semgrep SAST**: Static analysis findings linked directly to software artifacts.
- OSV Scanner: Open Source Vulnerability data for software dependencies.

### 🏛️ Architectural Registry
- **Asset Inventory**: Automated tracking of hosts, open ports, and service status.
- **Software Ecosystem**: Managed catalog of applications, versions, and vendors.
- **Smart Port Routing**: Automatically associates network findings with specific software based on listening ports.
- **Vulnerability Inheritance**: Software-level CVEs automatically propagate to all architectural nodes running that artifact.

### 🛠️ Strategic Workflow
- **Interactive Kanban Board**: Drag-and-drop remediation pipeline (Open → In Progress → Fixed → Risk Accepted → False Positive).
- **Business Criticality**: Define node and artifact importance. Automatic propagation ensures that high-value assets inherit the risk bias of their critical software.
- **Manual Intelligence**: Register findings from external research or magazines through a dedicated manual entry workflow.

### 📊 Visual Analytics
- **Risk Over Time**: Global trend analysis of active vulnerabilities.
- **Finding History**: Host-specific bar charts tracking detection counts across multiple scans.

## 🛠️ Technical Stack
- **Backend**: Python 3.11+, Django 5.2
- **Frontend**: Tailwind CSS, Google Stitch (Vigilant Architect Specification)
- **Charts**: Chart.js
- **Interactivity**: SortableJS (Kanban Drag & Drop)
- **Database**: SQLite (Standard)

## 💻 Quick Start

### 1. Clone & Setup Environment
```bash
git clone https://github.com/MichaelHeu4/cve3po.git
cd cve3po
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Initialize Database
```bash
python manage.py makemigrations
python manage.py migrate
```

### 3. Deploy Local Instance
```bash
python manage.py runserver
```
Access the console at `http://localhost:8000`.

### 4. Create a user
Navigate to http://localhost:8000/register/ to create a new user account.
