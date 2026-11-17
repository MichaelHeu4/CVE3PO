import html
import logging

import requests


logger = logging.getLogger(__name__)
# Wrike-Accounts sind an ein Rechenzentrum gebunden. Der EU-Account liegt auf
# app-eu.wrike.com; ein Token von dort wird auf www.wrike.com abgelehnt (401).
WRIKE_API_BASE = "https://app-eu.wrike.com/api/v4"


def _escape(value, default="N/A"):
    # Werte stammen aus Scanner-Daten und dürfen kein HTML in das Ticket einschleusen.
    if value is None or str(value).strip() == "":
        return default
    return html.escape(str(value).strip())


def build_wrike_description(vuln):
    host = vuln.host
    host_txt = _escape(host.ip_address) if host else "N/A"
    if host and host.hostname:
        host_txt = f"{host_txt} ({_escape(host.hostname)})"
    software = vuln.software
    software_txt = (
        _escape(f"{software.name} {software.version or ''}".strip())
        if software
        else "N/A"
    )
    description = _escape(vuln.description, "Keine Beschreibung vorhanden.").replace(
        "\n", "<br>"
    )
    parts = [
        f"<h3>CVE-Finding: {_escape(vuln.cve_id)}</h3>",
        "<p>Erstellt aus CVE3PO</p>",
        "<table>",
        f"<tr><td><b>Severity</b></td><td>{_escape(vuln.severity)}</td></tr>",
        f"<tr><td><b>Status</b></td><td>{_escape(vuln.status)}</td></tr>",
        f"<tr><td><b>CVSS</b></td><td>{_escape(vuln.cvss)}</td></tr>",
        f"<tr><td><b>Host</b></td><td>{host_txt}</td></tr>",
        f"<tr><td><b>Software</b></td><td>{software_txt}</td></tr>",
        "</table>",
        "<h3>Beschreibung</h3>",
        f"<p>{description}</p>",
    ]
    if vuln.ai_suggestion and vuln.ai_suggestion.strip():
        suggestion = _escape(vuln.ai_suggestion).replace("\n", "<br>")
        parts += ["<h3>Empfehlung</h3>", f"<p>{suggestion}</p>"]
    return "".join(parts)


def create_task(vuln, api_token, folder_id):
    url = f"{WRIKE_API_BASE}/folders/{folder_id}/tasks"
    headers = {"Authorization": f"bearer {api_token}"}
    payload = {
        "title": f"[{vuln.severity.upper()}] {vuln.cve_id} - {vuln.name}",
        "description": build_wrike_description(vuln),
    }
    response = requests.post(url, headers=headers, data=payload, timeout=10)
    response.raise_for_status()
    data = response.json().get("data", [])
    if not data:
        raise ValueError("wrike_task_creation_failed")
    task = data[0]
    return task.get("id"), task.get("permalink")


def get_task(api_token, task_id):
    url = f"{WRIKE_API_BASE}/tasks/{task_id}"
    headers = {"Authorization": f"bearer {api_token}"}
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    data = response.json().get("data", [])
    if not data:
        raise ValueError("wrike_task_not_found")
    return data[0]


def mark_task_completed(api_token, task_id, completed):
    url = f"{WRIKE_API_BASE}/tasks/{task_id}"
    headers = {"Authorization": f"bearer {api_token}"}
    payload = {"completed": "true" if completed else "false"}
    response = requests.put(url, headers=headers, data=payload, timeout=10)
    response.raise_for_status()
    data = response.json().get("data", [])
    if not data:
        raise ValueError("wrike_task_update_failed")
    return data[0]
