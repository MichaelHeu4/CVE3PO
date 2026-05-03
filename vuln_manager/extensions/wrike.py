import logging

import requests


logger = logging.getLogger(__name__)
WRIKE_API_BASE = "https://www.wrike.com/api/v4"


def build_wrike_description(vuln):
    host = vuln.host.ip_address if vuln.host else "N/A"
    software = vuln.software.name if vuln.software else "N/A"
    return (
        f"CVE: {vuln.cve_id}\n"
        f"Severity: {vuln.severity}\n"
        f"Status: {vuln.status}\n"
        f"Host: {host}\n"
        f"Software: {software}\n\n"
        f"{vuln.description or 'No description provided.'}"
    )


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
