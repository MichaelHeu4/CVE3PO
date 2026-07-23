#!/usr/bin/env python3
"""
Custom Wazuh Integration - Vulnerability Alerts -> Vuln-Management-Tool

Leitet alle Wazuh Vulnerability-Alerts an ein externes
Vulnerability-Management-Tool weiter.

Aufruf durch den Wazuh-Manager (ueber den custom-vulnmgmt Wrapper):
    custom-vulnmgmt.py <alert_file> <api_key> <hook_url> [options]

argv[1] = Pfad zur Alert-Datei (JSON, vom Manager erzeugt)
argv[2] = API-Key   (aus <api_key> in ossec.conf)
argv[3] = Hook-URL  (aus <hook_url> in ossec.conf)
argv[4] = optional: "debug" (aktiviert ausfuehrliches Logging)
"""

import json
import os
import sys
from datetime import datetime

try:
    import requests
except ImportError:
    print("Modul 'requests' fehlt. Es ist normalerweise in der "
          "Wazuh-Python-Umgebung (framework/python) enthalten.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Konfiguration
# ---------------------------------------------------------------------------
WAZUH_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(WAZUH_PATH, "logs", "integrations.log")

TIMEOUT = 30          # Request-Timeout in Sekunden
VERIFY_TLS = True     # bei Self-Signed-Zertifikat ggf. auf False setzen

debug_enabled = False


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
def log(message):
    """Schreibt eine Zeile ins Wazuh-Integrations-Log."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} custom-vulnmgmt: {message}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except Exception:
        # Logging darf die Integration niemals crashen lassen
        pass


def debug(message):
    if debug_enabled:
        log(f"DEBUG: {message}")


def load_alert(path):
    """Liest und parst die vom Manager uebergebene Alert-Datei."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def is_vulnerability_alert(alert):
    """True, wenn der Alert einen Vulnerability-Datensatz enthaelt."""
    return bool(alert.get("data", {}).get("vulnerability"))


def build_payload(alert):
    """
    Baut das Ziel-JSON im gewuenschten Format:
    [ { "body": { "full_alert": { "agent": {...},
                                  "data": { "vulnerability": {...} } } } } ]
    """
    vuln = alert.get("data", {}).get("vulnerability", {})
    agent = alert.get("agent", {})

    full_alert = {
        "agent": {
            "name": agent.get("name"),
            "ip": agent.get("ip"),
        },
        "data": {
            "vulnerability": vuln,
        },
    }

    # Willst du stattdessen den KOMPLETTEN Rohalarm mitschicken,
    # ersetze die Zeile oben einfach durch:
    #     full_alert = alert

    return [{"body": {"full_alert": full_alert}}]


def send(payload, hook_url, api_key):
    """Sendet das Payload per HTTP POST an das Vuln-Management-Tool."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_key:
        # Auth-Schema ggf. an dein Tool anpassen:
        # Bearer / X-API-Key / Basic ...
        headers["Authorization"] = f"Bearer {api_key}"

    return requests.post(
        hook_url,
        data=json.dumps(payload),
        headers=headers,
        timeout=TIMEOUT,
        verify=VERIFY_TLS,
    )


# ---------------------------------------------------------------------------
# Hauptlogik
# ---------------------------------------------------------------------------
def main(argv):
    global debug_enabled

    if len(argv) < 4:
        log("ERROR: Zu wenige Argumente. Aufruf: "
            "custom-vulnmgmt.py <alert_file> <api_key> <hook_url> [debug]")
        sys.exit(1)

    alert_file = argv[1]
    api_key = argv[2]
    hook_url = argv[3]
    debug_enabled = len(argv) > 4 and "debug" in argv[4]

    debug(f"Aufruf: file={alert_file} hook={hook_url}")

    # Alert einlesen
    try:
        alert = load_alert(alert_file)
    except Exception as e:
        log(f"ERROR: Alert-Datei konnte nicht gelesen/geparst werden: {e}")
        sys.exit(1)

    # Nur Vulnerability-Alerts verarbeiten (Sicherheitsnetz zusaetzlich
    # zum <group>-Filter in der ossec.conf)
    if not is_vulnerability_alert(alert):
        debug("Kein Vulnerability-Alert - wird uebersprungen.")
        sys.exit(0)

    payload = build_payload(alert)
    debug(f"Payload: {json.dumps(payload)}")

    # Senden
    try:
        resp = send(payload, hook_url, api_key)
    except requests.exceptions.RequestException as e:
        log(f"ERROR: Request fehlgeschlagen: {e}")
        sys.exit(1)

    cve = alert.get("data", {}).get("vulnerability", {}).get("cve", "?")
    if 200 <= resp.status_code < 300:
        log(f"OK: {cve} gesendet (HTTP {resp.status_code}).")
    else:
        log(f"ERROR: Tool antwortete mit HTTP {resp.status_code} "
            f"fuer {cve}: {resp.text[:500]}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        log(f"ERROR: Unerwarteter Fehler: {e}")
        sys.exit(1)
