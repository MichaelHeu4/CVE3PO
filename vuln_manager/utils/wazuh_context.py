"""Optional, read-only Wazuh Syscollector integration for the context pilot."""
import os
import re
from urllib.parse import urlsplit

import requests

MAX_ITEMS = 5000
PAGE_SIZE = 500


def fetch_wazuh_context(agent_id):
    if not re.fullmatch(r"[0-9]{1,12}", agent_id):
        raise ValueError("Invalid Wazuh agent ID")
    base = os.environ.get("WAZUH_CONTEXT_API_URL", "").strip().rstrip("/")
    username = os.environ.get("WAZUH_CONTEXT_API_USER", "")
    password = os.environ.get("WAZUH_CONTEXT_API_PASSWORD", "")
    parsed = urlsplit(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Wazuh context API must be configured with an HTTPS URL")
    if not username or not password:
        raise ValueError("Wazuh context API credentials are missing")
    with requests.Session() as session:
        auth = session.get(base + "/security/user/authenticate", auth=(username, password),
                           timeout=(5, 20), allow_redirects=False)
        auth.raise_for_status()
        if auth.status_code != 200:
            raise ValueError("Unexpected Wazuh authentication response")
        token = auth.json()["data"]["token"]
        headers = {"Authorization": "Bearer " + token}
        results = []
        for kind in ("ports", "processes"):
            entries = []
            while True:
                response = session.get(f"{base}/syscollector/{agent_id}/{kind}", headers=headers,
                                       params={"limit": PAGE_SIZE, "offset": len(entries)},
                                       timeout=(5, 20), allow_redirects=False)
                response.raise_for_status()
                if response.status_code != 200:
                    raise ValueError("Unexpected Wazuh response")
                body = response.json()
                data = body["data"]
                if body.get("error") or data.get("total_failed_items", 0):
                    raise ValueError("Wazuh returned an incomplete result")
                page = data["affected_items"]
                total = data["total_affected_items"]
                if not isinstance(page, list) or not isinstance(total, int) or total > MAX_ITEMS:
                    raise ValueError("Invalid or oversized Wazuh result")
                entries.extend(page)
                if len(entries) >= total:
                    break
                if not page:
                    raise ValueError("Incomplete Wazuh pagination")
            # Avoid collecting command lines or process arguments, which may contain secrets.
            keys = ({"local", "protocol", "state", "pid", "process", "scan"} if kind == "ports" else
                    {"pid", "name", "start_time", "scan"})
            results.append([{key: item[key] for key in keys if key in item} for item in entries])
        return results
