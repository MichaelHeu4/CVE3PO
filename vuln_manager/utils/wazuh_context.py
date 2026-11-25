"""Optional, read-only Wazuh Syscollector integration for the context pilot."""
import os
import re
from urllib.parse import urlsplit

import requests
from vuln_manager.models import Host, HostAddress, WazuhContextSnapshot

MAX_ITEMS = 5000
PAGE_SIZE = 500


def fetch_wazuh_agents(heartbeat=None):
    """Read the complete Wazuh agent list; incomplete lists are not used for matching."""
    base = os.environ.get("WAZUH_CONTEXT_API_URL", "").strip().rstrip("/")
    username, password = os.environ.get("WAZUH_CONTEXT_API_USER", ""), os.environ.get("WAZUH_CONTEXT_API_PASSWORD", "")
    parsed = urlsplit(base)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or not username or not password:
        raise ValueError("Wazuh HTTPS API configuration is missing or invalid")
    with requests.Session() as session:
        response = session.get(base + "/security/user/authenticate", auth=(username, password), timeout=(5, 20), allow_redirects=False)
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError("Unexpected Wazuh authentication response")
        headers = {"Authorization": "Bearer " + response.json()["data"]["token"]}
        agents = []
        while True:
            if heartbeat:
                heartbeat()
            response = session.get(base + "/agents", headers=headers, params={"limit": PAGE_SIZE, "offset": len(agents)}, timeout=(5, 20), allow_redirects=False)
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError("Unexpected Wazuh agents response")
            body = response.json()
            data = body["data"]
            page, total = data["affected_items"], data["total_affected_items"]
            if body.get("error") or data.get("total_failed_items", 0) or not isinstance(page, list) or not isinstance(total, int) or total > 100000:
                raise ValueError("Invalid or incomplete Wazuh agents response")
            agents.extend(page)
            if len(agents) >= total:
                return agents
            if not page:
                raise ValueError("Incomplete Wazuh agents pagination")


def match_hosts(agents):
    """Match unambiguous registered IPs, or unique hostnames for dynamic-IP agents."""
    index = {}
    hostnames = {}
    for host in Host.objects.all():
        index.setdefault(host.ip_address, set()).add(host.pk)
        if host.hostname:
            hostnames.setdefault(host.hostname.strip().casefold(), set()).add(host.pk)
    for host_id, ip in HostAddress.objects.values_list("host_id", "ip_address"):
        index.setdefault(ip, set()).add(host_id)
    candidates = {}
    for agent in agents:
        agent_id, ip = str(agent.get("id", "")), agent.get("ip")
        if not re.fullmatch(r"[0-9]{1,12}", agent_id):
            continue
        if ip and str(ip).casefold() != "any":
            target_ids = index.get(ip, set())
        else:
            target_ids = hostnames.get(str(agent.get("name") or "").strip().casefold(), set())
        if len(target_ids) != 1:
            continue
        for host_id in target_ids:
            candidates.setdefault(host_id, []).append(agent_id)
    return {host_id: ids[0] for host_id, ids in candidates.items() if len(ids) == 1}


def map_software(host, ports, processes):
    """Return suggestions based only on unambiguous exact process/package names."""
    def normal(value):
        name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
        return name[:-4] if name.endswith(".exe") else name
    names = {}
    for software in host.software_inventory.all():
        names.setdefault(normal(software.name), []).append(software)
    by_pid = {}
    for process in processes:
        if process.get("pid") not in (None, 0, "0", ""):
            by_pid.setdefault(str(process["pid"]), []).append(process.get("name", ""))
    matches = []
    for port in ports:
        process = port.get("process") or ""
        if not process and len(by_pid.get(str(port.get("pid")), [])) == 1:
            process = by_pid[str(port["pid"])][0]
        candidates = names.get(normal(process), []) if process else []
        if len(candidates) == 1:
            matches.append({"software_id": candidates[0].pk, "software_name": candidates[0].name,
                            "process": process, "pid": port.get("pid"), "local": port.get("local"),
                            "protocol": port.get("protocol"), "state": port.get("state"), "scan": port.get("scan"),
                            "basis": "exact process and software name; suggested mapping"})
    return matches


def refresh_all_hosts(heartbeat=None):
    mapping = match_hosts(fetch_wazuh_agents(heartbeat=heartbeat))
    all_hosts = list(Host.objects.all())
    summary = {"hosts": len(all_hosts), "matched": len(mapping), "updated": 0, "failed": 0,
               "unmatched_hosts": [{"id": host.pk, "address": host.ip_address} for host in all_hosts if host.pk not in mapping],
               "failed_hosts": []}
    for host in Host.objects.filter(pk__in=mapping).prefetch_related("software_inventory"):
        if heartbeat:
            heartbeat()
        try:
            ports, processes = fetch_wazuh_context(mapping[host.pk])
            WazuhContextSnapshot.objects.create(host=host, agent_id=mapping[host.pk], ports=ports, processes=processes,
                                                software_matches=map_software(host, ports, processes))
            summary["updated"] += 1
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Wazuh context fetch failed for host %s", host.pk)
            summary["failed"] += 1
            summary["failed_hosts"].append({"id": host.pk, "address": host.ip_address})
    return summary


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
