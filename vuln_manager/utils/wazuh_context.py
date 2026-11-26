"""Optional, read-only Wazuh Syscollector integration for the context pilot."""
import os
import re
from urllib.parse import urlsplit

import requests
from vuln_manager.models import Host, HostAddress, SystemSettings, WazuhContextSnapshot

MAX_ITEMS = 5000
PAGE_SIZE = 500

# These are package-name hints, not proof of executable ownership.
PROCESS_PACKAGE_HINTS = {
    "sshd": {"openssh-server", "openssh"},
    "smbd": {"samba", "samba-server"},
    "nmbd": {"samba", "samba-server"},
    "winbindd": {"winbind", "samba-winbind"},
    "httpd": {"httpd", "apache2"},
    "apache2": {"apache2", "httpd"},
    "mysqld": {"mysql-server", "mariadb-server"},
    "mariadbd": {"mariadb-server"},
    "postgres": {"postgresql", "postgresql-server"},
}
CONTAINER_PROXIES = {"docker-proxy", "rootlesskit-docker-proxy"}


def _process_name(value):
    name = str(value or "").replace("\\", "/").rsplit("/", 1)[-1].casefold()
    return name[:-4] if name.endswith(".exe") else name


def _executable_path(value):
    """Retain an absolute executable only, never command-line arguments."""
    value = value if isinstance(value, str) else ""
    if re.fullmatch(r"/[A-Za-z0-9_./+@-]{1,500}", value):
        return value
    return ""


def port_category(port):
    state = str(port.get("state") or "").strip().casefold().replace("-", "_")
    protocol = str(port.get("protocol") or "").strip().casefold()
    if state in {"listen", "listening"}:
        return "listening"
    if state in {"established", "syn_sent", "syn_recv", "syn_received", "fin_wait1", "fin_wait2", "fin_wait_1", "fin_wait_2", "close_wait", "closing", "last_ack", "time_wait"}:
        return "connections"
    if protocol.startswith("udp") and state in {"", "unknown", "none"}:
        return "udp_unknown"
    return "other"


def wazuh_api_config():
    settings = SystemSettings.objects.filter(pk=1).first()
    if settings and any((settings.wazuh_api_url, settings.wazuh_api_user, settings.wazuh_api_password)):
        base, username, password = settings.wazuh_api_url, settings.wazuh_api_user, settings.wazuh_api_password
    else:
        base, username, password = (os.environ.get("WAZUH_CONTEXT_API_URL", ""), os.environ.get("WAZUH_CONTEXT_API_USER", ""),
                                    os.environ.get("WAZUH_CONTEXT_API_PASSWORD", ""))
    base = base.strip().rstrip("/")
    username = username.strip()
    return base, username, password


def validate_api_url(base):
    try:
        parsed = urlsplit(base)
        return bool(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                    and not parsed.query and not parsed.fragment and parsed.port != 0)
    except ValueError:
        return False


def wazuh_verify_ssl():
    settings = SystemSettings.objects.filter(pk=1).only("wazuh_verify_ssl").first()
    return settings.wazuh_verify_ssl if settings else True


def fetch_wazuh_agents(heartbeat=None):
    """Read the complete Wazuh agent list; incomplete lists are not used for matching."""
    base, username, password = wazuh_api_config()
    if not validate_api_url(base) or not username or not password:
        raise ValueError("Wazuh HTTPS API configuration is missing or invalid")
    verify = wazuh_verify_ssl()
    with requests.Session() as session:
        response = session.post(base + "/security/user/authenticate", auth=(username, password), timeout=(5, 20), allow_redirects=False, verify=verify)
        response.raise_for_status()
        if response.status_code != 200:
            raise ValueError("Unexpected Wazuh authentication response")
        headers = {"Authorization": "Bearer " + response.json()["data"]["token"]}
        agents = []
        while True:
            if heartbeat:
                heartbeat()
            response = session.get(base + "/agents", headers=headers, params={"limit": PAGE_SIZE, "offset": len(agents)}, timeout=(5, 20), allow_redirects=False, verify=verify)
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
    """Associate only unique inventory matches and record the evidence used."""
    names = {}
    for software in host.software_inventory.all():
        names.setdefault(_process_name(software.name), []).append(software)
    by_pid = {}
    for process in processes:
        if process.get("pid") not in (None, 0, "0", ""):
            by_pid.setdefault(str(process["pid"]), []).append(process)
    matches = []
    for index, port in enumerate(ports):
        if not isinstance(port, dict):
            continue
        process = port.get("process") or ""
        pid_matches = by_pid.get(str(port.get("pid")), [])
        detail = pid_matches[0] if len(pid_matches) == 1 else {}
        if process and detail.get("name") and _process_name(process) != _process_name(detail["name"]):
            detail = {}
        if not process:
            process = detail.get("name") or ""
        executable = _executable_path(detail.get("cmd"))
        if not process and executable:
            process = _process_name(executable)
        name = _process_name(process)
        if name in CONTAINER_PROXIES:
            continue
        candidates = names.get(name, []) if name else []
        basis = "Exact process and software name"
        if not candidates and name in PROCESS_PACKAGE_HINTS:
            candidates = [item for hint in PROCESS_PACKAGE_HINTS[name] for item in names.get(hint, [])]
            basis = "Known process-to-package name"
        # Postfix master is a generic name; require a distinctive executable path.
        if not candidates and name == "master" and executable and "/postfix/" in executable.casefold():
            candidates = names.get("postfix", [])
            basis = "Postfix executable path"
        if len(candidates) == 1:
            matches.append({"software_id": candidates[0].pk, "software_name": candidates[0].name,
                            "port_index": index, "executable": executable,
                            "process": process, "pid": port.get("pid"), "local": port.get("local"),
                            "protocol": port.get("protocol"), "state": port.get("state"), "scan": port.get("scan"),
                            "basis": basis})
    return matches


def snapshot_port_rows(snapshot):
    """Format every observation, including ports without a software match."""
    if snapshot is None:
        return []
    matches = {item["port_index"]: item for item in map_software(snapshot.host, snapshot.ports, snapshot.processes)}
    processes = {}
    for process in snapshot.processes:
        if isinstance(process, dict) and process.get("pid") not in (None, "", 0, "0"):
            processes.setdefault(str(process["pid"]), []).append(process)
    rows = []
    for index, port in enumerate(snapshot.ports):
        if not isinstance(port, dict):
            continue
        local = port.get("local") or {}
        if not isinstance(local, dict):
            continue
        match = matches.get(index, {})
        pid_records = processes.get(str(port.get("pid")), [])
        detail = pid_records[0] if len(pid_records) == 1 else {}
        process_name = port.get("process") or match.get("process") or detail.get("name") or ""
        if port.get("process") and detail.get("name") and _process_name(port["process"]) != _process_name(detail["name"]):
            detail = {}
        is_proxy = _process_name(process_name) in CONTAINER_PROXIES
        rows.append({"host": snapshot.host, "port": local.get("port"), "address": local.get("ip"),
                     "protocol": port.get("protocol") or "", "state": port.get("state") or "",
                     "pid": port.get("pid"), "process": process_name,
                     "software_id": match.get("software_id"), "software_name": match.get("software_name"),
                     "mapping_basis": match.get("basis", ""), "executable": match.get("executable") or _executable_path(detail.get("cmd")),
                     "is_container_proxy": is_proxy, "category": port_category(port),
                     "scan": port.get("scan") or {}, "fetched_at": snapshot.fetched_at, "agent_id": snapshot.agent_id})
    return rows


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
    base, username, password = wazuh_api_config()
    if not validate_api_url(base):
        raise ValueError("Wazuh context API must be configured with an HTTPS URL")
    if not username or not password:
        raise ValueError("Wazuh context API credentials are missing")
    verify = wazuh_verify_ssl()
    with requests.Session() as session:
        auth = session.post(base + "/security/user/authenticate", auth=(username, password),
                           timeout=(5, 20), allow_redirects=False, verify=verify)
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
                                       timeout=(5, 20), allow_redirects=False, verify=verify)
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
            sanitized = [{key: item[key] for key in keys if key in item} for item in entries]
            if kind == "processes":
                for original, record in zip(entries, sanitized):
                    executable = _executable_path(original.get("cmd"))
                    if executable:
                        record["cmd"] = executable
            results.append(sanitized)
        return results
