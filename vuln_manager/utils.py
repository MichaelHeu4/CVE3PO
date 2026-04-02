import xml.etree.ElementTree as ET
import json
from .models import Host, Vulnerability, Port, Software
from collections import Counter
import re


def is_valid_ip(address):
    # Simple check for IP or Hostname
    return True


def parse_nmap_xml(file_path, scan_obj):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for host in root.findall("host"):
        ip = host.find("address[@addrtype='ipv4']").get("addr")
        hostname_elem = host.find("hostnames/hostname")
        hostname = hostname_elem.get("name") if hostname_elem is not None else ""

        host_obj, _ = Host.objects.get_or_create(ip_address=ip)
        if hostname:
            host_obj.hostname = hostname
            host_obj.save()

        for port in host.findall("ports/port"):
            port_id = port.get("portid")
            state = port.find("state").get("state")
            service = (
                port.find("service").get("name")
                if port.find("service") is not None
                else "unknown"
            )

            if state == "open":
                Port.objects.create(
                    host=host_obj,
                    scan=scan_obj,
                    port_number=int(port_id),
                    service_name=service,
                    state=state,
                )


def parse_nuclei_jsonl(file_path, scan_obj):
    # Pass 1: Count IPs per Hostname
    hostname_ips = {}
    with open(file_path, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                h = data.get("host")
                ip = data.get("ip")
                if h and ip:
                    if h not in hostname_ips:
                        hostname_ips[h] = []
                    hostname_ips[h].append(ip)
            except:
                continue

    # Majority vote for stable IP mapping
    stable_map = {}
    for h, ips in hostname_ips.items():
        stable_map[h] = Counter(ips).most_common(1)[0][0]

    # Pass 2: Import
    with open(file_path, "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                raw_host = data.get("host")
                ip = data.get("ip") or stable_map.get(raw_host)
                if not ip:
                    continue

                host_obj, _ = Host.objects.get_or_create(ip_address=ip)

                # Extract port: Check explicit field first, then fallback to regex
                port_num = data.get("port")
                if port_num:
                    port_num = int(port_num)
                else:
                    port_match = re.search(r":(\d+)", raw_host)
                    if port_match:
                        port_num = int(port_match.group(1))
                    elif raw_host.startswith("http://"):
                        port_num = 80
                    elif raw_host.startswith("https://"):
                        port_num = 443

                # Smart software routing
                sw_obj = None
                port_obj = None
                if port_num:
                    port_obj = Port.objects.filter(
                        host=host_obj, port_number=port_num
                    ).first()
                    sw_obj = Software.objects.filter(
                        hosts=host_obj, listening_port=port_num
                    ).first()

                severity = data.get("info", {}).get("severity", "info").lower()

                poc = (
                    data.get("curl-command")
                    or data.get("request")
                    or str(data.get("extracted-results", ""))
                )

                Vulnerability.objects.create(
                    host=host_obj,
                    scan=scan_obj,
                    software=sw_obj,
                    port=port_obj,
                    cve_id=data.get("template-id"),
                    severity=severity,
                    name=data.get("info", {}).get("name", "Nuclei Finding"),
                    description=data.get("info", {}).get("description", ""),
                    nuclei_poc=poc,
                )
            except:
                continue


def parse_openvas_xml(file_path, scan_obj):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for result in root.findall(".//result"):
        ip = result.find("host").text
        port_text = result.find("port").text  # e.g. "80/tcp"
        port_num = int(port_text.split("/")[0]) if "/" in port_text else None

        host_obj, _ = Host.objects.get_or_create(ip_address=ip)

        # Smart routing
        sw_obj = None
        port_obj = None
        if port_num:
            port_obj = Port.objects.filter(host=host_obj, port_number=port_num).first()
            sw_obj = Software.objects.filter(
                hosts=host_obj, listening_port=port_num
            ).first()

        cvss = float(result.find("nvt/cvss_base").text or 0)
        severity = "info"
        if cvss >= 9.0:
            severity = "critical"
        elif cvss >= 7.0:
            severity = "high"
        elif cvss >= 4.0:
            severity = "medium"
        elif cvss > 0.0:
            severity = "low"

        Vulnerability.objects.create(
            host=host_obj,
            scan=scan_obj,
            software=sw_obj,
            port=port_obj,
            cve_id=result.find("nvt").get("oid"),
            severity=severity,
            name=result.find("name").text,
            description=result.find("description").text,
        )


def parse_semgrep_json(file_path, scan_obj, software_obj=None):
    with open(file_path, "r") as f:
        data = json.load(f)

    for result in data.get("results", []):
        path = result.get("path")
        check_id = result.get("check_id")
        extra = result.get("extra", {})
        message = extra.get("message")
        sev_raw = extra.get("severity", "INFO").lower()

        severity = "info"
        if sev_raw == "error":
            severity = "high"
        elif sev_raw == "warning":
            severity = "medium"

        # SAST findings are now linked to Software, not a dummy host
        Vulnerability.objects.create(
            host=None,
            scan=scan_obj,
            software=software_obj,
            cve_id=check_id,
            severity=severity,
            name=f"Semgrep: {check_id}",
            description=f"File: {path}\n\n{message}",
            nuclei_poc=extra.get("lines"),
        )


def parse_osv_json(file_path, scan_obj, software_obj=None):
    with open(file_path, "r") as f:
        data = json.load(f)

    for result in data.get("results", []):
        for package in result.get("packages", []):
            cveid = []
            descriptions = []
            summaries = []
            severities = []

            groups = package.get("groups", [])
            for group in groups:
                group_id = group.get("id", [])
                group_alias = group.get("aliases", [])
                group_id.extend(group_alias)

                CVE_FOUND = False
                for id in group_id:
                    if id.startswith("CVE-"):
                        cveid.append(id)
                        CVE_FOUND = True

                if not CVE_FOUND:
                    cveid.append(group_id[0] if group_id else "OSV-Unknown")

            vulnerabilities = package.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                descriptions.append(vuln.get("details", "No description provided."))
                summaries.append(vuln.get("summary", "No summary provided."))
                database_specific = vuln.get("database_specific", {})
                sev_raw = database_specific.get("severity", "UNKNOWN").lower()
                severity = "info"
                if sev_raw == "critical":
                    severity = "critical"
                elif sev_raw == "high":
                    severity = "high"
                elif sev_raw == "moderate":
                    severity = "medium"
                elif sev_raw == "low":
                    severity = "low"
                else:
                    severity = "info"

                severities.append(severity)

            for idx, vuln in enumerate(vulnerabilities):
                desc = descriptions[idx] if idx < len(descriptions) else ""
                sum = summaries[idx] if idx < len(summaries) else ""
                poc = None
                if "### PoC" in desc:
                    poc = desc.split("### PoC", 1)[1].strip().split("###")[0]
                Vulnerability.objects.create(
                    host=None,
                    scan=scan_obj,
                    software=software_obj,
                    cve_id=cveid[idx] if idx < len(cveid) else "OSV-Unknown",
                    severity=severities[idx] if idx < len(severities) else "info",
                    name=f"OSV: {sum}",
                    description=f"{desc}",
                    nuclei_poc=poc,
                    supply_chain=True,
                )
