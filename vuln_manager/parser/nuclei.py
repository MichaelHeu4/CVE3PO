import json
import re

from vuln_manager.models import Host, Port, Vulnerability, Software


def parse_nuclei_jsonl(file_path, scan_obj):
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

    stable_map = {}
    for h, ips in hostname_ips.items():
        stable_map[h] = Counter(ips).most_common(1)[0][0]

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
