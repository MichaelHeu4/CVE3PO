import defusedxml.ElementTree as ET

from vuln_manager.models import Port
from vuln_manager.utils.identity import resolve_host


def parse_nmap_xml(file_path, scan_obj):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for host in root.findall("host"):
        address_elem = host.find("address[@addrtype='ipv4']")
        if address_elem is None:
            continue
        ip = address_elem.get("addr")
        hostname_elem = host.find("hostnames/hostname")
        hostname = hostname_elem.get("name") if hostname_elem is not None else ""

        host_obj, _ = resolve_host(
            ip_address=ip, hostname=hostname or None, source="nmap"
        )
        if hostname and not host_obj.hostname:
            host_obj.hostname = hostname
            host_obj.save(update_fields=["hostname"])

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
