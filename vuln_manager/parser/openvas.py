import xml.etree.ElementTree as ET

from vuln_manager.models import Host, Port, Vulnerability, Software


def parse_openvas_xml(file_path, scan_obj):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for result in root.findall(".//result"):
        ip = result.find("host").text
        port_text = result.find("port").text
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
