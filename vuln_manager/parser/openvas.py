import defusedxml.ElementTree as ET

from vuln_manager.models import Host, Port, Software
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability


def _text(node, path):
    found = node.find(path)
    if found is not None and found.text is not None:
        return found.text.strip()
    return None


def _parse_port_number(port_text):
    if not port_text or "/" not in port_text:
        return None
    try:
        return int(port_text.split("/")[0])
    except ValueError:
        return None


def _extract_cve_id(nvt):
    if nvt is None:
        return None
    for ref in nvt.findall("refs/ref"):
        if (ref.get("type") or "").lower() == "cve":
            cve = (ref.get("id") or "").strip()
            if cve:
                return cve.upper()
    return nvt.get("oid")


def _severity_from_score(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def parse_openvas_xml(file_path, scan_obj):
    tree = ET.parse(file_path)
    root = tree.getroot()
    for result in root.findall(".//result"):
        ip = _text(result, "host")
        if not ip:
            continue

        nvt = result.find("nvt")
        cve_id = _extract_cve_id(nvt)
        if not cve_id:
            continue

        port_num = _parse_port_number(_text(result, "port"))
        host_obj, _ = Host.objects.get_or_create(ip_address=ip)

        sw_obj = None
        port_obj = None
        if port_num:
            port_obj = Port.objects.filter(host=host_obj, port_number=port_num).first()
            sw_obj = Software.objects.filter(
                hosts=host_obj, listening_port=port_num
            ).first()

        cvss_raw = _text(result, "nvt/cvss_base") or _text(result, "severity")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else 0.0
        except ValueError:
            cvss = 0.0

        create_or_update_vulnerability(
            host=host_obj,
            scan=scan_obj,
            software=sw_obj,
            port=port_obj,
            cve_id=cve_id,
            severity=_severity_from_score(cvss),
            name=_text(result, "name") or cve_id,
            description=_text(result, "description") or "",
            actor="openvas_parser",
        )
