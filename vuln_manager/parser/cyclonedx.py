import json
import re

from vuln_manager.models import Software
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability


def _normalize_vendor(component):
    candidate = component.get("publisher") or component.get("author")
    if candidate:
        return str(candidate).strip()[:255] or None
    purl = component.get("purl") or ""
    # Example: pkg:deb/debian/libssl3@3.0.13-1
    match = re.match(r"^pkg:[^/]+/([^/]+)/", purl)
    if match:
        return match.group(1).strip()[:255] or None
    return None


def _extract_severity_and_cvss(vuln):
    ratings = vuln.get("ratings") or []
    for rating in ratings:
        if not isinstance(rating, dict):
            continue
        severity_raw = str(rating.get("severity", "")).lower()
        vector = rating.get("vector")
        if severity_raw in {"critical", "high", "medium", "low", "info"}:
            return severity_raw, vector
    return "info", None


def _extract_cve_id(vuln):
    vuln_id = str(vuln.get("id") or "").strip()
    if vuln_id.upper().startswith("CVE-"):
        return vuln_id.upper()
    source = vuln.get("source") or {}
    source_name = str(source.get("name") or "").strip()
    if source_name:
        return vuln_id or source_name
    return vuln_id or "CYCLONEDX-UNKNOWN"


def parse_cyclonedx_json(file_path, scan_obj, software_obj=None):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    components = data.get("components", [])
    ref_to_software = {}

    for component in components:
        if not isinstance(component, dict):
            continue
        name = (component.get("name") or "").strip()
        if not name:
            continue
        version = component.get("version")
        vendor = _normalize_vendor(component)

        sw_obj, _ = Software.objects.get_or_create(
            name=name,
            version=version,
            vendor=vendor,
            listening_port=None,
        )
        bom_ref = component.get("bom-ref")
        if bom_ref:
            ref_to_software[str(bom_ref)] = sw_obj

    vulnerabilities = data.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        severity, cvss = _extract_severity_and_cvss(vuln)
        description = vuln.get("description") or vuln.get("detail") or "No description provided."
        cve_id = _extract_cve_id(vuln)
        vuln_name = str(vuln.get("id") or cve_id or "Unknown")

        affected_refs = []
        for affected in vuln.get("affects", []):
            if isinstance(affected, dict) and affected.get("ref"):
                affected_refs.append(str(affected["ref"]))

        target_software = [ref_to_software[ref] for ref in affected_refs if ref in ref_to_software]
        if not target_software and software_obj:
            target_software = [software_obj]
        if not target_software:
            target_software = [None]

        for target in target_software:
            create_or_update_vulnerability(
                scan=scan_obj,
                software=target,
                cve_id=cve_id,
                cvss=cvss,
                severity=severity,
                name=f"CycloneDX: {vuln_name}",
                description=description,
                supply_chain=True,
                actor="cyclonedx_parser",
            )
