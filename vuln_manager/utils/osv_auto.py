import logging

import requests

from vuln_manager.models import Scan, Software
from vuln_manager.parser.osvscanner import (
    extract_cve_id,
    extract_poc_from_description,
    extract_severity,
)
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability


logger = logging.getLogger(__name__)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _looks_like_debian_revision(version):
    v = (version or "").lower()
    return any(token in v for token in ["~deb", "+deb", "ubuntu", "debian"])


def _candidate_ecosystems(software):
    vendor = (software.vendor or "").lower()
    name = (software.name or "").lower()
    version = software.version or ""

    ecosystems = []

    if (
        "debian" in vendor
        or "ubuntu" in vendor
        or "apt" in vendor
        or _looks_like_debian_revision(version)
    ):
        ecosystems.extend(["Debian", "Ubuntu"])

    if any(token in vendor for token in ["python", "pypi"]) or name.startswith("py"):
        ecosystems.append("PyPI")
    if any(token in vendor for token in ["node", "npm", "javascript"]):
        ecosystems.append("npm")
    if any(token in vendor for token in ["java", "maven"]):
        ecosystems.append("Maven")
    if any(token in vendor for token in ["golang", "go"]):
        ecosystems.append("Go")
    if any(token in vendor for token in ["rust", "cargo"]):
        ecosystems.append("crates.io")
    if any(token in vendor for token in ["ruby", "rubygems"]):
        ecosystems.append("RubyGems")
    if any(token in vendor for token in ["nuget", ".net", "dotnet"]):
        ecosystems.append("NuGet")
    if any(token in vendor for token in ["php", "composer", "packagist"]):
        ecosystems.append("Packagist")

    if not ecosystems:
        ecosystems = ["Debian", "Ubuntu", "PyPI", "npm", "Maven", "Go", "crates.io"]

    seen = set()
    deduped = []
    for eco in ecosystems:
        if eco not in seen:
            deduped.append(eco)
            seen.add(eco)
    return deduped


def _query_osv(name, version, ecosystem):
    payload = {
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }
    response = requests.post(OSV_QUERY_URL, json=payload, timeout=10)
    response.raise_for_status()
    return response.json().get("vulns", [])


def enrich_software_with_osv(software_id):
    software = Software.objects.filter(pk=software_id).first()
    if not software or not software.version:
        return

    scan_obj, _ = Scan.objects.get_or_create(scan_type="OSV", defaults={"raw_file": None})
    ecosystems = _candidate_ecosystems(software)

    for ecosystem in ecosystems:
        try:
            vulns = _query_osv(software.name, software.version, ecosystem)
        except Exception:
            logger.exception(
                "OSV query failed for software '%s' ecosystem '%s'",
                software.name,
                ecosystem,
            )
            continue

        for vuln in vulns:
            description = vuln.get("details", "No description provided.")
            summary = vuln.get("summary", "No summary provided.")
            description, poc = extract_poc_from_description(description)
            cvss_score, severity = extract_severity(vuln)

            create_or_update_vulnerability(
                scan=scan_obj,
                software=software,
                cve_id=extract_cve_id(vuln),
                cvss=cvss_score,
                severity=severity,
                name=f"OSV: {summary}",
                description=description,
                nuclei_poc=poc,
                supply_chain=True,
                actor=f"osv_auto:{ecosystem}",
            )
