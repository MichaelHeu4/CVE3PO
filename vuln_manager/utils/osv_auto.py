import logging
import os

import requests

import re
from packaging import version
from vuln_manager.models import Scan, Software
from vuln_manager.parser.osvscanner import (
    extract_cve_id,
    extract_poc_from_description,
    extract_severity,
)
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability


logger = logging.getLogger(__name__)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NVD_QUERY_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE = 50
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()


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
        ecosystems = ["Debian", "Ubuntu", "PyPI",
                      "npm", "Maven", "Go", "crates.io"]

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


def _nvd_headers():
    if not NVD_API_KEY:
        return {}
    return {"apiKey": NVD_API_KEY}


def _candidate_nvd_keywords(software):
    name = (software.name or "").strip()
    version = (software.version or "").strip()
    vendor = (software.vendor or "").strip()

    candidates = []
    if vendor and name and version:
        candidates.append(f"{vendor} {name} {version}")
    if name and version:
        candidates.append(f"{name} {version}")
    if vendor and name:
        candidates.append(f"{vendor} {name}")
    if name:
        candidates.append(name)

    seen = set()
    deduped = []
    for keyword in candidates:
        normalized = keyword.lower()
        if normalized in seen:
            continue
        deduped.append(keyword)
        seen.add(normalized)
    return deduped


def _query_nvd_by_keyword(keyword):
    response = requests.get(
        NVD_QUERY_URL,
        params={"keywordSearch": keyword,
                "resultsPerPage": NVD_RESULTS_PER_PAGE},
        headers=_nvd_headers(),
        timeout=15,
    )
    response.raise_for_status()
    records = response.json().get("vulnerabilities", [])
    return [entry.get("cve", {}) for entry in records if entry.get("cve")]


def _extract_nvd_description(cve):
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en" and description.get("value"):
            return description["value"]
    return "No description provided."


def _extract_nvd_cvss_and_severity(cve):
    metric_order = ["cvssMetricV40", "cvssMetricV31",
                    "cvssMetricV30", "cvssMetricV2"]
    metrics = cve.get("metrics", {})

    for metric_name in metric_order:
        entries = metrics.get(metric_name, [])
        if not entries:
            continue
        metric = entries[0]
        cvss_data = metric.get("cvssData", {})

        vector = cvss_data.get("vectorString")
        base_score = cvss_data.get("baseScore")
        severity_raw = cvss_data.get(
            "baseSeverity") or metric.get("baseSeverity")

        if severity_raw:
            normalized = severity_raw.lower()
            if normalized in {"critical", "high", "medium", "low"}:
                return vector, normalized

        if base_score is not None:
            return vector, normalize_severity_from_score(float(base_score))

    return None, "info"


def _normalize_and_parse_version(v_str):
    if not v_str:
        return None
    # Konvertiert OpenSSL-Styles wie "1.0.1g" in PEP 440-Styles wie "1.0.1+g"
    normalized = re.sub(r"^([\d\.]+)([a-zA-Z]+)$", r"\1+\2", v_str)
    try:
        return version.parse(normalized)
    except Exception:
        return None


def _cve_matches_software(cve, software):
    name = (software.name or "").lower().strip()
    version_str = (software.version or "").lower().strip()

    target_v = _normalize_and_parse_version(
        version_str) if version_str else None

    configurations = cve.get("configurations", [])
    has_cpes = False

    def _cpe_matches(node):
        for cpe in node.get("cpeMatch", []):
            criteria = str(cpe.get("criteria", "")).lower()

            parts = criteria.split(":")
            if len(parts) < 6:
                continue

            cpe_product = parts[4]
            cpe_version = parts[5]

            if name and name not in cpe_product:
                continue

            if not version_str:
                return True

            if cpe_version not in ["*", "-"] and version_str == cpe_version:
                return True

            if cpe_version in ["*", "-"]:
                v_start_inc = cpe.get("versionStartIncluding")
                v_start_exc = cpe.get("versionStartExcluding")
                v_end_inc = cpe.get("versionEndIncluding")
                v_end_exc = cpe.get("versionEndExcluding")

                if not any([v_start_inc, v_start_exc, v_end_inc, v_end_exc]):
                    return True

                if target_v:
                    try:
                        if v_start_inc and target_v < version.parse(v_start_inc):
                            continue  # Version ist zu alt
                        if v_start_exc and target_v <= version.parse(v_start_exc):
                            continue  # Version ist zu alt
                        if v_end_inc and target_v > version.parse(v_end_inc):
                            continue  # Version ist zu neu
                        if v_end_exc and target_v >= version.parse(v_end_exc):
                            continue  # Version ist zu neu

                        return True
                    except Exception:
                        pass

        for child in node.get("children", []):
            if _cpe_matches(child):
                return True
        return False

    for config in configurations:
        for node in config.get("nodes", []):
            has_cpes = True
            if _cpe_matches(node):
                return True

    if has_cpes:
        return False

    description = _extract_nvd_description(cve).lower()
    if name and name not in description:
        return False
    if version_str and version_str not in description:
        return False

    return True


def _collect_nvd_vulns(software):
    vulns_by_id = {}
    keywords = _candidate_nvd_keywords(software)

    for keyword in keywords:
        try:
            cves = _query_nvd_by_keyword(keyword)
        except Exception:
            logger.exception(
                "NVD query failed for software '%s' keyword '%s'",
                software.name,
                keyword,
            )
            continue

        for cve in cves:
            cve_id = cve.get("id")
            if not cve_id or cve_id in vulns_by_id:
                continue
            if not _cve_matches_software(cve, software):
                continue
            vulns_by_id[cve_id] = cve

    return vulns_by_id.values()


def enrich_software_with_feeds(software_id):
    software = Software.objects.filter(pk=software_id).first()
    if not software or not software.version:
        return

    scan_obj, _ = Scan.objects.get_or_create(
        scan_type="OSV", defaults={"raw_file": None}
    )
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

    nvd_scan_obj, _ = Scan.objects.get_or_create(
        scan_type="NVD", defaults={"raw_file": None}
    )
    for cve in _collect_nvd_vulns(software):
        cve_id = (cve.get("id") or "CVE-Unknown").upper()
        description = _extract_nvd_description(cve)
        cvss_score, severity = _extract_nvd_cvss_and_severity(cve)

        create_or_update_vulnerability(
            scan=nvd_scan_obj,
            software=software,
            cve_id=cve_id,
            cvss=cvss_score,
            severity=severity,
            name=f"NVD: {cve_id}",
            description=description,
            supply_chain=True,
            actor="nvd_auto",
        )


def enrich_software_with_osv(software_id):
    """
    Backwards compatible wrapper: keeps existing call sites while running
    the combined software enrichment flow (OSV + NVD).
    """
    enrich_software_with_feeds(software_id)
