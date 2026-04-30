import json
import re
from cvss import CVSS3, CVSS4
from vuln_manager.models import Vulnerability


POC_REGEX = re.compile(r"(?is)###\s*poc.*?(?=###|$)", re.I)


def normalize_severity_from_score(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def extract_cvss_base_score(cvss_vector):
    """
    Unterstützt CVSS v3.x und v4.0 Vector-Strings grob über cvss Library.
    pip install cvss
    """
    if not cvss_vector:
        return None

    try:
        if cvss_vector.startswith("CVSS:4.0"):
            return CVSS4(cvss_vector).scores()[0]

        if cvss_vector.startswith(("CVSS:3.0", "CVSS:3.1")):
            return CVSS3(cvss_vector).scores()[0]

    except Exception:
        return None

    return None


def extract_severity(vuln):
    # 1. Bevorzugt CVSS aus OSV severity[]
    for item in vuln.get("severity", []):
        score_type = item.get("type")
        score_value = item.get("score")

        if score_type in ("CVSS_V3", "CVSS_V4"):
            base_score = extract_cvss_base_score(score_value)
            if base_score is not None:
                return (score_value, normalize_severity_from_score(base_score))

    # 2. Fallback: database_specific.severity
    database_specific = vuln.get("database_specific", {})
    sev_raw = database_specific.get("severity", "UNKNOWN").lower()

    if sev_raw == "critical":
        return (None, "critical")
    if sev_raw == "high":
        return (None, "high")
    if sev_raw in ("moderate", "medium"):
        return (None, "medium")
    if sev_raw == "low":
        return (None, "low")

    return (None, "info")


def extract_cve_id(vuln):
    ids = []

    osv_id = vuln.get("id")
    if osv_id:
        ids.append(osv_id)

    ids.extend(vuln.get("aliases", []))

    for entry in ids:
        if str(entry).startswith("CVE-"):
            return entry

    return osv_id or "OSV-Unknown"


def extract_poc_from_description(description):
    poc = None
    desc = description or "No description provided."

    if "### PoC" in desc:
        match = POC_REGEX.search(desc)
        if match:
            poc = match.group(0)
            desc = POC_REGEX.sub("", desc).strip()

    return desc, poc


def parse_osv_json(file_path, scan_obj, software_obj=None):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = []

    # Variante 1: OSV-Scanner Format
    for result in data.get("results", []):
        for package in result.get("packages", []):
            vulnerabilities.extend(package.get("vulnerabilities", []))

    # Variante 2: OSV API Format
    vulnerabilities.extend(data.get("vulns", []))

    # Variante 3: Einzelnes OSV Advisory
    if data.get("schema_version") and data.get("id"):
        vulnerabilities.append(data)

    for vuln in vulnerabilities:
        description = vuln.get("details", "No description provided.")
        summary = vuln.get("summary", "No summary provided.")

        description, poc = extract_poc_from_description(description)

        cvss_score, severity = extract_severity(vuln)
        if (cvss_score):
            print(extract_cve_id(vuln) + " CVSS: " + cvss_score)
        
        Vulnerability.objects.create(
            host=None,
            scan=scan_obj,
            software=software_obj,
            cve_id=extract_cve_id(vuln),
            cvss=cvss_score,
            severity=severity,
            name=f"OSV: {summary}",
            description=description,
            nuclei_poc=poc,
            supply_chain=True,
        )
