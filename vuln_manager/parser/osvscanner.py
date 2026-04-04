import json
from vuln_manager.models import Vulnerability
import re


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
                    regex = re.compile(r"(?is)###\s*poc.*?(?=###)", re.I)
                    poc = regex.search(desc)
                    if poc:
                        poc = poc.group(0)
                        desc = re.sub(regex, "", desc)
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
