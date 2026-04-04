import json
from vuln_manager.models import Vulnerability


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
