import hashlib

from django.utils import timezone

from vuln_manager.models import Vulnerability
from vuln_manager.utils.audit import log_vulnerability_event


def build_vulnerability_fingerprint(
    *,
    scan_type,
    cve_id,
    host_id,
    software_id,
    port_id,
    name,
    supply_chain,
):
    raw = "|".join(
        [
            str(scan_type or "").lower().strip(),
            str(cve_id or "").upper().strip(),
            str(host_id or ""),
            str(software_id or ""),
            str(port_id or ""),
            str(name or "").strip(),
            "1" if supply_chain else "0",
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def create_or_update_vulnerability(
    *,
    scan,
    cve_id,
    severity,
    name,
    description=None,
    host=None,
    software=None,
    port=None,
    cvss=None,
    nuclei_poc=None,
    supply_chain=False,
    actor=None,
):
    now = timezone.now()
    fingerprint = build_vulnerability_fingerprint(
        scan_type=scan.scan_type,
        cve_id=cve_id,
        host_id=host.id if host else None,
        software_id=software.id if software else None,
        port_id=port.id if port else None,
        name=name,
        supply_chain=supply_chain,
    )

    vuln = Vulnerability.objects.filter(fingerprint=fingerprint).first()
    if vuln:
        old_status = vuln.status
        update_fields = []

        vuln.scan = scan
        update_fields.append("scan")

        if vuln.severity != severity:
            vuln.severity = severity
            update_fields.append("severity")
        if vuln.name != name:
            vuln.name = name
            update_fields.append("name")
        if vuln.description != description:
            vuln.description = description
            update_fields.append("description")
        if vuln.cvss != cvss:
            vuln.cvss = cvss
            update_fields.append("cvss")
        if vuln.nuclei_poc != nuclei_poc:
            vuln.nuclei_poc = nuclei_poc
            update_fields.append("nuclei_poc")
        if vuln.supply_chain != supply_chain:
            vuln.supply_chain = supply_chain
            update_fields.append("supply_chain")

        vuln.last_seen = now
        vuln.detection_count += 1
        update_fields.extend(["last_seen", "detection_count"])

        if vuln.status in {"fixed", "false_positive", "risk_accepted"}:
            vuln.status = "open"
            update_fields.append("status")
            log_vulnerability_event(
                vuln,
                "reopened",
                actor=actor,
                details={"from_status": old_status, "to_status": "open"},
            )
        else:
            log_vulnerability_event(
                vuln,
                "updated",
                actor=actor,
                details={"detection_count": vuln.detection_count},
            )

        vuln.save(update_fields=sorted(set(update_fields)))
        return vuln

    vuln = Vulnerability.objects.create(
        host=host,
        scan=scan,
        software=software,
        port=port,
        cve_id=cve_id,
        severity=severity,
        name=name,
        description=description,
        cvss=cvss,
        nuclei_poc=nuclei_poc,
        supply_chain=supply_chain,
        fingerprint=fingerprint,
        first_seen=now,
        last_seen=now,
        detection_count=1,
    )
    log_vulnerability_event(vuln, "created", actor=actor, details={"source": scan.scan_type})
    return vuln
