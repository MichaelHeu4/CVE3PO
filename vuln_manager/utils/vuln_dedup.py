import hashlib
import re

from django.utils import timezone

from vuln_manager.models import Vulnerability, VulnerabilityObservation, SystemSettings
from datetime import timedelta
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
    if vuln is None:
        observation = VulnerabilityObservation.objects.select_related("vulnerability").filter(fingerprint=fingerprint).first()
        vuln = observation.vulnerability if observation else None
    # Only correlate known CVEs on the exact same software version, host and
    # port. Ambiguous matches and decided findings need human review instead.
    if vuln is None and software and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id or "", re.IGNORECASE):
        candidates = list(Vulnerability.objects.filter(
            cve_id__iexact=cve_id, software=software, host=host, port=port,
            status="open").exclude(observations__source=scan.scan_type)[:2])
        if len(candidates) == 1:
            vuln = candidates[0]
    if vuln:
        old_status = vuln.status
        update_fields = []

        vuln.scan = scan
        update_fields.append("scan")

        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        is_new_source = not vuln.observations.filter(source=scan.scan_type).exists()
        if severity is not None and vuln.severity != severity and (not is_new_source or severity_order.get(severity, 0) > severity_order.get(vuln.severity, 0)):
            vuln.severity = severity
            update_fields.append("severity")
        if vuln.name != name:
            vuln.name = name
            update_fields.append("name")
        if vuln.description != description:
            vuln.description = description
            update_fields.append("description")
        if cvss is not None and vuln.cvss != cvss:
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

        expired_exception = (vuln.status in {"false_positive", "risk_accepted"}
                             and vuln.exception_expires and vuln.exception_expires < timezone.localdate())
        if vuln.status in {"fixed", "verification"} or expired_exception:
            vuln.status = "open"
            update_fields.append("status")
            if vuln.fixed_at is not None:
                vuln.fixed_at = None
                update_fields.append("fixed_at")
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
        observation, created = VulnerabilityObservation.objects.get_or_create(
            vulnerability=vuln, source=scan.scan_type,
            defaults={"scan": scan, "name": name, "description": description, "fingerprint": fingerprint})
        if not created:
            observation.scan, observation.name, observation.description = scan, name, description
            observation.fingerprint = fingerprint
            observation.last_seen = now
            observation.detection_count += 1
            observation.save()
        return vuln

    vuln = Vulnerability.objects.create(
        host=host,
        scan=scan,
        software=software,
        port=port,
        cve_id=cve_id,
        severity=severity or "info",
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
    settings = SystemSettings.objects.first()
    days = (settings.sla_critical_days if settings else 7) if severity == "critical" else ((settings.sla_high_days if settings else 30) if severity == "high" else None)
    if days:
        vuln.due_date = timezone.localdate(now) + timedelta(days=days)
        vuln.save(update_fields=["due_date"])
    VulnerabilityObservation.objects.create(vulnerability=vuln, scan=scan, source=scan.scan_type, name=name, description=description, fingerprint=fingerprint)
    log_vulnerability_event(vuln, "created", actor=actor, details={"source": scan.scan_type})
    return vuln
