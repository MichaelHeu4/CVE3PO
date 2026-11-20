from vuln_manager.models import VulnerabilityAuditEvent


def log_vulnerability_event(vulnerability, action, user=None, actor=None, details=None):
    event = VulnerabilityAuditEvent.objects.create(
        vulnerability=vulnerability,
        user=user,
        actor=actor,
        action=action,
        details=details or {},
    )
    if action in {"created", "reopened"}:
        from vuln_manager.utils.notifications import emit
        emit(f"audit:{event.pk}", "new_finding" if action == "created" else "reopened", f"{action}: {vulnerability.cve_id}", vulnerability=vulnerability)
