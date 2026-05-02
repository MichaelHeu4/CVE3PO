from vuln_manager.models import VulnerabilityAuditEvent


def log_vulnerability_event(vulnerability, action, user=None, actor=None, details=None):
    VulnerabilityAuditEvent.objects.create(
        vulnerability=vulnerability,
        user=user,
        actor=actor,
        action=action,
        details=details or {},
    )
