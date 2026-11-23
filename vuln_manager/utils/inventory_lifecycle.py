"""Close only inventory-confirmed host installations, retaining audit evidence."""
from datetime import timedelta

from django.db.models import Exists, F, OuterRef, Q
from django.utils import timezone

from vuln_manager.models import InventoryFindingClosure, Software, SystemSettings, Vulnerability
from vuln_manager.utils.audit import log_vulnerability_event
from vuln_manager.utils.retention import bulk_delete_fixed_vulnerabilities

ACTIVE = ("open", "in_progress", "verification")


def record_absent_installation(host, software, reason):
    """Called only after the host/software relation is detached."""
    now = timezone.now()
    for vuln in Vulnerability.objects.filter(software=software, status__in=ACTIVE).filter(Q(host=host) | Q(host__isnull=True)):
        InventoryFindingClosure.objects.create(
            vulnerability=vuln, host=host, host_label=host.hostname or host.ip_address,
            software_name=software.name, software_version=software.version or "", reason=reason,
            closed_at=now,
        )
        details = {"reason": reason, "host_id": host.pk, "host": host.hostname or host.ip_address,
                   "software": software.name, "version": software.version or "", "confirmation_snapshots": 2}
        if vuln.host_id == host.pk or (vuln.host_id is None and not software.hosts.exists()):
            old = vuln.status
            vuln.status = "fixed"
            vuln.fixed_at = now
            vuln.inventory_closed_at = now
            vuln.save(update_fields=["status", "fixed_at", "inventory_closed_at"])
            details.update({"from_status": old, "to_status": "fixed"})
            log_vulnerability_event(vuln, "status_changed", actor="inventory:confirmed_absence", details=details)
        else:
            log_vulnerability_event(vuln, "updated", actor="inventory:confirmed_absence", details=details)


def record_reappearance(host, software):
    """Reopen only findings that were closed by this inventory process."""
    closures = InventoryFindingClosure.objects.filter(host=host, vulnerability__software=software, reopened_at__isnull=True).select_related("vulnerability")
    now = timezone.now()
    for closure in closures:
        closure.reopened_at = now
        closure.save(update_fields=["reopened_at"])
    findings = Vulnerability.objects.filter(software=software, status="fixed", inventory_closed_at__isnull=False, fixed_at=F("inventory_closed_at")).filter(Q(host=host) | Q(host__isnull=True))
    for vuln in findings:
        vuln.status, vuln.fixed_at, vuln.inventory_closed_at = "open", None, None
        vuln.save(update_fields=["status", "fixed_at", "inventory_closed_at"])
        log_vulnerability_event(vuln, "reopened", actor="inventory:reappeared", details={"host_id": host.pk, "software": software.name, "version": software.version or ""})


def cleanup_inventory_findings():
    settings, _ = SystemSettings.objects.get_or_create(pk=1)
    threshold = timezone.now() - timedelta(days=max(settings.inventory_retention_days, 1))
    # A manual reopen and later re-fix has a different fixed_at and must not be
    # deleted under the earlier inventory closure's retention deadline.
    installations = Software.hosts.through.objects.filter(software_id=OuterRef("software_id"))
    eligible = Vulnerability.objects.filter(status="fixed", software__isnull=False, inventory_closed_at__lt=threshold, fixed_at=F("inventory_closed_at")).annotate(
        inventory_any_host=Exists(installations),
        inventory_target_host=Exists(installations.filter(host_id=OuterRef("host_id"))),
    ).filter(Q(host__isnull=True, inventory_any_host=False) | Q(host__isnull=False, inventory_target_host=False))
    return bulk_delete_fixed_vulnerabilities(eligible, actor="inventory:retention", tag="inventory_retention")
