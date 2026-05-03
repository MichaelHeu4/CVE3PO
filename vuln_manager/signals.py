import threading

from django.db import transaction
from django.db.models.signals import post_save, pre_delete
from django.dispatch import receiver

from vuln_manager.models import Software, Vulnerability
from vuln_manager.utils.osv_auto import enrich_software_with_feeds
from vuln_manager.utils.audit import log_vulnerability_event


@receiver(post_save, sender=Software)
def trigger_osv_auto_lookup(sender, instance, created, **kwargs):
    if not created:
        return

    def _run_lookup():
        worker = threading.Thread(
            target=enrich_software_with_feeds, args=(instance.id,), daemon=True
        )
        worker.start()

    transaction.on_commit(_run_lookup)


@receiver(pre_delete, sender=Software)
def mark_software_vulnerabilities_fixed(sender, instance, **kwargs):
    active_vulns = Vulnerability.objects.filter(software=instance).exclude(
        status__in=["fixed", "false_positive", "risk_accepted"]
    )

    for vuln in active_vulns:
        old_status = vuln.status
        vuln.status = "fixed"
        vuln.save(update_fields=["status"])
        log_vulnerability_event(
            vuln,
            "status_changed",
            actor="software_delete:auto_close",
            details={
                "from_status": old_status,
                "to_status": "fixed",
                "reason": "software_deleted",
                "software_id": instance.id,
                "software_name": instance.name,
                "software_version": instance.version,
            },
        )
