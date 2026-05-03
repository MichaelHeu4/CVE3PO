import threading

from django.db import transaction
from django.db.models import Count
from django.db.models.signals import post_save, pre_delete, post_delete
from django.dispatch import receiver

from vuln_manager.models import Host, Software, Vulnerability
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
    if getattr(instance, "_skip_auto_close_vulnerabilities", False):
        return

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


@receiver(pre_delete, sender=Host)
def collect_orphan_software_candidates_for_host_delete(sender, instance, **kwargs):
    orphan_sw_ids = (
        instance.software_inventory.annotate(host_count=Count("hosts"))
        .filter(host_count=1)
        .values_list("id", flat=True)
    )
    instance._orphan_software_ids_on_delete = list(orphan_sw_ids)


@receiver(post_delete, sender=Host)
def cleanup_orphans_after_host_delete(sender, instance, **kwargs):
    orphan_sw_ids = getattr(instance, "_orphan_software_ids_on_delete", [])
    if not orphan_sw_ids:
        return

    orphan_software_qs = Software.objects.filter(id__in=orphan_sw_ids, hosts__isnull=True)
    orphan_software_ids = list(orphan_software_qs.values_list("id", flat=True))
    if not orphan_software_ids:
        return

    Vulnerability.objects.filter(software_id__in=orphan_software_ids, host__isnull=True).delete()

    for sw in orphan_software_qs:
        sw._skip_auto_close_vulnerabilities = True
        sw.delete()
