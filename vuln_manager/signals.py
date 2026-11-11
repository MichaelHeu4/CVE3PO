import threading

from django.db import connections, transaction
from django.db.models import Count
from django.db.models.signals import post_save, pre_delete, post_delete
from django.dispatch import receiver

from vuln_manager.models import Host, HostAddress, Software, Vulnerability
from vuln_manager.utils.osv_auto import enrich_software_with_feeds
from vuln_manager.utils.audit import log_vulnerability_event
from vuln_manager.utils.retention import stamp_fixed_at

# Bound how many enrichment threads run at once. A Wazuh batch can create many
# new Software rows in one request; without a cap each would spawn its own
# long-lived thread hammering the single SQLite writer, starving web workers.
_ENRICHMENT_SLOTS = threading.Semaphore(2)


@receiver(post_save, sender=Software)
def trigger_osv_auto_lookup(sender, instance, created, **kwargs):
    if not created:
        return

    software_id = instance.id

    def _worker():
        # Manually spawned threads get their own DB connections that Django
        # never cleans up for us. Cap concurrency and always release the
        # connection so write locks don't linger and connections don't leak.
        with _ENRICHMENT_SLOTS:
            try:
                enrich_software_with_feeds(software_id)
            finally:
                connections.close_all()

    def _run_lookup():
        threading.Thread(target=_worker, daemon=True).start()

    transaction.on_commit(_run_lookup)


@receiver(post_save, sender=Host)
def ensure_primary_host_address(sender, instance, **kwargs):
    """Mirror a Host's primary IP into HostAddress so IP-based identity
    resolution also finds hosts created outside the resolver (manual add,
    fixtures). Idempotent and never steals an IP already owned elsewhere."""
    if not instance.ip_address:
        return
    if HostAddress.objects.filter(ip_address=instance.ip_address).exists():
        return
    try:
        HostAddress.objects.create(
            host=instance, ip_address=instance.ip_address, source="manual"
        )
    except Exception:
        # A concurrent writer may have registered the same IP; ignore the race.
        pass


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
        stamp_fixed_at(vuln)
        vuln.save(update_fields=["status", "fixed_at"])
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
