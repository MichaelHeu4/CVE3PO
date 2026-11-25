"""
In-process scheduler for recurring enrichment.

There is no Celery/cron in this deployment, so a single daemon thread per
worker process wakes periodically and runs the full enrichment cycle when it
is due. Because gunicorn runs several worker processes, each tick first makes
an *atomic* DB claim on SystemSettings.auto_enrich_last_run; only the worker
whose UPDATE actually changes the row runs the cycle, so the job runs once per
interval regardless of how many workers are alive.
"""

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# How often each worker wakes to check whether a run is due. The real cadence
# is governed by SystemSettings.auto_enrich_interval_hours; this is just the
# polling granularity.
_CHECK_INTERVAL_SECONDS = 300

# Small delay before the first tick so migrations/startup settle first.
_STARTUP_DELAY_SECONDS = 30

# Be polite to upstream feeds between software items.
_PER_SOFTWARE_DELAY_SECONDS = 0.2

_started = False
_start_lock = threading.Lock()


def run_full_enrichment():
    """
    Re-run OSV/NVD enrichment for all inventoried software plus threat-intel
    refresh (CISA KEV + EPSS), and — when the Shodan module is active — refresh
    host exposure/ports from Shodan. Safe to call from any thread.
    """
    from vuln_manager.models import Extension, Software, Vulnerability, FeedRun
    from django.utils import timezone
    from vuln_manager.utils.enrichment import (
        get_epss_score, sync_cisa_kev_to_db,
        get_cve_enrichment, apply_cve_enrichment,
    )
    from django.db.models import Q
    from vuln_manager.utils.osv_auto import enrich_software_with_feeds

    logger.info("Full enrichment cycle started")

    # 1) Threat intelligence: refresh the CISA KEV catalogue.
    kev_run = FeedRun.objects.create(source="CISA KEV")
    try:
        count = sync_cisa_kev_to_db(strict=True)
        kev_run.status, kev_run.details = "success", f"{count} new entries"
    except Exception as exc:
        kev_run.status, kev_run.details = "failed", str(exc)[:500]
        logger.exception("CISA KEV sync failed during scheduled enrichment")
    finally:
        kev_run.finished_at = timezone.now()
        kev_run.save(update_fields=["status", "details", "finished_at"])

    # 2) Re-check every software with a known version against OSV/NVD. This is
    #    what surfaces newly published CVEs for already-inventoried software and
    #    reconciles vulns that upstream no longer reports.
    software_ids = list(
        Software.objects.exclude(version__isnull=True)
        .exclude(version="")
        .values_list("id", flat=True)
    )
    enriched = 0
    failed_software = []
    software_run = FeedRun.objects.create(source="OSV/NVD software")
    for software_id in software_ids:
        try:
            if enrich_software_with_feeds(software_id) is False:
                failed_software.append(str(software_id))
            else:
                enriched += 1
        except Exception:
            failed_software.append(str(software_id))
            logger.exception("Scheduled enrichment failed for software %s", software_id)
        if _PER_SOFTWARE_DELAY_SECONDS:
            time.sleep(_PER_SOFTWARE_DELAY_SECONDS)

    software_run.status = "partial" if failed_software else "success"
    software_run.details = (f"{enriched}/{len(software_ids)} completed; failed software IDs: " + ", ".join(failed_software))[:2000]
    software_run.finished_at = timezone.now()
    software_run.save(update_fields=["status", "details", "finished_at"])

    # 3) Refresh stale EPSS scores and record failures.
    epss_run = FeedRun.objects.create(source="EPSS")
    epss_errors = []
    for cve_id in Vulnerability.objects.values_list("cve_id", flat=True).distinct():
        if cve_id and cve_id.startswith("CVE-"):
            # Also repair old imports and findings with no associated software.
            # Fetch once per CVE, not once per host/package occurrence.
            missing = Vulnerability.objects.filter(cve_id=cve_id).filter(
                Q(severity="info") | Q(cvss__isnull=True) | Q(cvss="")
            )
            if missing.exists():
                try:
                    details = get_cve_enrichment(cve_id)
                    for vuln in missing:
                        apply_cve_enrichment(vuln, details, actor="auto_enrich")
                except Exception:
                    logger.exception("Rating enrichment failed for %s", cve_id)
            try:
                get_epss_score(cve_id, strict=True)
            except Exception as exc:
                epss_errors.append(f"{cve_id}: {exc}")
                logger.exception("EPSS fetch failed for %s during scheduled enrichment", cve_id)
    epss_run.status = "partial" if epss_errors else "success"
    epss_run.details = "; ".join(epss_errors)[:2000] if epss_errors else "Refresh completed"
    epss_run.finished_at = timezone.now()
    epss_run.save(update_fields=["status", "details", "finished_at"])

    # 4) Optional: refresh Shodan exposure/ports for all hosts.
    shodan_summary = None
    if Extension.objects.filter(name_id="shodan", is_active=True).exists():
        try:
            from vuln_manager.extensions import shodan as shodan_ext

            shodan_summary = shodan_ext.refresh_all_hosts()
        except Exception:
            logger.exception("Shodan refresh failed during scheduled enrichment")

    if (Extension.objects.filter(name_id="wazuh", is_active=True).exists()
            and all(os.environ.get(key) for key in ("WAZUH_CONTEXT_API_URL", "WAZUH_CONTEXT_API_USER", "WAZUH_CONTEXT_API_PASSWORD"))):
        try:
            from vuln_manager.utils.wazuh_sync import start_sync
            start_sync()
        except Exception:
            logger.exception("Wazuh inventory refresh could not be started")

    logger.info(
        "Full enrichment cycle finished (%s/%s software enriched)",
        enriched,
        len(software_ids),
    )
    return {
        "software_total": len(software_ids),
        "software_enriched": enriched,
        "errors": bool(failed_software or epss_errors or kev_run.status != "success"),
        "shodan": shodan_summary,
    }


def run_full_enrichment_and_record(record_status=True):
    """
    Wrapper that runs a full cycle and stamps SystemSettings with the result.
    Used by the "Run now" button and the management command.
    """
    from django.utils import timezone

    from vuln_manager.models import SystemSettings

    result = run_full_enrichment()
    if record_status:
        try:
            status = (
                f"{'partial' if result.get('errors') else 'ok'}: {result['software_enriched']}/{result['software_total']} software"
            )
            if result.get("shodan") and result["shodan"].get("status") == "done":
                status += (
                    f", shodan {result['shodan']['found']}/{result['shodan']['hosts']} found"
                )
            SystemSettings.objects.filter(pk=1).update(
                auto_enrich_last_run=timezone.now(),
                auto_enrich_last_status=status[:255],
            )
        except Exception:
            logger.exception("Failed to record enrichment status")
    return result


def run_fixed_vulnerability_cleanup():
    """Delete vulnerabilities fixed longer ago than the retention window.

    Only rows with ``status="fixed"`` and a ``fixed_at`` older than the configured
    number of days are removed. Safe to call from any thread.
    """
    from django.utils import timezone
    from django.db.models import F
    from datetime import timedelta

    from vuln_manager.models import SystemSettings, Vulnerability
    from vuln_manager.utils.retention import bulk_delete_fixed_vulnerabilities

    settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)
    days = max(1, settings_obj.auto_delete_fixed_days or 90)
    threshold = timezone.now() - timedelta(days=days)

    stale_fixed = Vulnerability.objects.filter(
        status="fixed", fixed_at__isnull=False, fixed_at__lt=threshold
    ).exclude(inventory_closed_at=F("fixed_at"))
    deleted = bulk_delete_fixed_vulnerabilities(
        stale_fixed, actor="auto_delete_fixed", tag="auto_fixed_retention"
    )
    logger.info("Auto-delete-fixed removed %s vulnerabilities (>%s days)", deleted, days)
    return {"deleted": deleted, "days": days}


def run_fixed_cleanup_and_record(record_status=True):
    """Run the retention cleanup and stamp SystemSettings with the result.

    Used by the "Run cleanup now" button and the scheduler tick.
    """
    from django.utils import timezone

    from vuln_manager.models import SystemSettings

    result = run_fixed_vulnerability_cleanup()
    if record_status:
        try:
            status = f"ok: {result['deleted']} deleted (>{result['days']}d)"
            SystemSettings.objects.filter(pk=1).update(
                auto_delete_fixed_last_run=timezone.now(),
                auto_delete_fixed_last_status=status[:255],
            )
        except Exception:
            logger.exception("Failed to record auto-delete-fixed status")
    return result


def _tick():
    from django.db import connections
    from django.db.models import Q
    from django.utils import timezone
    from datetime import timedelta

    from vuln_manager.models import Extension, SystemSettings

    try:
        if not Extension.objects.filter(name_id="auto_enrich", is_active=True).exists():
            return

        settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)
        interval_hours = max(1, settings_obj.auto_enrich_interval_hours or 24)
        threshold = timezone.now() - timedelta(hours=interval_hours)

        # Atomic claim: only one worker's UPDATE will match-and-change the row
        # within a given window, so only that worker proceeds to run the cycle.
        claimed = SystemSettings.objects.filter(pk=1).filter(
            Q(auto_enrich_last_run__isnull=True)
            | Q(auto_enrich_last_run__lt=threshold)
        ).update(auto_enrich_last_run=timezone.now())

        if not claimed:
            return

        logger.info("Scheduled enrichment run claimed; executing")
        run_full_enrichment_and_record(record_status=True)
    finally:
        connections.close_all()


def _tick_fixed_cleanup():
    """Daily-cadence claim+run for the Auto-Delete-Fixed module.

    Independent of the enrichment tick: it has its own extension flag and its own
    atomic claim on ``auto_delete_fixed_last_run`` so the cleanup runs once per
    day across all gunicorn workers.
    """
    from django.db import connections
    from django.db.models import Q
    from django.utils import timezone
    from datetime import timedelta

    from vuln_manager.models import Extension, SystemSettings

    try:
        if not Extension.objects.filter(
            name_id="auto_delete_fixed", is_active=True
        ).exists():
            return

        SystemSettings.objects.get_or_create(pk=1)
        threshold = timezone.now() - timedelta(hours=24)

        claimed = SystemSettings.objects.filter(pk=1).filter(
            Q(auto_delete_fixed_last_run__isnull=True)
            | Q(auto_delete_fixed_last_run__lt=threshold)
        ).update(auto_delete_fixed_last_run=timezone.now())

        if not claimed:
            return

        logger.info("Scheduled fixed-vulnerability cleanup claimed; executing")
        run_fixed_cleanup_and_record(record_status=True)
    finally:
        connections.close_all()


def _tick_netbox_sync():
    """Claim+run the NetBox criticality sync on its own configurable interval.

    Uses an atomic claim on ``netbox_last_run`` (like the other ticks) so only
    one gunicorn worker runs the sync per interval.
    """
    from django.db import connections
    from django.db.models import Q
    from django.utils import timezone
    from datetime import timedelta

    from vuln_manager.extensions import netbox as netbox_ext
    from vuln_manager.models import SystemSettings

    try:
        if not netbox_ext.is_active():
            return
        settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)
        if not netbox_ext.is_configured(settings_obj):
            return
        interval_hours = max(1, settings_obj.netbox_sync_interval_hours or 6)
        threshold = timezone.now() - timedelta(hours=interval_hours)

        claimed = SystemSettings.objects.filter(pk=1).filter(
            Q(netbox_last_run__isnull=True) | Q(netbox_last_run__lt=threshold)
        ).update(netbox_last_run=timezone.now())
        if not claimed:
            return

        logger.info("Scheduled NetBox criticality sync claimed; executing")
        netbox_ext.sync_and_record()
    finally:
        connections.close_all()


def reopen_expired_exceptions():
    """Reopen expired exceptions, preserving the decision in the audit trail."""
    from django.utils import timezone
    from vuln_manager.models import Vulnerability
    from vuln_manager.utils.audit import log_vulnerability_event
    expired = Vulnerability.objects.filter(status__in=["risk_accepted", "false_positive"], exception_expires__lt=timezone.localdate())
    for vuln in expired.iterator():
        old = vuln.status
        if Vulnerability.objects.filter(pk=vuln.pk, status=old, exception_expires__lt=timezone.localdate()).update(status="open"):
            log_vulnerability_event(vuln, "reopened", actor="exception_expiry", details={"from_status": old, "to_status": "open", "reason": "exception_expired"})


def _tick_inventory_cleanup():
    from django.db import connections
    from django.db.models import Q
    from django.utils import timezone
    from datetime import timedelta
    from vuln_manager.models import SystemSettings
    from vuln_manager.utils.inventory_lifecycle import cleanup_inventory_findings

    try:
        SystemSettings.objects.get_or_create(pk=1)
        claimed = SystemSettings.objects.filter(pk=1).filter(
            Q(inventory_cleanup_last_run__isnull=True) | Q(inventory_cleanup_last_run__lt=timezone.now()-timedelta(days=1))
        ).update(inventory_cleanup_last_run=timezone.now())
        if claimed:
            try:
                count = cleanup_inventory_findings()
                logger.info("Inventory retention removed %s findings", count)
            except Exception:
                SystemSettings.objects.filter(pk=1).update(inventory_cleanup_last_run=None)
                raise
    finally:
        connections.close_all()


def _scheduler_loop():
    time.sleep(_STARTUP_DELAY_SECONDS)
    while True:
        try:
            _tick_inventory_cleanup()
        except Exception:
            logger.exception("Inventory cleanup failed")
        try:
            from vuln_manager.utils.cti import run_feeds
            run_feeds()
        except Exception:
            logger.exception("CTI feed check failed")
        try:
            from vuln_manager.utils.notifications import tick as notification_tick
            notification_tick()
        except Exception:
            logger.exception("Notification check failed")
        try:
            from vuln_manager.utils.reminders import run_reminders
            run_reminders()
        except Exception:
            logger.exception("Reminder check failed")
        try:
            reopen_expired_exceptions()
        except Exception:
            logger.exception("Exception expiry check failed")
        try:
            _tick()
        except Exception:
            logger.exception("Scheduler tick raised")
        try:
            _tick_fixed_cleanup()
        except Exception:
            logger.exception("Fixed-cleanup tick raised")
        try:
            _tick_netbox_sync()
        except Exception:
            logger.exception("NetBox sync tick raised")
        time.sleep(_CHECK_INTERVAL_SECONDS)


def start_scheduler():
    """Start the background scheduler thread once per process."""
    global _started
    with _start_lock:
        if _started:
            return
        _started = True
    thread = threading.Thread(
        target=_scheduler_loop, name="cve3po-scheduler", daemon=True
    )
    thread.start()
    logger.info("CVE3PO enrichment scheduler started")
