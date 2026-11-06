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
    from vuln_manager.models import Extension, Software, Vulnerability
    from vuln_manager.utils.enrichment import get_epss_score, sync_cisa_kev_to_db
    from vuln_manager.utils.osv_auto import enrich_software_with_feeds

    logger.info("Full enrichment cycle started")

    # 1) Threat intelligence: refresh the CISA KEV catalogue.
    try:
        sync_cisa_kev_to_db()
    except Exception:
        logger.exception("CISA KEV sync failed during scheduled enrichment")

    # 2) Re-check every software with a known version against OSV/NVD. This is
    #    what surfaces newly published CVEs for already-inventoried software and
    #    reconciles vulns that upstream no longer reports.
    software_ids = list(
        Software.objects.exclude(version__isnull=True)
        .exclude(version="")
        .values_list("id", flat=True)
    )
    enriched = 0
    for software_id in software_ids:
        try:
            enrich_software_with_feeds(software_id)
            enriched += 1
        except Exception:
            logger.exception("Scheduled enrichment failed for software %s", software_id)
        if _PER_SOFTWARE_DELAY_SECONDS:
            time.sleep(_PER_SOFTWARE_DELAY_SECONDS)

    # 3) Ensure EPSS scores exist for every CVE we track.
    for cve_id in Vulnerability.objects.values_list("cve_id", flat=True).distinct():
        if cve_id and cve_id.startswith("CVE-"):
            try:
                get_epss_score(cve_id)
            except Exception:
                logger.exception("EPSS fetch failed for %s during scheduled enrichment", cve_id)

    # 4) Optional: refresh Shodan exposure/ports for all hosts.
    shodan_summary = None
    if Extension.objects.filter(name_id="shodan", is_active=True).exists():
        try:
            from vuln_manager.extensions import shodan as shodan_ext

            shodan_summary = shodan_ext.refresh_all_hosts()
        except Exception:
            logger.exception("Shodan refresh failed during scheduled enrichment")

    logger.info(
        "Full enrichment cycle finished (%s/%s software enriched)",
        enriched,
        len(software_ids),
    )
    return {
        "software_total": len(software_ids),
        "software_enriched": enriched,
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
                f"ok: {result['software_enriched']}/{result['software_total']} software"
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


def _scheduler_loop():
    time.sleep(_STARTUP_DELAY_SECONDS)
    while True:
        try:
            _tick()
        except Exception:
            logger.exception("Scheduler tick raised")
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
