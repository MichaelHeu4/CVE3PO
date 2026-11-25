"""Tracked Wazuh inventory sync, shared by the UI and enrichment scheduler."""
import logging
import threading
from datetime import timedelta

from django.db import IntegrityError, close_old_connections
from django.utils import timezone

from vuln_manager.models import WazuhInventorySync
from vuln_manager.utils.wazuh_context import refresh_all_hosts

logger = logging.getLogger(__name__)


def _run(sync_id):
    close_old_connections()
    try:
        result = refresh_all_hosts(heartbeat=lambda: WazuhInventorySync.objects.filter(pk=sync_id, status="running").update(heartbeat_at=timezone.now()))
        status = "partial" if result["failed"] else "completed"
    except Exception:
        logger.exception("Wazuh inventory sync failed")
        result, status = {"error": "See server logs"}, "failed"
    finally:
        close_old_connections()
    WazuhInventorySync.objects.filter(pk=sync_id, status="running").update(status=status, summary=result, finished_at=timezone.now())
    close_old_connections()


def start_sync():
    WazuhInventorySync.objects.filter(status="running", heartbeat_at__lt=timezone.now()-timedelta(minutes=10)).update(status="interrupted", finished_at=timezone.now())
    try:
        sync = WazuhInventorySync.objects.create()
    except IntegrityError:
        return False
    try:
        threading.Thread(target=_run, args=(sync.pk,), daemon=True).start()
    except Exception:
        WazuhInventorySync.objects.filter(pk=sync.pk).update(status="failed", finished_at=timezone.now(), summary={"error": "Could not start worker"})
        raise
    return True
