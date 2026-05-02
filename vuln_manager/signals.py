import threading

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from vuln_manager.models import Software
from vuln_manager.utils.osv_auto import enrich_software_with_osv


@receiver(post_save, sender=Software)
def trigger_osv_auto_lookup(sender, instance, created, **kwargs):
    if not created:
        return

    def _run_lookup():
        worker = threading.Thread(
            target=enrich_software_with_osv, args=(instance.id,), daemon=True
        )
        worker.start()

    transaction.on_commit(_run_lookup)
