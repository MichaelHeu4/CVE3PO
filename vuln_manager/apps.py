import os
import sys

from django.apps import AppConfig


class VulnManagerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'vuln_manager'

    def ready(self):
        import vuln_manager.signals  # noqa: F401
        self._maybe_start_scheduler()

    def _maybe_start_scheduler(self):
        # Never start the background scheduler for build/management commands
        # (the entrypoint runs makemigrations/migrate/collectstatic before the
        # server). It should only run inside the actual web server process.
        blocked = {
            "makemigrations",
            "migrate",
            "collectstatic",
            "shell",
            "shell_plus",
            "test",
            "createsuperuser",
            "showmigrations",
            "dumpdata",
            "loaddata",
            "generate_test_data",
            "enrich_feeds",
            "sync_threat_intel",
        }
        if any(arg in blocked for arg in sys.argv):
            return

        # Under runserver, ready() runs twice (reloader parent + child). Only
        # start in the child that actually serves requests.
        if "runserver" in sys.argv and os.environ.get("RUN_MAIN") != "true":
            return

        try:
            from vuln_manager.utils.scheduler import start_scheduler

            start_scheduler()
        except Exception:
            # Scheduler start must never block app startup.
            import logging

            logging.getLogger(__name__).exception("Failed to start enrichment scheduler")
