from django.core.management.base import BaseCommand
from vuln_manager.utils.enrichment import sync_cisa_kev_to_db, get_epss_score
from vuln_manager.models import Vulnerability

class Command(BaseCommand):
    help = 'Synchronizes local threat intelligence data (CISA KEV and EPSS scores).'

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Synchronizing CISA Known Exploited Vulnerabilities (KEV)..."))
        new_cisa_count = sync_cisa_kev_to_db()
        self.stdout.write(self.style.SUCCESS("CISA KEV sync complete. Local cache updated."))

        self.stdout.write(self.style.WARNING("Synchronizing EPSS scores for active CVEs in local database..."))
        local_cves = list(Vulnerability.objects.values_list('cve_id', flat=True).distinct())
        synced_epss = 0
        for cve_id in local_cves:
            if cve_id and cve_id.startswith("CVE-"):
                # get_epss_score automatically fetches from FIRST.org API and caches in EpssEntry
                get_epss_score(cve_id)
                synced_epss += 1
                
        self.stdout.write(self.style.SUCCESS(f"EPSS score sync complete. Cached {synced_epss} CVE scores locally."))
        self.stdout.write(self.style.SUCCESS("=== Threat Intelligence Sync Finished Successfully ==="))
