from django.core.management.base import BaseCommand

from vuln_manager.utils.scheduler import run_full_enrichment_and_record


class Command(BaseCommand):
    help = (
        "Runs a full enrichment cycle once: re-checks all inventoried software "
        "against OSV/NVD, refreshes CISA KEV + EPSS, and (if the Shodan module "
        "is active) refreshes host exposure from Shodan. Use this for an "
        "external cron if you prefer it over the built-in scheduler."
    )

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Starting full enrichment cycle..."))
        result = run_full_enrichment_and_record(record_status=True)
        self.stdout.write(
            self.style.SUCCESS(
                "Enrichment complete: "
                f"{result['software_enriched']}/{result['software_total']} software re-checked."
            )
        )
        shodan = result.get("shodan")
        if shodan and shodan.get("status") == "done":
            self.stdout.write(
                self.style.SUCCESS(
                    f"Shodan: {shodan['found']}/{shodan['hosts']} hosts found, "
                    f"{shodan['newly_exposed']} newly marked exposed."
                )
            )
