from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vuln_manager", "0034_dashboard_query_indexes"),
    ]

    operations = [
        migrations.AddField(
            model_name="systemsettings",
            name="auto_enrich_interval_hours",
            field=models.PositiveIntegerField(default=24),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="auto_enrich_last_run",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="auto_enrich_last_status",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AlterField(
            model_name="scan",
            name="scan_type",
            field=models.CharField(
                choices=[
                    ("NMAP", "Nmap Scan"),
                    ("NUCLEI", "Nuclei Scan"),
                    ("OPENVAS", "OpenVAS Scan"),
                    ("SEMGREP", "Semgrep SAST"),
                    ("CYCLONEDX", "CycloneDX SBOM"),
                    ("MANUAL", "Manual Entry"),
                    ("OSV", "OSV Scan"),
                    ("NVD", "NVD Scan"),
                    ("WAZUH", "Wazuh Live Feed"),
                    ("SHODAN", "Shodan Lookup"),
                ],
                max_length=10,
            ),
        ),
    ]
