from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vuln_manager', '0033_cisakeventry_epssentry'),
    ]

    operations = [
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(fields=['uploaded_at'], name='scan_uploaded_idx'),
        ),
        migrations.AddIndex(
            model_name='host',
            index=models.Index(
                fields=['criticality', 'is_exposed'], name='host_crit_exposed_idx'
            ),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['status'], name='vuln_status_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['severity'], name='vuln_severity_idx'),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(
                fields=['status', 'severity'], name='vuln_status_sev_idx'
            ),
        ),
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(
                fields=['severity', 'first_seen'], name='vuln_sev_firstseen_idx'
            ),
        ),
    ]
