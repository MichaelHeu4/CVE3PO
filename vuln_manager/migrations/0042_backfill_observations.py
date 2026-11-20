from django.db import migrations


def backfill(apps, schema_editor):
    Vulnerability = apps.get_model("vuln_manager", "Vulnerability")
    Observation = apps.get_model("vuln_manager", "VulnerabilityObservation")
    batch = []
    for vuln in Vulnerability.objects.select_related("scan").iterator():
        batch.append(Observation(vulnerability_id=vuln.pk, scan_id=vuln.scan_id,
            source=vuln.scan.scan_type, name=vuln.name, description=vuln.description,
            first_seen=vuln.first_seen, last_seen=vuln.last_seen, detection_count=vuln.detection_count))
        if len(batch) >= 500:
            Observation.objects.bulk_create(batch, ignore_conflicts=True)
            batch = []
    Observation.objects.bulk_create(batch, ignore_conflicts=True)

class Migration(migrations.Migration):
    dependencies = [("vuln_manager", "0041_host_last_agent_contact_vulnerability_assignee_and_more")]
    operations = [migrations.RunPython(backfill, migrations.RunPython.noop)]
