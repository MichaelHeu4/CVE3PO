from django.db import migrations


def backfill_fixed_at(apps, schema_editor):
    """Populate fixed_at for vulnerabilities that are already fixed.

    Prefer the timestamp of the most recent ``status_changed -> fixed`` audit
    event; fall back to ``last_seen`` when no such event exists (e.g. rows fixed
    before the audit trail was introduced).
    """
    Vulnerability = apps.get_model("vuln_manager", "Vulnerability")
    AuditEvent = apps.get_model("vuln_manager", "VulnerabilityAuditEvent")

    to_update = []
    fixed_qs = Vulnerability.objects.filter(
        status="fixed", fixed_at__isnull=True
    ).iterator()
    for vuln in fixed_qs:
        last_fix = (
            AuditEvent.objects.filter(
                vulnerability_id=vuln.id,
                action="status_changed",
                details__to_status="fixed",
            )
            .order_by("-created_at")
            .values_list("created_at", flat=True)
            .first()
        )
        vuln.fixed_at = last_fix or vuln.last_seen
        to_update.append(vuln)
        if len(to_update) >= 1000:
            Vulnerability.objects.bulk_update(to_update, ["fixed_at"])
            to_update = []

    if to_update:
        Vulnerability.objects.bulk_update(to_update, ["fixed_at"])


def noop_reverse(apps, schema_editor):
    # Reversing simply clears the backfilled timestamps.
    Vulnerability = apps.get_model("vuln_manager", "Vulnerability")
    Vulnerability.objects.filter(status="fixed").update(fixed_at=None)


class Migration(migrations.Migration):

    dependencies = [
        ("vuln_manager", "0036_systemsettings_auto_delete_fixed_days_and_more"),
    ]

    operations = [
        migrations.RunPython(backfill_fixed_at, noop_reverse),
    ]
