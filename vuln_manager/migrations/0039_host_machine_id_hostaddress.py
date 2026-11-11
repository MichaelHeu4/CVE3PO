import django.db.models.deletion
from django.db import migrations, models


def backfill_host_addresses(apps, schema_editor):
    """Seed HostAddress from each existing Host's primary IP so IP-based
    resolution keeps working for hosts that predate identity resolution."""
    Host = apps.get_model("vuln_manager", "Host")
    HostAddress = apps.get_model("vuln_manager", "HostAddress")
    for host in Host.objects.all().iterator():
        if not host.ip_address:
            continue
        HostAddress.objects.get_or_create(
            ip_address=host.ip_address,
            defaults={"host": host, "source": "manual"},
        )


def noop_reverse(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("vuln_manager", "0038_host_running_kernel"),
    ]

    operations = [
        migrations.AddField(
            model_name="host",
            name="machine_id",
            field=models.CharField(
                blank=True, max_length=255, null=True, unique=True
            ),
        ),
        migrations.CreateModel(
            name="HostAddress",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("ip_address", models.GenericIPAddressField(unique=True)),
                (
                    "source",
                    models.CharField(
                        choices=[
                            ("agent", "Agent"),
                            ("wazuh", "Wazuh"),
                            ("shodan", "Shodan"),
                            ("nmap", "Nmap Scan"),
                            ("manual", "Manual Entry"),
                        ],
                        default="manual",
                        max_length=20,
                    ),
                ),
                ("first_seen", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                (
                    "host",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="addresses",
                        to="vuln_manager.host",
                    ),
                ),
            ],
        ),
        migrations.RunPython(backfill_host_addresses, noop_reverse),
    ]
