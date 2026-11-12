from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("vuln_manager", "0039_host_machine_id_hostaddress"),
    ]

    operations = [
        migrations.AddField(
            model_name="host",
            name="criticality_source",
            field=models.CharField(
                choices=[("manual", "Manual"), ("netbox", "NetBox")],
                default="manual",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="host",
            name="criticality_synced_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_url",
            field=models.URLField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_api_token",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_verify_ssl",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_source_type",
            field=models.CharField(
                choices=[("custom_field", "Custom field"), ("tag", "Tag")],
                default="custom_field",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_source_name",
            field=models.CharField(default="criticality", max_length=100),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_value_mapping",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_sync_interval_hours",
            field=models.PositiveIntegerField(default=6),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_last_run",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="netbox_last_status",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
