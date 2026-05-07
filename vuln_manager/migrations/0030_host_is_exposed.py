from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("vuln_manager", "0029_alter_scan_scan_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="host",
            name="is_exposed",
            field=models.BooleanField(default=False),
        ),
    ]
