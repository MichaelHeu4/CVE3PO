from django.db import migrations


def create_module(apps, schema_editor):
    extension = apps.get_model("vuln_manager", "Extension")
    # Preserve the behavior of installations already using the CTI inbox.
    extension.objects.get_or_create(name_id="cti", defaults={"is_active": True})


class Migration(migrations.Migration):
    dependencies = [("vuln_manager", "0045_heise_feeds")]
    operations = [migrations.RunPython(create_module, migrations.RunPython.noop)]
