from django.db import migrations


def seed(apps, schema_editor):
    feed = apps.get_model("vuln_manager", "CTIFeed")
    for name, url in [
        ("Heise Security Alerts", "https://www.heise.de/security/rss/alert-news-atom.xml"),
        ("Heise Security News", "https://www.heise.de/security/rss/news-atom.xml"),
    ]:
        feed.objects.get_or_create(name=name, defaults={"url": url, "enabled": True})


class Migration(migrations.Migration):
    dependencies = [("vuln_manager", "0044_ctifeed_notificationrule_ctiitem_notificationevent_and_more")]
    operations = [migrations.RunPython(seed, migrations.RunPython.noop)]
