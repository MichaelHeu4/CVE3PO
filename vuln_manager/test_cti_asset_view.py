from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from vuln_manager.models import CTIFeed, CTIItem, CTIMatch, Host, HostSoftwareRelationship, Software


class CTIAssetViewTests(TestCase):
    def setUp(self):
        self.client.force_login(User.objects.create_user("analyst"))
        feed = CTIFeed.objects.get(name="Heise Security Alerts")
        self.item = CTIItem.objects.create(
            source=feed, external_id="asset-grouping", title="DLA-4902-1 apache2",
            url="https://example.com/advisory", cves=["CVE-2026-42356"],
            debian_advisories={"DLA-4902-1": {"fetched_at": timezone.now().isoformat(), "cves": ["CVE-2026-42356"], "fixes": [{"release": "bookworm", "source_package": "apache2", "fixed_version": "2.4.71-1~deb12u1"}]}},
        )
        self.old = Software.objects.create(name="apache2", version="2.4.62-1~deb12u2")
        self.new = Software.objects.create(name="apache2", version="2.4.71-1~deb12u1")
        CTIMatch.objects.create(item=self.item, software=self.old, reason="match")
        CTIMatch.objects.create(item=self.item, software=self.new, reason="match")
        self.hosts = []
        for i in range(31):
            host = Host.objects.create(ip_address=f"192.0.2.{i+1}", hostname=f"host-{i:02d}", operating_system="Debian GNU/Linux 12 (bookworm)")
            self.hosts.append(host)
            software = self.old if i == 0 else self.new
            software.hosts.add(host)
            if i != 30:
                HostSoftwareRelationship.objects.create(host=host, software=software, source="agent", package_manager="dpkg", source_package="apache2", source_version=software.version)
        # One host runs both package versions; it must be counted once as affected.
        self.new.hosts.add(self.hosts[0])
        HostSoftwareRelationship.objects.create(host=self.hosts[0], software=self.new, source="agent", package_manager="dpkg", source_package="apache2", source_version=self.new.version)
        self.url = reverse("cti_detail", args=[self.item.pk])

    def test_unique_host_counts_priority_and_status_filter(self):
        response = self.client.get(self.url, {"assessment_status": "below_fix"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["asset_counts"], {"all": 31, "below_fix": 1, "unknown": 1, "fixed": 29})
        self.assertEqual(response.context["asset_groups"].paginator.count, 1)
        group = response.context["asset_groups"].object_list[0]
        self.assertEqual(group["host"].hostname, "host-00")
        self.assertEqual(len(group["items"]), 2)
        self.assertContains(response, "Möglicherweise betroffen")

    def test_filter_and_pagination_apply_across_all_hosts(self):
        first = self.client.get(self.url, {"asset_sort": "name"})
        second = self.client.get(self.url, {"asset_sort": "name", "asset_page": 2})
        self.assertEqual(len(first.context["asset_groups"]), 25)
        self.assertEqual(len(second.context["asset_groups"]), 6)
        self.assertContains(second, "host-30")
        search = self.client.get(self.url, {"asset_q": "host-30"})
        self.assertEqual(search.context["asset_groups"].paginator.count, 1)
        self.assertEqual(search.context["asset_groups"].object_list[0]["status"], "unknown")

    def test_package_grouping_and_search(self):
        response = self.client.get(self.url, {"group": "package", "asset_q": "2.4.62"})
        self.assertEqual(response.context["asset_mode"], "package")
        self.assertEqual(response.context["asset_groups"].paginator.count, 1)
        group = response.context["asset_groups"].object_list[0]
        self.assertEqual(group["software"], self.old)
        self.assertEqual(group["items"][0]["host"], self.hosts[0])

    def test_unknown_filters_and_bad_page_are_safe(self):
        response = self.client.get(self.url, {"group": "wrong", "assessment_status": "wrong", "asset_page": "abc"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["asset_mode"], "host")
        self.assertEqual(response.context["asset_status"], "all")
        self.assertEqual(response.context["asset_groups"].number, 1)

    def test_more_hosts_do_not_add_queries_per_assessment(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as before:
            self.client.get(self.url)
        for i in range(5):
            host = Host.objects.create(ip_address=f"192.0.2.{100+i}", hostname=f"extra-{i}", operating_system="Debian GNU/Linux 12")
            self.old.hosts.add(host)
            HostSoftwareRelationship.objects.create(host=host, software=self.old, source="agent", package_manager="dpkg", source_package="apache2", source_version=self.old.version)
        with CaptureQueriesContext(connection) as after:
            self.client.get(self.url)
        self.assertLessEqual(len(after), len(before) + 1)
