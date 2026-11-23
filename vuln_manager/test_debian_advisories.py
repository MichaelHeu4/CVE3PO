from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from vuln_manager.models import CTIFeed, CTIItem, DebianAdvisorySnapshot, Host, HostSoftwareRelationship, Software
from vuln_manager.utils.debian_advisories import apply_advisory_data, enrich_existing_items, parse_advisory_list, refresh_advisory_snapshots
from vuln_manager.utils.cti import fetch_feed
from vuln_manager.utils.debian_cti import assess_host


DLA_LIST = """[12 Nov 2026] DLA-4902-1 apache2 - security update
\t{CVE-2026-42356 CVE-2026-42528}
\t[bookworm] - apache2 2.4.71-1~deb12u1
[11 Nov 2026] DLA-4901-1 another - security update
\t{CVE-2026-77777}
\t[bookworm] - another 1.0-1+deb12u1
"""


class DebianAdvisoryTests(TestCase):
    def setUp(self):
        feed = CTIFeed.objects.get(name="Heise Security Alerts")
        self.item = CTIItem.objects.create(source=feed, external_id="dla-example", title="DLA-4902-1 apache2 - security update", summary="Multiple vulnerabilities", url="https://example.com/advisory")
        self.records = parse_advisory_list(DLA_LIST, "DLA")
        self.snapshot = DebianAdvisorySnapshot.objects.create(kind="DLA", fetched_at=timezone.now(), data=self.records)
        self.host = Host.objects.create(ip_address="192.0.2.77", operating_system="Debian GNU/Linux 12 (bookworm)")
        self.software = Software.objects.create(name="apache2", version="2.4.62-1~deb12u2")
        self.software.hosts.add(self.host)
        self.rel = HostSoftwareRelationship.objects.create(host=self.host, software=self.software, source="agent", package_manager="dpkg", source_package="apache2", source_version="2.4.62-1~deb12u2")

    def test_debian_list_extracts_cves_and_release_fix(self):
        self.assertEqual(self.records["DLA-4902-1"]["cves"], ["CVE-2026-42356", "CVE-2026-42528"])
        self.assertEqual(self.records["DLA-4902-1"]["fixes"], [{"release": "bookworm", "source_package": "apache2", "fixed_version": "2.4.71-1~deb12u1"}])
        self.assertNotIn("CVE-2026-77777", self.records["DLA-4902-1"]["cves"])

    def test_dsa_is_parsed_with_debian_epoch(self):
        text = "[19 Nov 2026] DSA-6642-1 nginx - security update\n\t{CVE-2026-113425}\n\t[trixie] - nginx 1:1.26.3-3+deb13u11\n"
        record = parse_advisory_list(text, "DSA")["DSA-6642-1"]
        self.assertEqual(record["cves"], ["CVE-2026-113425"])
        self.assertEqual(record["fixes"][0]["fixed_version"], "1:1.26.3-3+deb13u11")

    def test_existing_item_enriched_without_agent_or_feed_cves(self):
        self.item.feed_cves = ["CVE-2025-11111"]
        self.item.cves = self.item.feed_cves
        self.item.save(update_fields=["cves", "feed_cves"])
        enrich_existing_items()
        self.item.refresh_from_db()
        self.assertEqual(self.item.cves, ["CVE-2025-11111", "CVE-2026-42356", "CVE-2026-42528"])
        self.assertIn("DLA-4902-1", self.item.debian_advisories)

    @patch("vuln_manager.utils.cti.validate_feed_url")
    @patch("vuln_manager.utils.cti.requests.get")
    def test_feed_reimport_preserves_advisory_cves(self, get, validate):
        import hashlib
        url = "https://www.heise.de/news/example.html"
        self.item.external_id = hashlib.sha256(url.encode()).hexdigest()
        self.item.save(update_fields=["external_id"])
        apply_advisory_data(self.item, {"DLA": self.snapshot})
        response = MagicMock(status_code=200)
        response.iter_content.return_value = [b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>DLA-4902-1 apache2</title><link href="https://www.heise.de/news/example.html"/><summary>Update</summary></entry></feed>']
        get.return_value = response
        fetch_feed(self.item.source)
        self.item.refresh_from_db()
        self.assertIn("CVE-2026-42356", self.item.cves)
        self.assertEqual(self.item.feed_cves, [])

    def test_fix_is_compared_per_release_and_source(self):
        apply_advisory_data(self.item, {"DLA": self.snapshot})
        before = assess_host(self.item, self.software, self.host, None)
        self.assertEqual(before["status"], "below_fix")
        self.assertIn("2.4.71-1~deb12u1", before["reason"])
        self.rel.source_version = "2.4.71-1~deb12u1"
        self.rel.save(update_fields=["source_version"])
        self.assertEqual(assess_host(self.item, self.software, self.host, None)["status"], "fixed")
        self.host.operating_system = "Debian GNU/Linux 13 (trixie)"
        self.assertEqual(assess_host(self.item, self.software, self.host, None)["status"], "unknown")
        self.host.operating_system = "Debian GNU/Linux 12 (bookworm)"
        self.rel.source_package = "other"
        self.rel.save(update_fields=["source_package"])
        self.assertEqual(assess_host(self.item, self.software, self.host, None)["status"], "unknown")

    def test_detail_shows_advisory_cves_and_fix(self):
        from django.contrib.auth.models import User
        from django.urls import reverse
        self.client.force_login(User.objects.create_user("analyst"))
        apply_advisory_data(self.item, {"DLA": self.snapshot})
        from vuln_manager.utils.cti import suggest_matches
        suggest_matches(self.item)
        response = self.client.get(reverse("cti_detail", args=[self.item.pk]))
        self.assertContains(response, "CVE-2026-42356")
        self.assertContains(response, "2.4.71-1~deb12u1")
        self.assertContains(response, "Möglicherweise betroffen")

    def test_stale_or_incomplete_advisory_never_claims_fixed(self):
        self.snapshot.fetched_at = timezone.now() - timedelta(days=3)
        apply_advisory_data(self.item, {"DLA": self.snapshot})
        self.assertEqual(assess_host(self.item, self.software, self.host, None)["status"], "unknown")
        self.snapshot.fetched_at = timezone.now()
        apply_advisory_data(self.item, {"DLA": self.snapshot})
        self.rel.source_package = ""
        self.rel.save(update_fields=["source_package"])
        self.assertEqual(assess_host(self.item, self.software, self.host, None)["status"], "unknown")

    def test_multiple_advisories_without_full_data_are_not_declared_fixed(self):
        self.item.title = "DLA-4902-1 and DLA-4900-1"
        apply_advisory_data(self.item, {"DLA": self.snapshot})
        self.rel.source_version = "2.4.71-1~deb12u1"
        self.rel.save(update_fields=["source_version"])
        self.assertEqual(assess_host(self.item, self.software, self.host, None)["status"], "unknown")

    @patch("vuln_manager.utils.debian_advisories.requests.get")
    def test_failed_refresh_preserves_last_snapshot(self, get):
        self.snapshot.fetched_at = timezone.now() - timedelta(days=3)
        self.snapshot.save(update_fields=["fetched_at"])
        get.side_effect = RuntimeError("offline")
        refresh_advisory_snapshots({"DLA"})
        self.snapshot.refresh_from_db()
        self.assertIn("offline", self.snapshot.error)
        self.assertIn("DLA-4902-1", self.snapshot.data)

    @patch("vuln_manager.utils.debian_advisories.requests.get")
    def test_successful_refresh_persists_valid_snapshot(self, get):
        self.snapshot.fetched_at = None
        self.snapshot.save(update_fields=["fetched_at"])
        response = MagicMock(status_code=200)
        response.iter_content.return_value = [DLA_LIST.encode()]
        get.return_value.__enter__.return_value = response
        refresh_advisory_snapshots({"DLA"})
        self.snapshot.refresh_from_db()
        self.assertIsNotNone(self.snapshot.fetched_at)
        self.assertEqual(self.snapshot.data["DLA-4902-1"]["fixes"][0]["fixed_version"], "2.4.71-1~deb12u1")
