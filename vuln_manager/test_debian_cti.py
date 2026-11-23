from datetime import timedelta
from unittest.mock import MagicMock, Mock, patch
import io
import json

from django.test import TestCase
from django.utils import timezone

from vuln_manager.extensions.agent import _sync_inventory_payload
from vuln_manager.models import CTIFeed, CTIItem, CTIMatch, DebianTrackerSnapshot, Host, HostSoftwareRelationship, Software
from vuln_manager.utils.cti import suggest_matches
from vuln_manager.utils.debian_cti import assess_host, compare_debian_versions, debian_release, refresh_tracker


class DebianVersionTests(TestCase):
    def test_dpkg_ordering(self):
        for left, right in [("1:1.0-1", "2.0-99"), ("1.0-1+deb12u2", "1.0-1+deb12u1"), ("1.0-1", "1.0-1~bpo12+1"), ("1.0-10", "1.0-2")]:
            with self.subTest(left=left, right=right):
                self.assertGreater(compare_debian_versions(left, right), 0)
                self.assertLess(compare_debian_versions(right, left), 0)
        self.assertEqual(compare_debian_versions("1.0", "1.0-0"), 0)
        with self.assertRaises(ValueError):
            compare_debian_versions("unknown", "1.0-1")

    def test_release_is_host_specific(self):
        self.assertEqual(debian_release("Debian GNU/Linux 12 (bookworm)"), "bookworm")
        self.assertEqual(debian_release("Debian GNU/Linux 13"), "trixie")
        self.assertIsNone(debian_release("Ubuntu 24.04.1 LTS"))


class DebianAssessmentTests(TestCase):
    def setUp(self):
        self.feed = CTIFeed.objects.get(name="Heise Security Alerts")
        self.item = CTIItem.objects.create(source=self.feed, external_id="debian-test", title="openssl security issue", url="https://www.heise.de/news/x", cves=["CVE-2025-12345"])
        self.software = Software.objects.create(name="libssl3", version="3.0.11-1~deb12u1")
        self.host = Host.objects.create(ip_address="192.0.2.1", operating_system="Debian GNU/Linux 12 (bookworm)")
        self.software.hosts.add(self.host)
        self.rel = HostSoftwareRelationship.objects.create(host=self.host, software=self.software, source="agent", package_manager="dpkg", source_package="openssl", source_version="3.0.11-1~deb12u1")
        self.snapshot = DebianTrackerSnapshot.objects.create(fetched_at=timezone.now(), data={"openssl": {"CVE-2025-12345": {"releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.11-1~deb12u2"}}}}})

    def test_per_host_backport_and_source_package_match(self):
        suggest_matches(self.item)
        self.assertTrue(CTIMatch.objects.filter(item=self.item, software=self.software).exists())
        self.assertEqual(assess_host(self.item, self.software, self.host, self.snapshot)["status"], "below_fix")
        self.rel.source_version = "3.0.11-1~deb12u2"
        self.rel.save(update_fields=["source_version"])
        self.assertEqual(assess_host(self.item, self.software, self.host, self.snapshot)["status"], "fixed")
        other = Host.objects.create(ip_address="192.0.2.2", operating_system="Ubuntu 24.04")
        self.software.hosts.add(other)
        self.assertEqual(assess_host(self.item, self.software, other, self.snapshot)["status"], "unknown")

    def test_tracker_finds_source_package_even_if_feed_does_not_name_it(self):
        self.item.title = "Critical vulnerability"
        self.item.save(update_fields=["title"])
        suggest_matches(self.item)
        match = CTIMatch.objects.get(item=self.item, software=self.software)
        self.assertIn("Debian tracker source package", match.reason)

    def test_missing_cve_source_or_stale_data_stays_unknown(self):
        self.snapshot.fetched_at = timezone.now() - timedelta(days=3)
        self.assertEqual(assess_host(self.item, self.software, self.host, self.snapshot)["status"], "unknown")
        self.snapshot.fetched_at = timezone.now()
        self.rel.source_package = ""
        self.rel.save(update_fields=["source_package"])
        self.assertEqual(assess_host(self.item, self.software, self.host, self.snapshot)["status"], "unknown")
        self.rel.source_package = "openssl"
        self.rel.save(update_fields=["source_package"])
        self.item.cves = []
        self.assertEqual(assess_host(self.item, self.software, self.host, self.snapshot)["status"], "unknown")

    def test_one_unresolved_cve_does_not_claim_fixed(self):
        self.rel.source_version = "3.0.11-1~deb12u2"
        self.rel.save(update_fields=["source_version"])
        self.item.cves.append("CVE-2025-99999")
        self.assertEqual(assess_host(self.item, self.software, self.host, self.snapshot)["status"], "unknown")

    def test_agent_records_source_and_clears_it_for_old_payload(self):
        data = {"host_ip": "192.0.2.50", "operating_system": "Debian GNU/Linux 12", "software": [{"name": "libssl3", "version": "3.0", "package_manager": "dpkg", "source_package": "openssl", "source_version": "3.0-1"}]}
        host, _ = _sync_inventory_payload(data)
        rel = HostSoftwareRelationship.objects.get(host=host)
        self.assertEqual((rel.source_package, rel.source_version), ("openssl", "3.0-1"))
        data["software"] = [{"name": "libssl3", "version": "3.0"}]
        _sync_inventory_payload(data)
        rel.refresh_from_db()
        self.assertEqual(rel.source_package, "")

    @patch("vuln_manager.utils.debian_cti.requests.get")
    def test_tracker_failure_keeps_last_snapshot(self, get):
        self.snapshot.last_attempt = None
        self.snapshot.save(update_fields=["last_attempt"])
        get.side_effect = RuntimeError("offline")
        refresh_tracker()
        self.snapshot.refresh_from_db()
        self.assertIn("offline", self.snapshot.error)
        self.assertIn("openssl", self.snapshot.data)

    @patch("vuln_manager.utils.debian_cti.requests.get")
    def test_stream_refresh_keeps_only_inventory_packages_and_matching_fields(self, get):
        payload = {
            "unrelated": {"CVE-2025-00001": {"description": "not retained", "releases": {}}},
            "openssl": {"CVE-2025-12345": {"description": "not retained", "releases": {"bookworm": {"status": "resolved", "fixed_version": "3.0.11-1~deb12u2", "repositories": {"bookworm": "3.0"}}}}},
        }
        response = MagicMock(status_code=200)
        response.raw = io.BytesIO(json.dumps(payload).encode())
        get.return_value.__enter__.return_value = response
        refresh_tracker()
        self.snapshot.refresh_from_db()
        self.assertEqual(self.snapshot.covered_packages, ["openssl"])
        self.assertEqual(list(self.snapshot.data), ["openssl"])
        self.assertEqual(self.snapshot.data["openssl"]["CVE-2025-12345"]["releases"]["bookworm"], {"status": "resolved", "fixed_version": "3.0.11-1~deb12u2"})
        self.assertEqual(assess_host(self.item, self.software, self.host, self.snapshot)["status"], "below_fix")
        refresh_tracker()
        self.assertEqual(get.call_count, 1)

    @patch("vuln_manager.utils.debian_cti.requests.get")
    def test_added_source_package_refreshes_fresh_snapshot(self, get):
        payload = {"openssl": {}, "apache2": {"CVE-2025-99999": {"releases": {}}}}
        def response():
            value = MagicMock(status_code=200)
            value.raw = io.BytesIO(json.dumps(payload).encode())
            return value
        get.return_value.__enter__.side_effect = [response(), response()]
        refresh_tracker()
        other = Software.objects.create(name="apache2", version="1")
        HostSoftwareRelationship.objects.create(host=self.host, software=other, source="agent", package_manager="dpkg", source_package="apache2", source_version="1")
        refresh_tracker()
        self.snapshot.refresh_from_db()
        self.assertEqual(self.snapshot.covered_packages, ["apache2", "openssl"])
        self.assertIn("apache2", self.snapshot.data)
        self.assertEqual(get.call_count, 2)

    @patch("vuln_manager.utils.debian_cti.requests.get")
    def test_truncated_stream_preserves_existing_snapshot(self, get):
        response = MagicMock(status_code=200)
        response.raw = io.BytesIO(b'{"openssl":{"CVE-2025-12345":')
        get.return_value.__enter__.return_value = response
        old_data, old_time = self.snapshot.data, self.snapshot.fetched_at
        refresh_tracker()
        self.snapshot.refresh_from_db()
        self.assertEqual(self.snapshot.data, old_data)
        self.assertEqual(self.snapshot.fetched_at, old_time)
        self.assertTrue(self.snapshot.error)

    @patch("vuln_manager.utils.debian_cti.MAX_SNAPSHOT_BYTES", 32)
    @patch("vuln_manager.utils.debian_cti.requests.get")
    def test_oversized_stream_does_not_replace_last_snapshot(self, get):
        response = MagicMock(status_code=200)
        response.raw = io.BytesIO(json.dumps({"openssl": {"CVE-2025-12345": {"description": "x" * 100}}}).encode())
        get.return_value.__enter__.return_value = response
        old_data = self.snapshot.data
        refresh_tracker()
        self.snapshot.refresh_from_db()
        self.assertEqual(self.snapshot.data, old_data)
        self.assertIn("exceeds size limit", self.snapshot.error)
