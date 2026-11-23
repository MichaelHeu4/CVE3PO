from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from vuln_manager.extensions.agent import _sync_inventory_payload
from vuln_manager.models import CTIFeed, CTIItem, Host, HostSoftwareRelationship, InventoryFindingClosure, Scan, Software, SystemSettings, Vulnerability, VulnerabilityAuditEvent
from vuln_manager.utils.inventory_lifecycle import cleanup_inventory_findings


class InventoryLifecycleTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(ip_address="192.0.2.80", hostname="host-a")
        self.sw = Software.objects.create(name="example", version="1.0")
        self.sw.hosts.add(self.host)
        self.rel = HostSoftwareRelationship.objects.create(host=self.host, software=self.sw, source="agent", package_manager="dpkg")
        self.scan = Scan.objects.create(scan_type="MANUAL")
        self.vuln = Vulnerability.objects.create(scan=self.scan, software=self.sw, cve_id="CVE-2025-12345", severity="high", name="Test")
        self.base = int(timezone.now().timestamp() * 1000) - 10000

    def payload(self, number, software=None, **changes):
        data = {"host_ip": self.host.ip_address, "inventory_complete": True, "snapshot_started_ms": self.base + number, "complete_sources": ["dpkg"], "software": software if software is not None else []}
        data.update(changes)
        return data

    def test_two_unique_complete_snapshots_are_required(self):
        _sync_inventory_payload(self.payload(1))
        self.vuln.refresh_from_db()
        self.rel.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")
        self.assertEqual(self.rel.missing_snapshots, 1)
        _sync_inventory_payload(self.payload(1))  # duplicate is not another snapshot
        _sync_inventory_payload(self.payload(0))  # older snapshot cannot count
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")
        _sync_inventory_payload(self.payload(2))
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "fixed")
        self.assertEqual(self.vuln.fixed_at, self.vuln.inventory_closed_at)
        self.assertFalse(self.sw.hosts.filter(pk=self.host.pk).exists())
        self.assertEqual(InventoryFindingClosure.objects.get(vulnerability=self.vuln).reason, "removed")

    def test_old_incomplete_and_other_source_snapshots_do_not_close(self):
        for data in [self.payload(1, inventory_complete=False), {"host_ip": self.host.ip_address, "software": []}, self.payload(2, complete_sources=["rpm"])]:
            _sync_inventory_payload(data)
        self.vuln.refresh_from_db()
        self.rel.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")
        self.assertEqual(self.rel.missing_snapshots, 0)

    def test_incomplete_entry_and_future_timestamp_do_not_confirm_absence(self):
        _sync_inventory_payload(self.payload(1, [{"name": "another", "version": "", "package_manager": "dpkg"}]))
        _sync_inventory_payload(self.payload(2, snapshot_started_ms=int(timezone.now().timestamp() * 1000) + 600000))
        self.rel.refresh_from_db()
        self.vuln.refresh_from_db()
        self.assertEqual(self.rel.missing_snapshots, 0)
        self.assertEqual(self.vuln.status, "open")

    def test_presence_resets_absence_count(self):
        _sync_inventory_payload(self.payload(1))
        _sync_inventory_payload(self.payload(2, [{"name": "example", "version": "1.0", "package_manager": "dpkg"}]))
        _sync_inventory_payload(self.payload(3))
        self.rel.refresh_from_db()
        self.assertEqual(self.rel.missing_snapshots, 1)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")

    def test_changed_vendor_representation_does_not_count_as_absence(self):
        same_package = [{"name": "example", "version": "1.0", "vendor": "changed", "package_manager": "dpkg"}]
        _sync_inventory_payload(self.payload(1, same_package))
        _sync_inventory_payload(self.payload(2, same_package))
        self.vuln.refresh_from_db()
        self.rel.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")
        self.assertEqual(self.rel.missing_snapshots, 0)

    def test_shared_software_closes_only_after_last_host(self):
        second = Host.objects.create(ip_address="192.0.2.81", hostname="host-b")
        self.sw.hosts.add(second)
        HostSoftwareRelationship.objects.create(host=second, software=self.sw, source="agent", package_manager="dpkg")
        host_finding = Vulnerability.objects.create(scan=self.scan, host=self.host, software=self.sw, cve_id="CVE-2025-33333", severity="high", name="Host specific")
        for number in (1, 2):
            _sync_inventory_payload(self.payload(number))
        self.vuln.refresh_from_db()
        host_finding.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")
        self.assertEqual(host_finding.status, "fixed")
        self.assertTrue(self.sw.hosts.filter(pk=second.pk).exists())
        for number in (3, 4):
            _sync_inventory_payload({**self.payload(number), "host_ip": second.ip_address})
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "fixed")

    def test_version_change_and_reappearance(self):
        replacement = [{"name": "example", "version": "2.0", "package_manager": "dpkg"}]
        _sync_inventory_payload(self.payload(1, replacement))
        _sync_inventory_payload(self.payload(2, replacement))
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "fixed")
        self.assertEqual(self.vuln.inventory_closures.get().reason, "version_changed")
        self.assertTrue(Software.objects.filter(name="example", version="2.0", hosts=self.host).exists())
        _sync_inventory_payload(self.payload(3, [{"name": "example", "version": "1.0", "package_manager": "dpkg"}]))
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")
        self.assertIsNotNone(self.vuln.inventory_closures.get().reopened_at)

    def test_retention_only_deletes_inventory_closed_findings(self):
        _sync_inventory_payload(self.payload(1))
        _sync_inventory_payload(self.payload(2))
        self.vuln.refresh_from_db()
        closed = timezone.now() - timedelta(days=31)
        Vulnerability.objects.filter(pk=self.vuln.pk).update(fixed_at=closed, inventory_closed_at=closed)
        manual = Vulnerability.objects.create(scan=self.scan, status="fixed", fixed_at=closed, cve_id="CVE-2025-22222", severity="low", name="manual")
        SystemSettings.objects.update_or_create(pk=1, defaults={"inventory_retention_days": 30})
        self.assertEqual(cleanup_inventory_findings(), 1)
        self.assertFalse(Vulnerability.objects.filter(pk=self.vuln.pk).exists())
        self.assertTrue(Vulnerability.objects.filter(pk=manual.pk).exists())
        self.assertTrue(VulnerabilityAuditEvent.objects.filter(action="deleted", details__bulk="inventory_retention").exists())

    def test_retention_does_not_delete_reinstalled_software(self):
        _sync_inventory_payload(self.payload(1))
        _sync_inventory_payload(self.payload(2))
        closed = timezone.now() - timedelta(days=100)
        Vulnerability.objects.filter(pk=self.vuln.pk).update(fixed_at=closed, inventory_closed_at=closed)
        self.sw.hosts.add(self.host)  # manual or scanner re-association
        self.assertEqual(cleanup_inventory_findings(), 0)
        self.assertTrue(Vulnerability.objects.filter(pk=self.vuln.pk).exists())

    @patch("vuln_manager.signals.schedule_software_enrichment")
    def test_reintroduced_software_is_checked_after_old_finding_was_deleted(self, schedule):
        _sync_inventory_payload(self.payload(1))
        _sync_inventory_payload(self.payload(2))
        old = timezone.now() - timedelta(days=100)
        Vulnerability.objects.filter(pk=self.vuln.pk).update(fixed_at=old, inventory_closed_at=old)
        self.assertEqual(cleanup_inventory_findings(), 1)
        _sync_inventory_payload(self.payload(3, [{"name": "example", "version": "1.0", "package_manager": "dpkg"}]))
        schedule.assert_called_once_with(self.sw.pk)

    def test_host_specific_retention_does_not_require_removal_from_other_hosts(self):
        other = Host.objects.create(ip_address="192.0.2.82")
        self.sw.hosts.add(other)
        direct = Vulnerability.objects.create(scan=self.scan, host=self.host, software=self.sw, cve_id="CVE-2025-44444", severity="high", name="Direct")
        _sync_inventory_payload(self.payload(1))
        _sync_inventory_payload(self.payload(2))
        old = timezone.now() - timedelta(days=100)
        Vulnerability.objects.filter(pk=direct.pk).update(fixed_at=old, inventory_closed_at=old)
        self.assertEqual(cleanup_inventory_findings(), 1)
        self.assertFalse(Vulnerability.objects.filter(pk=direct.pk).exists())
        self.assertTrue(Vulnerability.objects.filter(pk=self.vuln.pk, status="open").exists())

    def test_general_fixed_cleanup_does_not_override_inventory_retention(self):
        from vuln_manager.utils.scheduler import run_fixed_vulnerability_cleanup
        _sync_inventory_payload(self.payload(1))
        _sync_inventory_payload(self.payload(2))
        old = timezone.now() - timedelta(days=40)
        Vulnerability.objects.filter(pk=self.vuln.pk).update(fixed_at=old, inventory_closed_at=old)
        SystemSettings.objects.update_or_create(pk=1, defaults={"auto_delete_fixed_days": 5, "inventory_retention_days": 90})
        self.assertEqual(run_fixed_vulnerability_cleanup()["deleted"], 0)
        self.assertTrue(Vulnerability.objects.filter(pk=self.vuln.pk).exists())

    def test_retention_setting_requires_staff(self):
        user = User.objects.create_user("regular")
        self.client.force_login(user)
        self.assertEqual(self.client.post(reverse("save_inventory_retention"), {"inventory_retention_days": "10"}).status_code, 403)
        user.is_staff = True
        user.save(update_fields=["is_staff"])
        self.assertEqual(self.client.post(reverse("save_inventory_retention"), {"inventory_retention_days": "10"}).status_code, 302)
        self.assertEqual(SystemSettings.objects.get(pk=1).inventory_retention_days, 10)


class CTIFindingVisibilityTests(TestCase):
    def test_fixed_findings_hidden_by_default_and_none_has_label(self):
        user = User.objects.create_user("analyst")
        self.client.force_login(user)
        feed = CTIFeed.objects.get(name="Heise Security Alerts")
        item = CTIItem.objects.create(source=feed, external_id="visibility", title="Example", url="https://example.com/advisory", cves=["CVE-2025-10001", "CVE-2025-10002"])
        scan = Scan.objects.create(scan_type="MANUAL")
        open_vuln = Vulnerability.objects.create(scan=scan, cve_id="CVE-2025-10001", severity="high", name="Unassigned")
        fixed = Vulnerability.objects.create(scan=scan, cve_id="CVE-2025-10002", severity="high", name="Closed", status="fixed")
        item.findings.add(open_vuln, fixed)
        url = reverse("cti_detail", args=[item.pk])
        response = self.client.get(url)
        self.assertContains(response, "Nicht zugeordnet")
        self.assertNotContains(response, "Closed")
        self.assertContains(response, "CVE-2025-10002")  # advisory CVE still visible
        self.assertContains(self.client.get(url + "?include_fixed=1"), "Closed")
