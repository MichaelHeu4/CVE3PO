from unittest.mock import patch

import json

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from vuln_manager.models import (
    Extension,
    Host,
    HostSoftwareRelationship,
    Scan,
    Software,
    Vulnerability,
    VulnerabilityAuditEvent,
)
from vuln_manager.utils.osv_auto import (
    _extract_nvd_cvss_and_severity,
    enrich_software_with_osv,
)


class NvdAutoLookupTests(TestCase):
    def test_extract_nvd_cvss_and_severity_uses_v31_metrics(self):
        cve = {
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                        }
                    }
                ]
            }
        }

        cvss, severity = _extract_nvd_cvss_and_severity(cve)
        self.assertEqual(cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(severity, "critical")

    @patch("vuln_manager.utils.osv_auto._candidate_nvd_keywords", return_value=["openssl 3.0.0"])
    @patch("vuln_manager.utils.osv_auto._cve_matches_software", return_value=True)
    @patch("vuln_manager.utils.osv_auto._query_osv", return_value=[])
    @patch("vuln_manager.utils.osv_auto._query_nvd_by_keyword")
    def test_enrich_software_with_osv_also_creates_nvd_vulnerability(
        self,
        query_nvd_mock,
        _query_osv_mock,
        _matches_mock,
        _keywords_mock,
    ):
        query_nvd_mock.return_value = [
            {
                "id": "CVE-2024-12345",
                "descriptions": [{"lang": "en", "value": "OpenSSL test issue"}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 8.8,
                                "baseSeverity": "HIGH",
                            }
                        }
                    ]
                },
            }
        ]

        sw = Software.objects.create(name="openssl", version="3.0.0", vendor="openssl")
        enrich_software_with_osv(sw.id)

        vuln = Vulnerability.objects.get(cve_id="CVE-2024-12345", software=sw)
        self.assertEqual(vuln.scan.scan_type, "NVD")
        self.assertEqual(vuln.severity, "high")
        self.assertEqual(vuln.name, "NVD: CVE-2024-12345")


class SoftwareDeletionStatusTests(TestCase):
    def test_deleting_software_marks_open_vulnerabilities_fixed_and_audits(self):
        scan = Scan.objects.create(scan_type="MANUAL")
        sw = Software.objects.create(name="nginx", version="1.25.5", vendor="nginx")
        vuln = Vulnerability.objects.create(
            scan=scan,
            software=sw,
            cve_id="CVE-2025-10000",
            severity="high",
            status="open",
            name="Test vuln",
        )

        Software.objects.filter(pk=sw.pk).delete()

        vuln.refresh_from_db()
        self.assertEqual(vuln.status, "fixed")
        self.assertIsNone(vuln.software)

        event = VulnerabilityAuditEvent.objects.filter(
            vulnerability=vuln, action="status_changed"
        ).latest("created_at")
        self.assertEqual(event.actor, "software_delete:auto_close")
        self.assertEqual(event.details.get("from_status"), "open")
        self.assertEqual(event.details.get("to_status"), "fixed")
        self.assertEqual(event.details.get("reason"), "software_deleted")

    def test_deleting_software_keeps_risk_accepted_unchanged(self):
        scan = Scan.objects.create(scan_type="MANUAL")
        sw = Software.objects.create(name="apache", version="2.4.0", vendor="apache")
        vuln = Vulnerability.objects.create(
            scan=scan,
            software=sw,
            cve_id="CVE-2025-20000",
            severity="medium",
            status="risk_accepted",
            name="Accepted risk vuln",
        )

        Software.objects.filter(pk=sw.pk).delete()

        vuln.refresh_from_db()
        self.assertEqual(vuln.status, "risk_accepted")
        self.assertIsNone(vuln.software)


class AuthAndStatusFlowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="alice", email="a@example.com", password="pw12345")
        self.scan = Scan.objects.create(scan_type="MANUAL")
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            cve_id="CVE-2026-11111",
            severity="medium",
            status="open",
            name="Status update test",
        )

    def test_dashboard_requires_login(self):
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_login_with_email_works(self):
        response = self.client.post(
            reverse("login"),
            {"identifier": "a@example.com", "password": "pw12345"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "dashboard")

    def test_update_vuln_status_json_updates_and_audits(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("api_update_vuln_status", args=[self.vuln.pk]),
            data=json.dumps({"status": "in_progress"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "in_progress")
        event = VulnerabilityAuditEvent.objects.filter(
            vulnerability=self.vuln, action="status_changed", user=self.user
        ).latest("created_at")
        self.assertEqual(event.details.get("from_status"), "open")
        self.assertEqual(event.details.get("to_status"), "in_progress")

    def test_update_vuln_status_invalid_value_keeps_status(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("api_update_vuln_status", args=[self.vuln.pk]),
            data=json.dumps({"status": "invalid_status"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")


class SoftwareRescanPermissionTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(username="staff", password="pw12345", is_staff=True)
        self.user = User.objects.create_user(username="bob", password="pw12345", is_staff=False)
        self.software = Software.objects.create(name="openssl", version="3.0.0", vendor="openssl")

    def test_rescan_requires_staff(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("software_rescan_osv", args=[self.software.pk]))
        self.assertEqual(response.status_code, 403)

    @patch("vuln_manager.views.threading.Thread")
    def test_rescan_starts_background_thread_for_staff(self, thread_cls):
        self.client.force_login(self.staff)
        response = self.client.post(reverse("software_rescan_osv", args=[self.software.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("software_detail", args=[self.software.pk]))
        thread_cls.assert_called_once()
        thread_cls.return_value.start.assert_called_once()

    def test_rescan_requires_version(self):
        no_version = Software.objects.create(name="pkg-no-version", version=None, vendor="x")
        self.client.force_login(self.staff)
        response = self.client.post(reverse("software_rescan_osv", args=[no_version.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content.decode(), "missing_version")


class AgentInventorySnapshotSyncTests(TestCase):
    def setUp(self):
        self.scan = Scan.objects.create(scan_type="MANUAL")
        self.extension = Extension.objects.create(
            name_id="agent_api",
            is_active=True,
            api_token="token-123",
        )
        self.url = reverse("api_update_inventory")

    def _post_inventory(self, payload, token="token-123"):
        return self.client.post(
            self.url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_API_KEY=token,
        )

    def test_inventory_rejects_invalid_token(self):
        response = self._post_inventory({"host_ip": "10.0.0.1", "software": []}, token="wrong")
        self.assertEqual(response.status_code, 401)

    def test_inventory_requires_host_ip(self):
        response = self._post_inventory({"software": []})
        self.assertEqual(response.status_code, 400)

    def test_inventory_returns_404_when_agent_extension_inactive(self):
        self.extension.is_active = False
        self.extension.save(update_fields=["is_active"])
        response = self._post_inventory({"host_ip": "10.0.0.1", "software": []})
        self.assertEqual(response.status_code, 404)

    def test_snapshot_removes_stale_agent_software_and_auto_fixes_linked_vuln(self):
        host = Host.objects.create(ip_address="10.0.0.10")
        stale_sw = Software.objects.create(name="oldpkg", version="1.0.0", vendor="acme")
        stale_sw.hosts.add(host)
        HostSoftwareRelationship.objects.create(host=host, software=stale_sw, source="agent")
        vuln = Vulnerability.objects.create(
            scan=self.scan,
            software=stale_sw,
            cve_id="CVE-2026-22222",
            severity="high",
            status="open",
            name="Old software vuln",
        )

        response = self._post_inventory(
            {
                "host_ip": "10.0.0.10",
                "hostname": "srv-01",
                "operating_system": "Ubuntu 24.04",
                "software": [
                    {
                        "name": "newpkg",
                        "version": "2.0.0",
                        "vendor": "acme",
                        "port": 443,
                    }
                ],
            }
        )
        self.assertEqual(response.status_code, 200)

        self.assertFalse(Software.objects.filter(pk=stale_sw.pk).exists())
        new_sw = Software.objects.get(name="newpkg", version="2.0.0", vendor="acme")
        self.assertTrue(new_sw.hosts.filter(pk=host.pk).exists())
        self.assertTrue(
            HostSoftwareRelationship.objects.filter(
                host=host, software=new_sw, source="agent"
            ).exists()
        )

        host.refresh_from_db()
        self.assertEqual(host.hostname, "srv-01")
        self.assertEqual(host.operating_system, "Ubuntu 24.04")

        vuln.refresh_from_db()
        self.assertEqual(vuln.status, "fixed")
        self.assertIsNone(vuln.software)
        event = VulnerabilityAuditEvent.objects.filter(
            vulnerability=vuln,
            action="status_changed",
            actor="software_delete:auto_close",
        ).latest("created_at")
        self.assertEqual(event.details.get("reason"), "software_deleted")
