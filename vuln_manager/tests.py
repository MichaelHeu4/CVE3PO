from unittest.mock import patch

import json
import io
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.test.utils import override_settings
from django.urls import reverse
from django.utils import timezone

from vuln_manager.models import (
    Extension,
    Host,
    HostSoftwareRelationship,
    Scan,
    Software,
    Vulnerability,
    VulnerabilityAuditEvent,
    SystemSettings,
)
from vuln_manager.utils.osv_auto import (
    _extract_nvd_cvss_and_severity,
    enrich_software_with_osv,
)
from vuln_manager.utils.enrichment import get_cve_details


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


class CveDetailEnrichmentParsingTests(TestCase):
    @patch("vuln_manager.utils.enrichment.requests.get")
    def test_get_cve_details_supports_cve_json_5_descriptions(self, get_mock):
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {
            "containers": {
                "cna": {
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Improper access control in PAM propagation scripts.",
                            "supportingMedia": [
                                {
                                    "type": "text/html",
                                    "value": "<div>Improper access control in PAM propagation scripts.</div>",
                                }
                            ],
                        }
                    ]
                }
            },
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
                        }
                    }
                ]
            },
        }

        cvss, description = get_cve_details("CVE-2023-5240")
        self.assertEqual(cvss, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(
            description, "Improper access control in PAM propagation scripts."
        )


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


class HostDeletionOrphanCleanupTests(TestCase):
    def test_deleting_host_removes_software_only_linked_to_it(self):
        host = Host.objects.create(ip_address="10.0.1.10")
        orphan_sw = Software.objects.create(name="orphan-sw", version="1.0", vendor="acme")
        orphan_sw.hosts.add(host)

        Host.objects.filter(pk=host.pk).delete()

        self.assertFalse(Software.objects.filter(pk=orphan_sw.pk).exists())

    def test_deleting_host_keeps_shared_software(self):
        host_a = Host.objects.create(ip_address="10.0.1.20")
        host_b = Host.objects.create(ip_address="10.0.1.21")
        shared_sw = Software.objects.create(name="shared-sw", version="1.0", vendor="acme")
        shared_sw.hosts.add(host_a, host_b)

        Host.objects.filter(pk=host_a.pk).delete()

        self.assertTrue(Software.objects.filter(pk=shared_sw.pk).exists())
        self.assertTrue(Software.objects.get(pk=shared_sw.pk).hosts.filter(pk=host_b.pk).exists())

    def test_deleting_host_removes_orphan_vulnerabilities(self):
        scan = Scan.objects.create(scan_type="MANUAL")
        host = Host.objects.create(ip_address="10.0.1.30")
        orphan_sw = Software.objects.create(name="orphan-vuln-sw", version="2.0", vendor="acme")
        orphan_sw.hosts.add(host)
        orphan_vuln = Vulnerability.objects.create(
            scan=scan,
            software=orphan_sw,
            host=None,
            cve_id="CVE-2026-40001",
            severity="high",
            status="open",
            name="Orphan vulnerability",
        )

        Host.objects.filter(pk=host.pk).delete()

        self.assertFalse(Vulnerability.objects.filter(pk=orphan_vuln.pk).exists())


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

    def test_dashboard_contains_extended_kpis(self):
        host = Host.objects.create(ip_address="10.0.0.20")
        sw = Software.objects.create(name="demo", version="1.0.0", vendor="acme")
        sw.hosts.add(host)
        self.vuln.software = sw
        self.vuln.save(update_fields=["software"])

        self.client.force_login(self.user)
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertIn("remediation_rate", response.context)
        self.assertIn("avg_open_age_days", response.context)
        self.assertIn("sla_breach_count", response.context)
        self.assertIn("status_map", response.context)
        self.assertIn("top_software", response.context)


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


class GlobalSearchPaginationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="searcher", password="pw12345")

    def test_host_search_filters_across_all_pages(self):
        for i in range(30):
            Host.objects.create(ip_address=f"10.10.0.{i+1}", hostname=f"host-{i+1}")
        Host.objects.create(ip_address="10.10.2.200", hostname="needle-host")

        self.client.force_login(self.user)
        response = self.client.get(reverse("host_list") + "?q=needle-host")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["hosts"].paginator.count, 1)
        self.assertContains(response, "needle-host")

    def test_software_search_filters_across_all_pages(self):
        for i in range(30):
            Software.objects.create(name=f"pkg-{i}", version="1.0.0", vendor="acme")
        Software.objects.create(name="needle-package", version="9.9.9", vendor="acme")

        self.client.force_login(self.user)
        response = self.client.get(reverse("software_list") + "?q=needle-package")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["software"].paginator.count, 1)
        self.assertContains(response, "needle-package")

    def test_vulnerability_search_filters_across_all_pages(self):
        scan = Scan.objects.create(scan_type="MANUAL")
        for i in range(60):
            Vulnerability.objects.create(
                scan=scan,
                cve_id=f"CVE-2026-{10000+i}",
                severity="medium",
                status="open",
                name=f"bulk-vuln-{i}",
            )
        Vulnerability.objects.create(
            scan=scan,
            cve_id="CVE-2099-4242",
            severity="high",
            status="open",
            name="needle vulnerability",
        )

        self.client.force_login(self.user)
        response = self.client.get(reverse("vuln_list") + "?status=active&q=4242")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["vulns"].paginator.count, 1)
        self.assertContains(response, "CVE-2099-4242")


class HostDetailInventorySearchTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="hostinv", password="pw12345")
        self.host = Host.objects.create(ip_address="10.22.0.10", hostname="inv-host")
        for i in range(25):
            sw = Software.objects.create(name=f"component-{i}", version="1.0.0", vendor="acme")
            sw.hosts.add(self.host)
        needle = Software.objects.create(name="needle-component", version="9.1.1", vendor="acme")
        needle.hosts.add(self.host)

    def test_inventory_search_filters_across_all_pages(self):
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("host_detail", args=[self.host.pk]) + "?tab=inventory&inv_q=needle-component"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["installed_software"].paginator.count, 1)
        self.assertContains(response, "needle-component")


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

    @patch("vuln_manager.extensions.agent.threading.Thread")
    def test_large_inventory_payload_is_accepted_and_processed_async(self, thread_cls):
        payload = {
            "host_ip": "10.0.0.55",
            "software": [
                {"name": f"pkg-{i}", "version": "1.0.0", "vendor": "acme"}
                for i in range(220)
            ],
        }
        response = self._post_inventory(payload)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json().get("status"), "accepted")
        thread_cls.assert_called_once()
        thread_cls.return_value.start.assert_called_once()


class WazuhWebhookAuthTests(TestCase):
    def setUp(self):
        self.url = reverse("wazuh_webhook")
        self.extension = Extension.objects.create(
            name_id="wazuh",
            is_active=True,
            api_token="wazuh-token-123",
        )
        self.payload = {
            "agent": {"ip": "10.30.0.10", "name": "wazuh-agent"},
            "data": {
                "vulnerability": {
                    "cve": "CVE-2026-90001",
                    "severity": "high",
                    "title": "Wazuh finding",
                    "status": "VALID",
                }
            },
        }

    def test_wazuh_webhook_accepts_authorization_bearer_token(self):
        response = self.client.post(
            self.url,
            data=json.dumps(self.payload),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer wazuh-token-123",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("status"), "upserted")

    def test_wazuh_webhook_still_accepts_x_api_key(self):
        response = self.client.post(
            self.url,
            data=json.dumps(self.payload),
            content_type="application/json",
            HTTP_X_API_KEY="wazuh-token-123",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json().get("status"), "upserted")

    def test_wazuh_webhook_rejects_missing_token(self):
        response = self.client.post(
            self.url,
            data=json.dumps(self.payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)


class ManualVulnerabilityEnrichmentTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="enricher", password="pw12345")
        self.scan = Scan.objects.create(scan_type="MANUAL")
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            cve_id="CVE-2026-33333",
            severity="medium",
            status="open",
            name="Manual finding",
            description="",
            cvss="",
        )

    @patch("vuln_manager.views.get_cve_details")
    def test_enrich_single_vulnerability_updates_cvss_and_description(self, cve_details_mock):
        cve_details_mock.return_value = (
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "Updated description from external source",
        )
        self.client.force_login(self.user)
        response = self.client.post(reverse("enrich_single_vulnerability", args=[self.vuln.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("vuln_detail", args=[self.vuln.pk]))
        self.vuln.refresh_from_db()
        self.assertEqual(
            self.vuln.cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        self.assertEqual(
            self.vuln.description, "Updated description from external source"
        )
        event = VulnerabilityAuditEvent.objects.filter(
            vulnerability=self.vuln, action="updated", user=self.user
        ).latest("created_at")
        self.assertEqual(event.details.get("source"), "manual_enrich")

    @patch("vuln_manager.views.get_cve_details", return_value=(None, None))
    def test_enrich_single_vulnerability_without_data_keeps_existing_values(
        self, _cve_details_mock
    ):
        self.vuln.cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        self.vuln.description = "Existing text"
        self.vuln.save(update_fields=["cvss", "description"])
        self.client.force_login(self.user)
        response = self.client.post(reverse("enrich_single_vulnerability", args=[self.vuln.pk]))
        self.assertEqual(response.status_code, 302)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.cvss, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")
        self.assertEqual(self.vuln.description, "Existing text")


class SeverityFilterAndSingleTriageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="eve", password="pw12345")
        Extension.objects.create(name_id="ai_triage", is_active=True)
        self.scan = Scan.objects.create(scan_type="MANUAL")
        self.host = Host.objects.create(ip_address="10.0.0.30")
        self.software = Software.objects.create(name="svc", version="1.0.0", vendor="acme")
        self.software.hosts.add(self.host)

        self.v_critical = Vulnerability.objects.create(
            scan=self.scan,
            host=self.host,
            software=self.software,
            cve_id="CVE-2026-30001",
            severity="critical",
            status="open",
            name="Critical issue",
        )
        self.v_low = Vulnerability.objects.create(
            scan=self.scan,
            host=self.host,
            software=self.software,
            cve_id="CVE-2026-30002",
            severity="low",
            status="open",
            name="Low issue",
        )

    def test_host_detail_filters_by_severity(self):
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("host_detail", args=[self.host.pk]) + "?tab=threats&severity=critical"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["severity_filter"], "critical")
        vulns = list(response.context["vulns"].object_list)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].cve_id, "CVE-2026-30001")

    def test_software_detail_filters_by_severity(self):
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("software_detail", args=[self.software.pk]) + "?severity=low"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["severity_filter"], "low")
        vulns = list(response.context["vulns"])
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].cve_id, "CVE-2026-30002")

    def test_kanban_filters_by_severity(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("kanban_board") + "?severity=critical")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["severity_filter"], "critical")
        self.assertEqual(response.context["board"]["open"].count(), 1)
        self.assertEqual(response.context["board"]["open"].first().cve_id, "CVE-2026-30001")

    def test_vuln_list_filters_by_severity(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("vuln_list") + "?status=active&severity=low")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["severity"], "low")
        vulns = list(response.context["vulns"].object_list)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].cve_id, "CVE-2026-30002")

    @patch("vuln_manager.views.threading.Thread")
    def test_single_vulnerability_retriage_endpoint(self, thread_cls):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("triage_single_vulnerability", args=[self.v_critical.pk])
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("vuln_detail", args=[self.v_critical.pk]))
        thread_cls.assert_called_once()
        thread_cls.return_value.start.assert_called_once()
        event = VulnerabilityAuditEvent.objects.filter(
            vulnerability=self.v_critical, action="updated", user=self.user
        ).latest("created_at")
        self.assertEqual(event.details.get("source"), "manual_retriage")


class ScanDiffViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="diff-user", password="pw12345")
        self.host = Host.objects.create(ip_address="10.0.2.10")
        self.software = Software.objects.create(name="diff-sw", version="1.0", vendor="acme")
        self.software.hosts.add(self.host)

    def test_scan_list_exposes_diff_for_scans_with_previous_same_type(self):
        older = Scan.objects.create(scan_type="NMAP")
        newer = Scan.objects.create(scan_type="NMAP")
        self.client.force_login(self.user)
        response = self.client.get(reverse("scan_list"))
        self.assertEqual(response.status_code, 200)
        newer_in_context = next(scan for scan in response.context["scans"] if scan.pk == newer.pk)
        self.assertIsNotNone(newer_in_context.previous_same_type)
        self.assertEqual(newer_in_context.previous_same_type.pk, older.pk)

    def test_scan_diff_shows_new_reopened_and_fixed_counts(self):
        self.client.force_login(self.user)

        older = Scan.objects.create(scan_type="NMAP")
        newer = Scan.objects.create(scan_type="NMAP")
        t1 = timezone.now() - timedelta(hours=2)
        t2 = timezone.now() - timedelta(hours=1)
        Scan.objects.filter(pk=older.pk).update(uploaded_at=t1)
        Scan.objects.filter(pk=newer.pk).update(uploaded_at=t2)
        older.refresh_from_db()
        newer.refresh_from_db()

        new_vuln = Vulnerability.objects.create(
            scan=newer,
            host=self.host,
            software=self.software,
            cve_id="CVE-2026-50001",
            severity="high",
            status="open",
            name="New finding",
            first_seen=t2 + timedelta(minutes=1),
            last_seen=t2 + timedelta(minutes=1),
        )
        reopened_vuln = Vulnerability.objects.create(
            scan=newer,
            host=self.host,
            software=self.software,
            cve_id="CVE-2026-50002",
            severity="medium",
            status="open",
            name="Reopened finding",
            first_seen=t1 - timedelta(days=1),
            last_seen=t2 + timedelta(minutes=2),
        )
        reopened_event = VulnerabilityAuditEvent.objects.create(
            vulnerability=reopened_vuln,
            action="reopened",
            actor="test",
            details={"from_status": "fixed", "to_status": "open"},
        )
        VulnerabilityAuditEvent.objects.filter(pk=reopened_event.pk).update(
            created_at=t2 + timedelta(minutes=3)
        )

        fixed_vuln = Vulnerability.objects.create(
            scan=older,
            host=self.host,
            software=self.software,
            cve_id="CVE-2026-50003",
            severity="critical",
            status="fixed",
            name="Fixed finding",
            first_seen=t1 - timedelta(days=2),
            last_seen=t1 + timedelta(minutes=5),
        )
        fixed_event = VulnerabilityAuditEvent.objects.create(
            vulnerability=fixed_vuln,
            action="status_changed",
            actor="test",
            details={"from_status": "open", "to_status": "fixed"},
        )
        VulnerabilityAuditEvent.objects.filter(pk=fixed_event.pk).update(
            created_at=t2 + timedelta(minutes=4)
        )

        response = self.client.get(reverse("scan_diff", args=[newer.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["summary"]["new_count"], 1)
        self.assertEqual(response.context["summary"]["reopened_count"], 1)
        self.assertEqual(response.context["summary"]["fixed_count"], 1)
        self.assertEqual(response.context["new_findings"].first().pk, new_vuln.pk)


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class EmailReportingAndPasswordResetTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="staff-mail", email="staff@example.com", password="pw12345", is_staff=True
        )
        self.user = User.objects.create_user(
            username="user-mail", email="user@example.com", password="pw12345"
        )
        Extension.objects.create(name_id="email_reporting", is_active=True)
        settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)
        settings_obj.email_report_recipients = "secops@example.com, soc@example.com"
        settings_obj.save(update_fields=["email_report_recipients"])

    def test_login_page_contains_password_reset_link(self):
        response = self.client.get(reverse("login"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("password_reset"))

    def test_staff_can_save_email_reporting_recipients(self):
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse("save_email_reporting_config"),
            {"email_report_recipients": "team@example.com"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("extensions"))
        self.assertEqual(SystemSettings.objects.get(pk=1).email_report_recipients, "team@example.com")

    def test_non_staff_cannot_send_email_report(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("send_email_report_now"))
        self.assertEqual(response.status_code, 403)

    @patch("vuln_manager.views._render_dashboard_pdf_buffer")
    def test_staff_can_send_email_report(self, render_pdf_mock):
        from django.core import mail

        render_pdf_mock.return_value = io.BytesIO(b"%PDF-1.4 fake")
        self.client.force_login(self.staff)
        response = self.client.post(reverse("send_email_report_now"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("extensions"))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["secops@example.com", "soc@example.com"])

    def test_password_reset_form_is_reachable(self):
        response = self.client.get(reverse("password_reset"))
        self.assertEqual(response.status_code, 200)


class AITriageModuleConfigTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="triage-admin",
            email="triage-admin@example.com",
            password="pw12345",
            is_staff=True,
        )
        self.user = User.objects.create_user(
            username="triage-user",
            email="triage-user@example.com",
            password="pw12345",
        )
        self.scan = Scan.objects.create(scan_type="MANUAL")
        self.vuln = Vulnerability.objects.create(
            scan=self.scan,
            cve_id="CVE-2026-88888",
            severity="high",
            status="open",
            name="AI Triage test vuln",
        )
        Extension.objects.create(name_id="ai_triage", is_active=False)

    def test_staff_can_save_ai_triage_provider_config(self):
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse("save_ai_triage_config"),
            {
                "ai_triage_provider": "azure",
                "ai_openrouter_model": "deepseek/deepseek-v4-flash",
                "ai_azure_endpoint": "https://example-resource.inference.ai.azure.com",
                "ai_azure_model": "gpt-4o-mini",
                "ai_azure_api_version": "2024-06-01",
                "ai_azure_api_key": "azure-secret",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("extensions"))
        settings_obj = SystemSettings.objects.get(pk=1)
        self.assertEqual(settings_obj.ai_triage_provider, "azure")
        self.assertEqual(settings_obj.ai_azure_model, "gpt-4o-mini")
        self.assertEqual(settings_obj.ai_azure_api_version, "2024-06-01")
        self.assertEqual(
            settings_obj.ai_azure_endpoint, "https://example-resource.inference.ai.azure.com"
        )

    @patch("vuln_manager.views.threading.Thread")
    def test_single_triage_forbidden_when_module_disabled(self, thread_cls):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("triage_single_vulnerability", args=[self.vuln.pk])
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content.decode(), "ai_triage_disabled")
        thread_cls.assert_not_called()

    def test_bulk_triage_forbidden_when_module_disabled(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("do_triage"))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content.decode(), "ai_triage_disabled")

    def test_staff_can_save_ai_triage_with_empty_azure_api_version(self):
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse("save_ai_triage_config"),
            {
                "ai_triage_provider": "azure",
                "ai_openrouter_model": "deepseek/deepseek-v4-flash",
                "ai_azure_endpoint": "https://example-resource.inference.ai.azure.com",
                "ai_azure_model": "gpt-4o-mini",
                "ai_azure_api_version": "",
            },
        )
        self.assertEqual(response.status_code, 302)
        settings_obj = SystemSettings.objects.get(pk=1)
        self.assertEqual(settings_obj.ai_azure_api_version, "")
