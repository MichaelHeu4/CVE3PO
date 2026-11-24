from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import Host, Scan, Software, Vulnerability


class OperationalDashboardTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="analyst", password="test")
        self.client.force_login(self.user)
        self.scan = Scan.objects.create(scan_type="MANUAL")
        self.host = Host.objects.create(ip_address="192.0.2.1", is_exposed=True, criticality="High")
        self.other = Host.objects.create(ip_address="192.0.2.2", is_exposed=True)
        self.software = Software.objects.create(name="Example")
        self.software.hosts.add(self.host, self.other)

    def finding(self, **kwargs):
        data = {"scan": self.scan, "name": "Test finding", "cve_id": "CVE-2026-1234", "severity": "critical"}
        data.update(kwargs)
        return Vulnerability.objects.create(**data)

    def test_work_counts_sort_and_filters_use_active_findings(self):
        pending = self.finding(ai_result="tbd")
        act = self.finding(ai_result="Act", due_date=timezone.localdate() - timedelta(days=1), assignee=self.user)
        self.finding(ai_result="Act", status="risk_accepted")
        self.finding(ai_result="Attend", status="verification")
        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["counts"]["act"], 1)
        self.assertEqual(response.context["counts"]["overdue"], 1)
        self.assertEqual(response.context["counts"]["verification"], 1)
        self.assertEqual(response.context["page"][0].pk, act.pk)
        response = self.client.get(reverse("dashboard"), {"filter": "pending"})
        self.assertEqual([v.pk for v in response.context["page"]], [pending.pk])
        self.assertContains(response, "AUSSTEHEND")

    def test_exposed_hosts_deduplicate_direct_and_software_findings(self):
        finding = self.finding(host=self.host, software=self.software, ai_result="Act")
        self.finding(host=self.host, status="fixed", ai_result="Act")
        response = self.client.get(reverse("dashboard"), {"view": "hosts"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["host_counts"]["act"], 2)
        hosts = {host.pk: host for host in response.context["page"]}
        self.assertEqual([v.pk for v in hosts[self.host.pk].dashboard_findings], [finding.pk])
        self.assertEqual([v.pk for v in hosts[self.other.pk].dashboard_findings], [finding.pk])
        self.assertContains(response, "Finding-Triage")

    def test_host_scope_and_search(self):
        self.finding(host=self.host, severity="high", ai_result="tbd")
        response = self.client.get(reverse("dashboard"), {"view": "hosts"})
        self.assertEqual([h.pk for h in response.context["page"]], [self.host.pk])
        response = self.client.get(reverse("dashboard"), {"view": "hosts", "scope": "all", "q": "192.0.2.2"})
        self.assertEqual([h.pk for h in response.context["page"]], [self.other.pk])

    def test_report_matches_dashboard_and_includes_all_exposed_host_findings(self):
        from .views import _build_dashboard_report_context

        act = self.finding(host=self.host, software=self.software, ai_result="Act", due_date=timezone.localdate() - timedelta(days=1))
        pending = self.finding(host=self.host, ai_result="tbd", severity="high")
        self.finding(host=self.host, ai_result="Act", status="risk_accepted")
        report = _build_dashboard_report_context()
        dashboard = self.client.get(reverse("dashboard"))
        hosts_dashboard = self.client.get(reverse("dashboard"), {"view": "hosts"})
        self.assertEqual(report["counts"], dashboard.context["counts"])
        self.assertEqual(report["host_counts"], hosts_dashboard.context["host_counts"])
        self.assertEqual([v.pk for v in report["findings"]], [act.pk, pending.pk])
        hosts = {h.pk: h for h in report["attention_hosts"]}
        self.assertEqual({v.pk for v in hosts[self.host.pk].dashboard_findings}, {act.pk, pending.pk})
        self.assertEqual([v.pk for v in hosts[self.other.pk].dashboard_findings], [act.pk])
        response = self.client.get(reverse("export_dashboard_pdf"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b"".join(response.streaming_content).startswith(b"%PDF"))
