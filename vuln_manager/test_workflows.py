from datetime import timedelta
from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.core import mail
from django.urls import reverse
from django.utils import timezone
from vuln_manager.models import CisaKevEntry, EpssEntry, Host, Scan, Software, SystemSettings, Vulnerability, VulnerabilityObservation
from vuln_manager.utils.reminders import run_reminders
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability
from vuln_manager.utils.scheduler import reopen_expired_exceptions


class WorkflowTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="worker", password="pass")
        self.client.force_login(self.user)
        self.host = Host.objects.create(ip_address="192.0.2.7")
        self.scan = Scan.objects.create(scan_type="OPENVAS")
        self.args = dict(scan=self.scan, host=self.host, cve_id="CVE-2025-12345", severity="critical", name="test")
        self.vuln = create_or_update_vulnerability(**self.args)

    def test_assignment_and_filtered_work_list(self):
        response = self.client.post(reverse("update_vulnerability_work", args=[self.vuln.pk]), {"assignee": self.user.pk, "owner_team": "Ops", "due_date": "2020-01-01", "remediation_notes": "Upgrade", "fixed_version": "2.0"})
        self.assertEqual(response.status_code, 302)
        response = self.client.get(reverse("vuln_list"), {"work": "overdue"})
        self.assertContains(response, "CVE-2025-12345")
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.owner_team, "Ops")

    def test_exception_survives_rediscovery_and_expires(self):
        expiry = timezone.localdate() + timedelta(days=2)
        response = self.client.post(reverse("update_vuln_status", args=[self.vuln.pk]), {"status": "risk_accepted", "status_reason": "isolated", "exception_expires": expiry.isoformat()})
        self.assertEqual(response.status_code, 302)
        create_or_update_vulnerability(**self.args)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "risk_accepted")
        self.assertEqual(VulnerabilityObservation.objects.get(vulnerability=self.vuln).detection_count, 2)
        self.vuln.exception_expires = timezone.localdate() - timedelta(days=1)
        self.vuln.save(update_fields=["exception_expires"])
        reopen_expired_exceptions()
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")

    def test_detail_shows_threat_intelligence_and_coverage_renders(self):
        CisaKevEntry.objects.create(cve_id=self.vuln.cve_id)
        EpssEntry.objects.create(cve_id=self.vuln.cve_id, score=0.42, percentile=0.9)
        response = self.client.get(reverse("vuln_detail", args=[self.vuln.pk]))
        self.assertContains(response, "Listed")
        self.assertContains(response, "0.4200")
        self.assertEqual(self.client.get(reverse("coverage")).status_code, 200)

    def test_verification_is_reopened_on_redetection(self):
        self.vuln.status = "verification"
        self.vuln.save(update_fields=["status"])
        create_or_update_vulnerability(**self.args)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_reminders_are_opt_in_and_sent_once_per_day(self):
        self.user.email = "worker@example.com"
        self.user.save(update_fields=["email"])
        self.vuln.assignee = self.user
        self.vuln.due_date = timezone.localdate() - timedelta(days=8)
        self.vuln.save(update_fields=["assignee", "due_date"])
        settings, _ = SystemSettings.objects.get_or_create(pk=1)
        settings.reminders_enabled = True
        settings.escalation_recipients = "lead@example.com"
        settings.save()
        run_reminders()
        run_reminders()
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual({m.to[0] for m in mail.outbox}, {"worker@example.com", "lead@example.com"})

    def test_cross_source_correlation_keeps_observations_and_fingerprints(self):
        software = Software.objects.create(name="Example", version="1")
        first = create_or_update_vulnerability(scan=self.scan, host=self.host, software=software, cve_id="CVE-2025-99999", severity="critical", name="first")
        other_scan = Scan.objects.create(scan_type="NUCLEI")
        second = create_or_update_vulnerability(scan=other_scan, host=self.host, software=software, cve_id="CVE-2025-99999", severity="low", name="second")
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(second.severity, "critical")
        self.assertEqual(second.observations.count(), 2)
        again = create_or_update_vulnerability(scan=self.scan, host=self.host, software=software, cve_id="CVE-2025-99999", severity="critical", name="first")
        self.assertEqual(again.pk, first.pk)
        self.assertEqual(again.observations.get(source="OPENVAS").detection_count, 2)

    def test_manual_merge_refuses_conflicts_and_preserves_sources(self):
        other_scan = Scan.objects.create(scan_type="NUCLEI")
        other = create_or_update_vulnerability(scan=other_scan, host=self.host, cve_id=self.vuln.cve_id, severity="high", name="other")
        self.assertNotEqual(other.pk, self.vuln.pk)
        other.status = "fixed"
        other.save(update_fields=["status"])
        url = reverse("merge_vulnerabilities", args=[self.vuln.pk, other.pk])
        self.assertEqual(self.client.post(url).status_code, 400)
        other.status = "open"
        other.due_date = self.vuln.due_date
        other.save(update_fields=["status", "due_date"])
        self.assertEqual(self.client.post(url).status_code, 302)
        self.assertFalse(Vulnerability.objects.filter(pk=other.pk).exists())
        self.assertEqual(self.vuln.observations.count(), 2)
        result = create_or_update_vulnerability(scan=other_scan, host=self.host, cve_id=self.vuln.cve_id, severity="high", name="other")
        self.assertEqual(result.pk, self.vuln.pk)

    def test_verification_requires_explicit_evidence_to_close(self):
        self.vuln.status = "verification"
        self.vuln.save(update_fields=["status"])
        url = reverse("update_vuln_status", args=[self.vuln.pk])
        self.assertEqual(self.client.post(url, {"status": "fixed"}).status_code, 400)
        self.assertEqual(self.client.post(url, {"status": "fixed", "status_reason": "Rescan confirms patch"}).status_code, 302)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "fixed")
        self.assertEqual(self.vuln.verification_notes, "Rescan confirms patch")

    def test_deleting_scan_preserves_correlated_finding(self):
        software = Software.objects.create(name="Example", version="1")
        first = create_or_update_vulnerability(scan=self.scan, host=self.host, software=software, cve_id="CVE-2025-99998", severity="high", name="first")
        second_scan = Scan.objects.create(scan_type="NUCLEI")
        create_or_update_vulnerability(scan=second_scan, host=self.host, software=software, cve_id="CVE-2025-99998", severity="high", name="second")
        self.assertEqual(self.client.post(reverse("delete_scan", args=[second_scan.pk])).status_code, 302)
        first.refresh_from_db()
        self.assertEqual(first.scan_id, self.scan.pk)
        self.assertEqual(first.observations.count(), 2)
