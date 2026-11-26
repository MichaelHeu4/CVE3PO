from datetime import timedelta
from unittest.mock import patch
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from .models import AITriageJob, Extension, Host, Scan, Vulnerability
from .views import run_triage_background

class FindingTriageProgressTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="triage-progress")
        self.client.force_login(self.user)
        Extension.objects.create(name_id="ai_triage", is_active=True)
        self.host = Host.objects.create(ip_address="192.0.2.50", criticality="High")
        self.scan = Scan.objects.create(scan_type="MANUAL")

    def finding(self, **kwargs):
        data = dict(scan=self.scan, host=self.host, name="Finding", cve_id="CVE-2026-5000", severity="high")
        data.update(kwargs)
        return Vulnerability.objects.create(**data)

    @patch("vuln_manager.views.threading.Thread")
    def test_general_triage_creates_tracked_run(self, thread):
        response = self.client.post(reverse("do_triage"))
        self.assertRedirects(response, reverse("ai_dashboard"))
        job = AITriageJob.objects.get()
        self.assertEqual(job.kind, "findings")
        self.assertIsNotNone(job.heartbeat_at)
        self.assertEqual(thread.call_args.kwargs["args"], (job.pk,))
        thread.return_value.start.assert_called_once()

    @patch("vuln_manager.views.ai_triage.triage")
    def test_general_run_counts_and_continues_after_failure(self, triage):
        first = self.finding()
        second = self.finding(ai_result="Act", ai_last_criticality="Low")
        self.finding(ai_result="Track", ai_last_criticality="High")
        self.finding(status="fixed")
        job = AITriageJob.objects.create(kind="findings", host_label="General finding triage", heartbeat_at=timezone.now())
        triage.side_effect = [RuntimeError("error"), None]
        with self.assertLogs("vuln_manager.views", level="ERROR"):
            run_triage_background(job.pk)
        job.refresh_from_db()
        self.assertEqual((job.status, job.total, job.processed, job.succeeded, job.failed), ("partial", 2, 2, 1, 1))
        self.assertEqual([x.args[0].pk for x in triage.call_args_list], [first.pk, second.pk])
        self.assertContains(self.client.get(reverse("ai_dashboard")), "Completed with errors")

    def test_stale_runs_interrupted_but_recent_run_unaffected(self):
        old = timezone.now() - timedelta(minutes=3)
        recent = timezone.now()
        a = AITriageJob.objects.create(kind="findings", host_label="old finding", heartbeat_at=old, started_at=old, total=5, processed=2)
        b = AITriageJob.objects.create(kind="software", host_label="old host", heartbeat_at=old, started_at=old)
        c = AITriageJob.objects.create(kind="software", host_label="active host", heartbeat_at=recent, started_at=old)
        response = self.client.get(reverse("ai_triage_jobs"))
        for job in (a,b,c): job.refresh_from_db()
        self.assertEqual((a.status,b.status,c.status), ("interrupted", "interrupted", "running"))
        self.assertEqual(a.processed, 2)
        self.assertIsNotNone(a.finished_at)
        self.assertContains(response, "Interrupted")

    def test_empty_run_completes(self):
        job = AITriageJob.objects.create(kind="findings", host_label="empty", heartbeat_at=timezone.now())
        run_triage_background(job.pk)
        job.refresh_from_db()
        self.assertEqual((job.status, job.total, job.processed), ("completed", 0, 0))

    def test_dashboard_renders_special_characters_correctly(self):
        from .models import SystemSettings
        settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)
        settings_obj.ai_triage_provider = "azure"
        settings_obj.ai_azure_model = "example-model"
        settings_obj.save()
        self.finding(host=None)
        response = self.client.get(reverse("ai_dashboard"))
        self.assertContains(response, "Azure AI · example-model")
        self.assertContains(response, "—")
        self.assertNotContains(response, "Â·")
        self.assertNotContains(response, "â€")

    def test_cancel_running_job_and_show_cancelled_status(self):
        job = AITriageJob.objects.create(kind="findings", host_label="cancel me", heartbeat_at=timezone.now(), total=3)
        self.assertContains(self.client.get(reverse("ai_triage_jobs")), "Cancel cancel me run")
        self.assertEqual(self.client.get(reverse("cancel_triage_job", args=[job.pk])).status_code, 405)
        self.assertRedirects(self.client.post(reverse("cancel_triage_job", args=[job.pk])), reverse("ai_dashboard"))
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.assertIsNotNone(job.finished_at)
        self.assertContains(self.client.get(reverse("ai_triage_jobs")), "Cancelled")
        self.assertEqual(self.client.post(reverse("cancel_triage_job", args=[job.pk])).status_code, 409)

    @patch("vuln_manager.views.ai_triage.triage")
    def test_cancel_during_finding_stops_before_next_finding(self, triage):
        self.finding(cve_id="CVE-2026-5001")
        self.finding(cve_id="CVE-2026-5002")
        job = AITriageJob.objects.create(kind="findings", host_label="test", heartbeat_at=timezone.now())
        def cancel(*args, **kwargs):
            AITriageJob.objects.filter(pk=job.pk).update(status="cancelled", finished_at=timezone.now())
        triage.side_effect = cancel
        run_triage_background(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(triage.call_count, 1)

    def test_vulnerability_list_shows_outcome_and_pending_state(self):
        self.finding(cve_id="CVE-2026-5001", ai_result="Track*")
        self.finding(cve_id="CVE-2026-5002", ai_result="Act")
        self.finding(cve_id="CVE-2026-5003", ai_result="tbd")
        response = self.client.get(reverse("vuln_list"))
        for text in ("AI outcome", "Track*", "Act", "Not triaged"):
            self.assertContains(response, text)

    @patch("vuln_manager.utils.ai_triage.is_cisa_kev")
    @patch("vuln_manager.utils.ai_triage.get_epss_score")
    def test_cancel_between_external_requests_skips_following_requests(self, epss, kev):
        from .utils.ai_triage import triage
        stopped = {"value": False}
        def cancel_after_epss(*args):
            stopped["value"] = True
            return 0.1
        epss.side_effect = cancel_after_epss
        triage(self.finding(), should_cancel=lambda: stopped["value"])
        kev.assert_not_called()

    def test_cancel_requires_login(self):
        job = AITriageJob.objects.create(kind="findings", host_label="protected")
        self.client.logout()
        self.assertEqual(self.client.post(reverse("cancel_triage_job", args=[job.pk])).status_code, 302)
        job.refresh_from_db()
        self.assertEqual(job.status, "running")
