from unittest.mock import ANY, call, patch
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from .models import AITriageJob, Extension, Host, Software
from .views import run_host_software_triage

class HostSoftwareTriageTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="host-analyst", password="test")
        self.client.force_login(self.user)
        self.host = Host.objects.create(ip_address="192.0.2.41")
        other_host = Host.objects.create(ip_address="192.0.2.42")
        self.first = Software.objects.create(name="First")
        self.second = Software.objects.create(name="Second")
        other = Software.objects.create(name="Other")
        self.first.hosts.add(self.host, other_host)
        self.second.hosts.add(self.host)
        other.hosts.add(other_host)
        self.extension = Extension.objects.create(name_id="ai_triage", is_active=True)
        self.url = reverse("triage_host_software", args=[self.host.pk])

    @patch("vuln_manager.views.threading.Thread")
    def test_starts_background_job_for_all_host_software(self, thread):
        response = self.client.post(self.url, {"inv_q": "First"})
        self.assertRedirects(response, reverse("host_detail", args=[self.host.pk]) + "?tab=inventory")
        self.assertEqual(thread.call_args.kwargs["target"], run_host_software_triage)
        job = AITriageJob.objects.get()
        self.assertEqual(thread.call_args.kwargs["args"], (job.pk, [self.first.pk, self.second.pk]))
        self.assertEqual(job.total, 2)
        self.assertTrue(thread.call_args.kwargs["daemon"])
        thread.return_value.start.assert_called_once()

    @patch("vuln_manager.views.ai_triage.triage_software")
    def test_worker_continues_after_a_failure(self, triage):
        triage.side_effect = [RuntimeError("provider failure"), None]
        job = AITriageJob.objects.create(host=self.host, host_label=str(self.host), total=3)
        with self.assertLogs("vuln_manager.views", level="ERROR"):
            run_host_software_triage(job.pk, [self.first.pk, self.second.pk, self.second.pk + 1000])
        job.refresh_from_db()
        self.assertEqual((job.status, job.processed, job.succeeded, job.failed), ("partial", 3, 1, 2))
        self.assertEqual(job.progress_percent, 100)
        self.assertIsNotNone(job.finished_at)
        self.assertEqual(triage.call_args_list, [call(self.first, should_cancel=ANY), call(self.second, should_cancel=ANY)])

    @patch("vuln_manager.views.threading.Thread")
    def test_disabled_or_empty_inventory_does_not_start_job(self, thread):
        self.extension.is_active = False
        self.extension.save()
        self.assertEqual(self.client.post(self.url).status_code, 403)
        thread.assert_not_called()
        self.extension.is_active = True
        self.extension.save()
        self.host.software_inventory.clear()
        response = self.client.post(self.url, follow=True)
        self.assertContains(response, "No software is assigned to this host.")
        thread.assert_not_called()

    def test_auth_method_and_inventory_button(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)
        response = self.client.get(reverse("host_detail", args=[self.host.pk]), {"tab": "inventory", "inv_q": "First"})
        self.assertContains(response, "Triage all host software")
        self.assertContains(response, "all 2 components")
        self.client.logout()
        self.assertEqual(self.client.post(self.url).status_code, 302)

    @patch("vuln_manager.views.ai_triage.triage_software")
    def test_completed_job_is_visible_on_dashboard_and_status_endpoint(self, triage):
        job = AITriageJob.objects.create(host=self.host, host_label="web-server", total=2)
        run_host_software_triage(job.pk, [self.first.pk, self.second.pk])
        job.refresh_from_db()
        self.assertEqual((job.status, job.processed, job.succeeded, job.failed), ("completed", 2, 2, 0))
        self.assertIsNotNone(job.finished_at)
        for url in (reverse("ai_dashboard"), reverse("ai_triage_jobs")):
            response = self.client.get(url)
            self.assertContains(response, "web-server")
            self.assertContains(response, "Completed")
            self.assertContains(response, "2 successful")

    def test_status_endpoint_requires_login(self):
        self.client.logout()
        self.assertEqual(self.client.get(reverse("ai_triage_jobs")).status_code, 302)

    @patch("vuln_manager.views.threading.Thread")
    def test_resume_skips_successes_and_retries_other_components(self, thread):
        from django.utils import timezone
        job = AITriageJob.objects.create(host=self.host, host_label="test", status="interrupted", total=2, processed=1, succeeded=1, software_ids=[self.first.pk, self.second.pk], completed_software_ids=[self.first.pk], finished_at=timezone.now())
        response = self.client.post(reverse("resume_triage_job", args=[job.pk]))
        self.assertRedirects(response, reverse("ai_dashboard"))
        continuation = AITriageJob.objects.exclude(pk=job.pk).get()
        self.assertEqual(continuation.software_ids, [self.second.pk])
        self.assertEqual(thread.call_args.kwargs["args"], (continuation.pk, [self.second.pk]))
        self.assertEqual(self.client.post(reverse("resume_triage_job", args=[job.pk])).status_code, 409)

    @patch("vuln_manager.views.threading.Thread")
    def test_resume_legacy_job_uses_completed_software_timestamp(self, thread):
        from datetime import timedelta
        from django.utils import timezone
        started = timezone.now() - timedelta(hours=1)
        finished = timezone.now()
        Software.objects.filter(pk=self.first.pk).update(ai_triage_time=started + timedelta(minutes=5))
        job = AITriageJob.objects.create(host=self.host, host_label="legacy", status="interrupted", started_at=started, finished_at=finished)
        self.assertContains(self.client.get(reverse("ai_dashboard")), "Older run")
        self.client.post(reverse("resume_triage_job", args=[job.pk]))
        continuation = AITriageJob.objects.exclude(pk=job.pk).get()
        self.assertEqual(continuation.software_ids, [self.second.pk])

    def test_dismiss_finished_only_and_preserve_job(self):
        job = AITriageJob.objects.create(host=self.host, host_label="finished", status="completed")
        running = AITriageJob.objects.create(host=self.host, host_label="running")
        self.assertEqual(self.client.post(reverse("dismiss_triage_job", args=[running.pk])).status_code, 409)
        self.assertRedirects(self.client.post(reverse("dismiss_triage_job", args=[job.pk])), reverse("ai_dashboard"))
        job.refresh_from_db()
        self.assertTrue(job.dismissed)
        self.assertNotContains(self.client.get(reverse("ai_triage_jobs")), "finished")

    @patch("vuln_manager.views.ai_triage.triage_software")
    def test_successful_components_are_recorded(self, triage):
        job = AITriageJob.objects.create(host=self.host, host_label="test", software_ids=[self.first.pk, self.second.pk])
        run_host_software_triage(job.pk, [self.first.pk, self.second.pk])
        job.refresh_from_db()
        self.assertEqual(job.completed_software_ids, [self.first.pk, self.second.pk])

    @patch("vuln_manager.utils.ai_triage.triage")
    def test_software_triage_stops_between_findings(self, triage):
        from .models import Scan, Vulnerability
        from .utils.ai_triage import triage_software
        scan = Scan.objects.create(scan_type="MANUAL")
        for cve in ("CVE-2026-2001", "CVE-2026-2002"):
            Vulnerability.objects.create(scan=scan, software=self.first, cve_id=cve, name="test", severity="high")
        stopped = {"value": False}
        def cancel(*args, **kwargs):
            stopped["value"] = True
        triage.side_effect = cancel
        triage_software(self.first, should_cancel=lambda: stopped["value"])
        self.assertEqual(triage.call_count, 1)
        self.first.refresh_from_db()
        self.assertIsNone(self.first.ai_triage_time)
