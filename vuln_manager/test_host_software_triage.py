from unittest.mock import call, patch
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
        self.assertEqual(triage.call_args_list, [call(self.first), call(self.second)])

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
