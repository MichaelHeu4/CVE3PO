from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from vuln_manager.models import CTIFeed, CTIItem, ContextAssessment, Extension, Host, Scan, SystemSettings, Vulnerability, WazuhContextSnapshot
from vuln_manager.utils.context_assessment import ContextProposal, collect_sources, generate_proposal
from vuln_manager.utils.wazuh_context import fetch_wazuh_context


class ContextAssessmentTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(ip_address="192.0.2.1")
        self.other_host = Host.objects.create(ip_address="192.0.2.2")
        scan = Scan.objects.create(scan_type="OSV")
        self.vuln = Vulnerability.objects.create(scan=scan, host=self.host, cve_id="CVE-2025-1234", severity="high", name="Test")
        self.user = User.objects.create_user(username="analyst", password="test", is_staff=True)
        self.client.force_login(self.user)

    def test_sources_require_explicit_cve_or_link(self):
        feed = CTIFeed.objects.create(name="test", url="https://example.org/feed")
        CTIItem.objects.create(source=feed, external_id="1", title="Match", url="https://example.org/1", cves=["cve-2025-1234"])
        CTIItem.objects.create(source=feed, external_id="2", title="Unrelated", url="https://example.org/2", cves=["CVE-2025-12345"])
        self.assertEqual([s["title"] for s in collect_sources(self.vuln)], ["CVE-2025-1234", "Match"])

    def test_finding_page_shows_pilot(self):
        response = self.client.get(reverse("vuln_detail", args=[self.vuln.pk]))
        self.assertContains(response, "CVE context pilot")
        self.assertContains(response, "require explicit approval")

    @patch("vuln_manager.utils.ai_triage._call_openrouter")
    def test_generated_plan_must_reference_supplied_sources(self, call):
        Extension.objects.create(name_id="ai_triage", is_active=True)
        SystemSettings.objects.create(pk=1, ai_triage_provider="openrouter")
        call.return_value = ContextProposal(prerequisite="test", source_ids=["invented"], query="",
                                            positive_evidence="unknown", negative_evidence="unknown", limitations="unknown")
        with self.assertRaises(ValueError):
            generate_proposal(self.vuln, self.host)
        call.return_value.source_ids = ["finding"]
        sources, proposal, provider, model = generate_proposal(self.vuln, self.host)
        self.assertEqual(proposal["source_ids"], ["finding"])
        self.assertEqual(provider, "openrouter")

    @patch("vuln_manager.utils.ai_triage._call_openrouter")
    def test_partial_context_evidence_is_requested(self, call):
        Extension.objects.create(name_id="ai_triage", is_active=True)
        SystemSettings.objects.create(pk=1, ai_triage_provider="openrouter")
        call.return_value = ContextProposal(prerequisite="mod_ssl configuration", source_ids=["finding"],
            query="SELECT pid, path FROM process_memory_map WHERE path LIKE '%mod_ssl%' LIMIT 100",
            positive_evidence="Module observed", negative_evidence="Unknown",
            limitations="Partial check; cannot determine applicability")
        _, proposal, _, _ = generate_proposal(self.vuln, self.host)
        from context_agent.policy import validate_query
        self.assertEqual(validate_query(proposal["query"]), proposal["query"])
        self.assertIn("only a partial check", call.call_args.args[0][0]["content"])

    @patch("vuln_manager.context_views.generate_proposal")
    def test_proposal_is_scoped_to_host_and_does_not_change_finding(self, generate):
        generate.return_value = ([], {"prerequisite": "test"}, "openrouter", "model")
        url = reverse("prepare_context", args=[self.vuln.pk])
        self.client.post(url, {"host_id": self.other_host.pk})
        generate.assert_not_called()
        self.client.post(url, {"host_id": self.host.pk})
        self.assertEqual(ContextAssessment.objects.count(), 1)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.status, "open")
        self.assertEqual(self.vuln.ai_result, "tbd")

    @patch("vuln_manager.context_views.generate_proposal")
    def test_non_staff_cannot_generate_proposal(self, generate):
        self.user.is_staff = False
        self.user.save()
        self.client.post(reverse("prepare_context", args=[self.vuln.pk]), {"host_id": self.host.pk})
        generate.assert_not_called()
        self.assertFalse(ContextAssessment.objects.exists())

class WazuhContextTests(TestCase):
    @patch.dict("os.environ", {"WAZUH_CONTEXT_API_URL": "https://wazuh.example:55000", "WAZUH_CONTEXT_API_USER": "user", "WAZUH_CONTEXT_API_PASSWORD": "secret"})
    @patch("vuln_manager.utils.wazuh_context.requests.Session")
    def test_fetch_filters_sensitive_fields_and_rejects_partial_results(self, session_class):
        session = session_class.return_value.__enter__.return_value
        auth = Mock(status_code=200)
        auth.json.return_value = {"data": {"token": "token"}}
        ports = Mock(status_code=200)
        ports.json.return_value = {"error": 0, "data": {"total_affected_items": 1, "affected_items": [{"pid": 42, "process": "apache", "scan": {"time": "now"}}]}}
        processes = Mock(status_code=200)
        processes.json.return_value = {"error": 0, "data": {"total_affected_items": 1, "affected_items": [{"pid": 42, "name": "apache", "argvs": "secret"}]}}
        session.get.side_effect = [auth, ports, processes]
        result = fetch_wazuh_context("001")
        self.assertEqual(result[1], [{"pid": 42, "name": "apache"}])
        self.assertFalse(any(call.kwargs.get("allow_redirects") for call in session.get.call_args_list))
        ports.json.return_value["data"]["total_failed_items"] = 1
        session.get.side_effect = [auth, ports]
        with self.assertRaises(ValueError):
            fetch_wazuh_context("001")
