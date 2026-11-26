from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from pydantic import ValidationError

from .models import SystemSettings
from .utils.ai_triage import TriageErgebnis, SoftwareTriageErgebnis, _call_azure_ai, _call_openrouter


class TriageRequestTests(SimpleTestCase):
    def config(self, effort=""):
        return SimpleNamespace(
            ai_reasoning_effort=effort, ai_openrouter_api_key="key",
            ai_openrouter_model="example/model", ai_azure_endpoint="https://example.openai.azure.com",
            ai_azure_api_key="key", ai_azure_model="deployment", ai_azure_api_version="",
        )

    @patch("vuln_manager.utils.ai_triage.instructor.from_openai")
    @patch("vuln_manager.utils.ai_triage.OpenAI")
    def test_openrouter_sends_effort_only_when_selected(self, openai, instructor):
        create = instructor.return_value.chat.completions.create
        _call_openrouter([], self.config())
        self.assertNotIn("reasoning_effort", create.call_args.kwargs)
        _call_openrouter([], self.config("high"))
        self.assertEqual(create.call_args.kwargs["reasoning_effort"], "high")
        self.assertNotIn("temperature", create.call_args.kwargs)

    @patch("vuln_manager.utils.ai_triage.instructor.from_openai")
    @patch("vuln_manager.utils.ai_triage.AzureOpenAI")
    def test_azure_openai_sends_selected_effort(self, azure, instructor):
        _call_azure_ai([], self.config("medium"))
        kwargs = instructor.return_value.chat.completions.create.call_args.kwargs
        self.assertEqual(kwargs["reasoning_effort"], "medium")
        self.assertNotIn("temperature", kwargs)

    def test_azure_inference_rejects_explicit_effort(self):
        config = self.config("high")
        config.ai_azure_endpoint = "https://example.inference.ai.azure.com"
        with self.assertRaisesRegex(ValueError, "Azure AI Inference"):
            _call_azure_ai([], config)

    def test_schema_accepts_custom_scores_and_rejects_empty_fields(self):
        result = TriageErgebnis(gedankengang_analyst="Reason", ssvc_score="Custom", patching_vorschlag="Action")
        self.assertEqual(result.ssvc_score, "Custom")
        with self.assertRaises(ValidationError):
            TriageErgebnis(gedankengang_analyst="Reason", ssvc_score="  ", patching_vorschlag="Action")
        with self.assertRaises(ValidationError):
            SoftwareTriageErgebnis(gedankengang_analyst="Reason", cluster_1_score="Track", cluster_2_score="Track", cluster_3_score="Track", cluster_4_score="")


class ReasoningSettingsTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="reasoning-admin", password="test", is_staff=True)
        self.client.force_login(self.user)

    def test_save_and_display_effort_with_custom_prompts(self):
        response = self.client.post(reverse("save_ai_triage_config"), {
            "ai_reasoning_effort": "high", "ai_cve_system_prompt": "Custom CVE rules",
            "ai_software_system_prompt": "Custom software rules",
        })
        self.assertEqual(response.status_code, 302)
        settings = SystemSettings.objects.get(pk=1)
        self.assertEqual(settings.ai_reasoning_effort, "high")
        self.assertEqual(settings.ai_cve_system_prompt, "Custom CVE rules")
        self.assertEqual(settings.ai_software_system_prompt, "Custom software rules")
        self.assertContains(self.client.get(reverse("extensions")), 'value="high" selected')

    def test_invalid_effort_is_rejected_without_saving(self):
        response = self.client.post(reverse("save_ai_triage_config"), {"ai_reasoning_effort": "invalid"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(SystemSettings.objects.get(pk=1).ai_reasoning_effort, "")
