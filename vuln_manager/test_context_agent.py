import hashlib
import json
import sys
import os
import subprocess
import unittest
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from context_agent.policy import validate_query
from context_agent import agent as context_client
from vuln_manager.models import ContextAgent, ContextAssessment, ContextJob, Host, Scan, Vulnerability


class QueryPolicyTests(TestCase):
    def test_policy_is_narrow_and_rejects_injection(self):
        self.assertEqual(validate_query("SELECT pid, name FROM processes WHERE name = 'apache2' LIMIT 10"),
                         "SELECT pid, name FROM processes WHERE name = 'apache2' LIMIT 10")
        for query in ["select * from processes limit 10", "select cmdline from processes limit 10",
                      "select pid from processes; drop table processes", "select pid from processes limit 999",
                      "select pid from processes where name = 'x' OR 1=1 limit 1",
                      "select pid from processes join users on 1=1 limit 1"]:
            with self.subTest(query=query), self.assertRaises(ValueError):
                validate_query(query)

    def test_expanded_policy_supports_constrained_configuration_and_runtime_queries(self):
        for query in ["SELECT id, active_state FROM systemd_units WHERE id LIKE 'apache%' LIMIT 20",
                      "SELECT pid, path FROM process_memory_map WHERE path LIKE '%libssl%' AND pid > 0 LIMIT 20",
                      "SELECT name, current_value FROM system_controls WHERE name = 'net.ipv4.ip_forward' LIMIT 1",
                      "SELECT path, mode FROM file WHERE path = '/etc/apache2/apache2.conf' LIMIT 1",
                      r"SELECT name, data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' LIMIT 10"]:
            with self.subTest(query=query):
                self.assertEqual(validate_query(query), query)
        for query in ["SELECT name, current_value FROM system_controls LIMIT 10",
                      "SELECT path FROM file WHERE path LIKE '/etc/%' LIMIT 10",
                      r"SELECT data FROM registry WHERE key = 'HKEY_LOCAL_MACHINE\SAM' LIMIT 10",
                      "SELECT pid FROM processes WHERE name = 'x' OR 1=1 LIMIT 10"]:
            with self.subTest(query=query), self.assertRaises(ValueError):
                validate_query(query)

    def test_agent_executes_without_shell_and_inventory_is_dry_run(self):
        self.assertEqual(context_client.run_limited([sys.executable, "-c", "import json; print(json.dumps([{'pid': 1}]))"]), [{"pid": 1}])
        with patch("context_agent.agent.run_limited", return_value={"software": []}) as run:
            result = context_client.execute({"kind": "inventory"}, {"legacy_agent_path": sys.executable})
        self.assertEqual(result["status"], "success")
        self.assertEqual(run.call_args.kwargs.get("timeout"), 120)
        self.assertEqual(run.call_args.args[1]["DRY_RUN"], "true")

    def test_agent_revalidates_query(self):
        with patch("context_agent.agent.run_limited") as run:
            result = context_client.execute({"kind": "query", "query": "select * from processes limit 1"}, {"osquery_path": "unused"})
        self.assertEqual(result["status"], "error")
        run.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows affinity API")
    def test_windows_affinity_is_inherited_by_child(self):
        code = r'''
import ctypes, json, subprocess, sys
from context_agent.agent import apply_windows_affinity
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.GetCurrentProcess.restype = ctypes.c_void_p
k.GetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
p, s = ctypes.c_size_t(), ctypes.c_size_t()
assert k.GetProcessAffinityMask(k.GetCurrentProcess(), ctypes.byref(p), ctypes.byref(s))
cpus = [i for i in range(8, 64) if p.value & (1 << i)]
if not cpus:
    print("SKIP")
    raise SystemExit(0)
cpu = cpus[0]
apply_windows_affinity([cpu])
assert k.GetProcessAffinityMask(k.GetCurrentProcess(), ctypes.byref(p), ctypes.byref(s))
assert p.value == 1 << cpu
child = "import ctypes; k=ctypes.WinDLL('kernel32'); k.GetCurrentProcess.restype=ctypes.c_void_p; k.GetProcessAffinityMask.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.POINTER(ctypes.c_size_t)]; p=ctypes.c_size_t(); s=ctypes.c_size_t(); assert k.GetProcessAffinityMask(k.GetCurrentProcess(),ctypes.byref(p),ctypes.byref(s)); print(p.value)"
assert int(subprocess.check_output([sys.executable, "-c", child])) == 1 << cpu
print("OK")
'''
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        if "SKIP" in result.stdout:
            self.skipTest("No available CPU beyond the first eight")
        self.assertIn("OK", result.stdout)


class ContextAgentProtocolTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(ip_address="192.0.2.11")
        self.agent = ContextAgent.objects.create(host=self.host, token_hash=hashlib.sha256(b"secret").hexdigest(), last_inventory_requested=timezone.now())
        self.other = ContextAgent.objects.create(host=Host.objects.create(ip_address="192.0.2.12"), token_hash=hashlib.sha256(b"other").hexdigest(), last_inventory_requested=timezone.now())
        self.user = User.objects.create_user("reviewer", is_staff=True)
        scan = Scan.objects.create(scan_type="OSV")
        self.vulnerability = Vulnerability.objects.create(scan=scan, host=self.host, cve_id="CVE-2025-1234", severity="high", name="test")
        self.assessment = ContextAssessment.objects.create(vulnerability=self.vulnerability, host=self.host, provider="test", proposal={"query": "SELECT pid, name FROM processes WHERE name = 'apache2' LIMIT 10"})

    def post_agent(self, url, token, data):
        return self.client.post(url, data=json.dumps(data), content_type="application/json", HTTP_AUTHORIZATION="Bearer " + token)

    def test_approval_claim_and_one_time_result_are_scoped_to_host(self):
        self.client.force_login(self.user)
        self.client.post(reverse("approve_context", args=[self.vulnerability.pk, self.assessment.pk]))
        job = ContextJob.objects.get(kind="query")
        poll = reverse("context_agent_poll")
        self.assertEqual(self.post_agent(poll, "bad", {}).status_code, 401)
        self.assertIsNone(self.post_agent(poll, "other", {}).json()["job"])
        claim = self.post_agent(poll, "secret", {}).json()["job"]
        self.assertEqual(claim["id"], job.pk)
        submit = reverse("context_agent_submit", args=[job.pk])
        result = {"lease": claim["lease"], "result": {"status": "success", "rows": []}}
        self.assertEqual(self.post_agent(submit, "other", result).status_code, 409)
        self.assertEqual(self.post_agent(submit, "secret", result).status_code, 200)
        self.assertEqual(self.post_agent(submit, "secret", result).status_code, 409)
        job.refresh_from_db()
        self.assertEqual(job.verdict, "not_determined")
        self.vulnerability.refresh_from_db()
        self.assertEqual(self.vulnerability.status, "open")
        self.assertEqual(self.vulnerability.ai_result, "tbd")

    def test_hourly_inventory_is_separate_and_expired_lease_cannot_submit(self):
        self.agent.last_inventory_requested = None
        self.agent.save()
        claim = self.post_agent(reverse("context_agent_poll"), "secret", {}).json()["job"]
        self.assertEqual(claim["kind"], "inventory")
        job = ContextJob.objects.get(pk=claim["id"])
        job.claimed_at = timezone.now() - timedelta(minutes=6)
        job.save()
        url = reverse("context_agent_submit", args=[job.pk])
        self.assertEqual(self.post_agent(url, "secret", {"lease": claim["lease"], "result": {"status": "success"}}).status_code, 409)

    def test_unapproved_and_unsafe_queries_cannot_be_queued(self):
        self.client.force_login(self.user)
        self.assessment.proposal = {"query": "SELECT * FROM processes LIMIT 10"}
        self.assessment.save()
        self.client.post(reverse("approve_context", args=[self.vulnerability.pk, self.assessment.pk]))
        self.assertFalse(ContextJob.objects.filter(kind="query").exists())

    def test_pilot_package_is_separate_and_restricted(self):
        response = self.client.get(reverse("download_context_agent"))
        self.assertEqual(response.status_code, 302)
        self.client.force_login(self.user)
        response = self.client.get(reverse("download_context_agent"))
        self.assertEqual(response.status_code, 200)
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            names = archive.namelist()
        self.assertIn("cve3po-context-agent/agent.py", names)
        self.assertIn("cve3po-context-agent/apache_check.py", names)
        self.assertTrue(all(name.startswith("cve3po-context-agent/") for name in names))

    def test_changed_target_makes_review_stale(self):
        job = ContextJob.objects.create(agent=self.agent, assessment=self.assessment, kind="query", status="completed",
                                        completed_at=timezone.now(), expires_at=timezone.now()+timedelta(hours=1), target_os="Linux")
        self.assertTrue(job.is_stale)
