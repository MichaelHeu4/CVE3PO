import os
import tempfile
import posixpath
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase
from django.contrib.auth.models import User
from django.urls import reverse

from context_agent.apache_check import collect
from context_agent.policy import validate_local_query, validate_query
from vuln_manager.models import ContextAgent, ContextAssessment, ContextJob, Host, Scan, Vulnerability


class ApacheCollectionTests(SimpleTestCase):
    def test_general_augeas_queries_require_exact_path_label_and_local_permission(self):
        query = "SELECT node, label, value FROM augeas WHERE path = '/etc/ssh/sshd_config' AND label = 'PermitRootLogin' LIMIT 100"
        self.assertEqual(validate_query(query), query)
        with patch("context_agent.policy.os.path", posixpath):
            self.assertEqual(validate_local_query(query, {"augeas_allowed_roots": ["/etc/ssh"], "augeas_allowed_labels": ["PermitRootLogin"]}), query)
            with self.assertRaises(ValueError):
                validate_local_query(query, {"augeas_allowed_roots": ["/etc/apache2"], "augeas_allowed_labels": ["PermitRootLogin"]})
            with self.assertRaises(ValueError):
                validate_local_query(query, {"augeas_allowed_roots": ["/etc/ssh"], "augeas_allowed_labels": ["OtherLabel"]})
        for unsafe in ["SELECT value FROM augeas LIMIT 10", "SELECT value FROM augeas WHERE path = '/etc/ssh/sshd_config' LIMIT 10",
                       "SELECT value FROM augeas WHERE path LIKE '/etc/%' AND label = 'secret' LIMIT 10"]:
            with self.assertRaises(ValueError):
                validate_query(unsafe)

    def test_includes_virtualhosts_and_sensitive_directives_are_filtered(self):
        with tempfile.TemporaryDirectory() as root:
            main, child = os.path.join(root, "httpd.conf"), os.path.join(root, "vhost.conf")
            for path in (main, child):
                with open(path, "w") as handle:
                    handle.write("fixture")
            def run(args, timeout):
                if "httpd.conf" in args[-1]:
                    return [{"node": "/files/main/VirtualHost", "label": "VirtualHost", "value": ""},
                            {"node": "/files/main/VirtualHost/arg", "label": "arg", "value": "*:443"},
                            {"node": "/files/main/VirtualHost/directive[1]", "label": "directive", "value": "Include"},
                            {"node": "/files/main/VirtualHost/directive[1]/arg", "label": "arg", "value": "vhost.conf"},
                            {"node": "/files/main/directive[2]", "label": "directive", "value": "SecretKey"},
                            {"node": "/files/main/directive[2]/arg", "label": "arg", "value": "secret"}]
                return [{"node": "/files/child/directive", "label": "directive", "value": "SSLStrictSNIVHostCheck"},
                        {"node": "/files/child/directive/arg", "label": "arg", "value": "Off"}]
            config = {"apache_server_root": root, "apache_config_path": main, "apache_allowed_roots": [root], "osquery_path": "osqueryi"}
            with patch("context_agent.apache_check.os.name", "posix"):
                result = collect(config, run)
            self.assertEqual(len(result["files"]), 2)
            setting = next(item for item in result["directives"] if item["directive"] == "SSLStrictSNIVHostCheck")
            self.assertEqual(setting["virtual_host"], "/files/main/VirtualHost")
            self.assertEqual(setting["arguments"], ["Off"])
            self.assertNotIn("secret", str(result))
            self.assertFalse(result["complete"])

    def test_outside_root_and_missing_lens_never_give_negative_result(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            main = os.path.join(root, "httpd.conf")
            with open(main, "w") as handle:
                handle.write("fixture")
            config = {"apache_server_root": root, "apache_config_path": main, "apache_allowed_roots": [root], "osquery_path": "osqueryi"}
            with patch("context_agent.apache_check.os.name", "posix"):
                result = collect(config, lambda args, timeout: [])
                self.assertEqual(result["interpretation"], "not_determined")
                self.assertTrue(result["warnings"])
                config["apache_config_path"] = os.path.join(outside, "httpd.conf")
                with self.assertRaises(ValueError):
                    collect(config, lambda args, timeout: [])


class ApacheApprovalTests(TestCase):
    def test_approval_works_for_other_cves_with_configured_agent(self):
        host = Host.objects.create(ip_address="192.0.2.1")
        agent = ContextAgent.objects.create(host=host, token_hash="a" * 64, capabilities={"apache_check": True})
        vuln = Vulnerability.objects.create(scan=Scan.objects.create(scan_type="OSV"), host=host, cve_id="CVE-2024-12345", severity="high", name="test")
        assessment = ContextAssessment.objects.create(vulnerability=vuln, host=host, provider="test")
        user = User.objects.create_user("analyst", is_staff=True)
        self.client.force_login(user)
        self.client.post(reverse("approve_apache_context", args=[vuln.pk, assessment.pk]))
        self.assertEqual(ContextJob.objects.get().kind, "apache")
        self.assertEqual(ContextJob.objects.get().agent, agent)
