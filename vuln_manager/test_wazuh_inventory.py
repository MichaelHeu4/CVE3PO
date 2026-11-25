from unittest.mock import Mock, patch
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from vuln_manager.models import Extension, Host, HostAddress, Software, WazuhContextSnapshot
from vuln_manager.utils.wazuh_context import fetch_wazuh_agents, match_hosts, map_software, refresh_all_hosts


class WazuhInventoryTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(ip_address="192.0.2.1")
        self.other = Host.objects.create(ip_address="192.0.2.2")
        HostAddress.objects.create(host=self.host, ip_address="192.0.2.3")
        self.software = Software.objects.create(name="apache2", version="2")
        self.software.hosts.add(self.host)

    def test_host_mapping_requires_unique_wazuh_agent(self):
        agents = [{"id": "001", "ip": "192.0.2.3"}, {"id": "002", "ip": "192.0.2.2"}]
        self.assertEqual(match_hosts(agents), {self.host.pk: "001", self.other.pk: "002"})
        agents.append({"id": "003", "ip": "192.0.2.1"})
        self.assertEqual(match_hosts(agents), {self.other.pk: "002"})

    def test_dynamic_ip_uses_unique_hostname_and_conflicting_ips_are_rejected(self):
        self.host.hostname = "web.example"
        self.host.save()
        self.assertEqual(match_hosts([{"id": "001", "ip": "any", "name": "WEB.EXAMPLE"}]), {self.host.pk: "001"})
        self.other.hostname = "web.example"
        self.other.save()
        self.assertEqual(match_hosts([{"id": "001", "ip": "any", "name": "web.example"}]), {})
        HostAddress.objects.filter(ip_address="192.0.2.1").update(host=self.other)
        self.assertEqual(match_hosts([{"id": "001", "ip": "192.0.2.1"}]), {})

    def test_process_mapping_never_guesses_ambiguous_software(self):
        ports = [{"process": "", "pid": 42, "local": {"ip": "0.0.0.0", "port": 80}}]
        processes = [{"pid": 42, "name": "apache2"}]
        self.assertEqual(map_software(self.host, ports, processes)[0]["software_id"], self.software.pk)
        duplicate = Software.objects.create(name="apache2", version="3")
        duplicate.hosts.add(self.host)
        self.assertEqual(map_software(self.host, ports, processes), [])

    def test_observations_are_visible_on_host_and_software_pages(self):
        user = User.objects.create_user("reader")
        self.client.force_login(user)
        ports = [{"process": "apache2", "pid": 42, "local": {"ip": "0.0.0.0", "port": 80}, "protocol": "tcp"}]
        WazuhContextSnapshot.objects.create(host=self.host, agent_id="001", ports=ports, software_matches=map_software(self.host, ports, []))
        self.assertContains(self.client.get(reverse("host_detail", args=[self.host.pk])), "apache2")
        response = self.client.get(reverse("software_detail", args=[self.software.pk]))
        self.assertContains(response, "Wazuh process and port suggestions")
        self.assertContains(response, "80/tcp")

    @patch("vuln_manager.utils.wazuh_context.fetch_wazuh_context")
    @patch("vuln_manager.utils.wazuh_context.fetch_wazuh_agents")
    def test_bulk_sync_handles_each_host_without_closing_findings(self, agents, fetch):
        agents.return_value = [{"id": "001", "ip": "192.0.2.1"}, {"id": "002", "ip": "192.0.2.2"}]
        fetch.side_effect = [([{"process": "apache2", "pid": 42}], []), RuntimeError("offline")]
        result = refresh_all_hosts()
        self.assertEqual((result["hosts"], result["matched"], result["updated"], result["failed"]), (2, 2, 1, 1))
        self.assertEqual(result["failed_hosts"][0]["id"], self.other.pk)
        self.assertEqual(WazuhContextSnapshot.objects.get().software_matches[0]["software_id"], self.software.pk)

    @patch("vuln_manager.utils.wazuh_sync.start_sync", return_value=True)
    def test_module_sync_requires_staff_and_active_module(self, start):
        user = User.objects.create_user("tester", is_staff=True)
        self.client.force_login(user)
        url = reverse("sync_wazuh_inventory")
        self.client.post(url)
        start.assert_not_called()
        Extension.objects.create(name_id="wazuh", is_active=True)
        self.client.post(url)
        start.assert_called_once()

    @patch.dict("os.environ", {"WAZUH_CONTEXT_API_URL": "https://wazuh.example:55000", "WAZUH_CONTEXT_API_USER": "user", "WAZUH_CONTEXT_API_PASSWORD": "secret"})
    @patch("vuln_manager.utils.wazuh_context.requests.Session")
    def test_agent_list_fetches_all_pages(self, session_class):
        session = session_class.return_value.__enter__.return_value
        auth = Mock(status_code=200)
        auth.json.return_value = {"data": {"token": "token"}}
        page1, page2 = Mock(status_code=200), Mock(status_code=200)
        page1.json.return_value = {"data": {"total_affected_items": 2, "affected_items": [{"id": "001"}]}}
        page2.json.return_value = {"data": {"total_affected_items": 2, "affected_items": [{"id": "002"}]}}
        session.get.side_effect = [auth, page1, page2]
        self.assertEqual([item["id"] for item in fetch_wazuh_agents()], ["001", "002"])
        self.assertEqual(session.get.call_args_list[-1].kwargs["params"]["offset"], 1)
