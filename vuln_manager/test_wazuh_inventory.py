from unittest.mock import Mock, patch
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from vuln_manager.models import Extension, Host, HostAddress, Software, SystemSettings, WazuhContextSnapshot
from vuln_manager.utils.wazuh_context import fetch_wazuh_agents, fetch_wazuh_context, match_hosts, map_software, port_category, refresh_all_hosts


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
        host_response = self.client.get(reverse("host_detail", args=[self.host.pk]), {"tab": "infrastructure"})
        self.assertContains(host_response, "Wazuh ports and processes")
        self.assertContains(host_response, "apache2")
        self.assertContains(host_response, ":80")
        self.assertContains(self.client.get(reverse("port_list")), "apache2")
        response = self.client.get(reverse("software_detail", args=[self.software.pk]))
        self.assertContains(response, "Wazuh process and port suggestions")
        self.assertContains(response, "80/tcp")

    def test_port_page_uses_only_latest_snapshot_and_searches_unmapped_processes(self):
        user = User.objects.create_user("port-reader")
        self.client.force_login(user)
        WazuhContextSnapshot.objects.create(host=self.host, agent_id="001", ports=[{"local": {"port": 111}, "process": "obsolete"}])
        WazuhContextSnapshot.objects.create(host=self.host, agent_id="001", ports=[{"local": {"port": 8443, "ip": "127.0.0.1"}, "process": "unmapped-process", "protocol": "tcp"}])
        response = self.client.get(reverse("port_list"), {"q": "unmapped-process"})
        self.assertContains(response, "8443")
        self.assertContains(response, "unmapped-process")
        self.assertContains(response, "unknown")
        self.assertNotContains(response, "obsolete")
        response = self.client.get(reverse("host_detail", args=[self.host.pk]), {"tab": "infrastructure"})
        self.assertContains(response, "unmapped-process")
        self.assertNotContains(response, "obsolete")

    def test_known_process_package_hints_and_container_proxy(self):
        for name in ("openssh-server", "samba", "postfix", "docker-proxy"):
            software = Software.objects.create(name=name, version="1")
            software.hosts.add(self.host)
        ports = [{"process": "sshd", "pid": 1}, {"process": "nmbd", "pid": 2},
                 {"process": "smbd", "pid": 3}, {"process": "master", "pid": 4},
                 {"process": "docker-proxy", "pid": 5}]
        processes = [{"name": "master", "pid": 4, "cmd": "/usr/lib/postfix/sbin/master"}]
        results = {item["process"]: item for item in map_software(self.host, ports, processes)}
        self.assertEqual(results["sshd"]["software_name"], "openssh-server")
        self.assertEqual(results["smbd"]["software_name"], "samba")
        self.assertEqual(results["nmbd"]["software_name"], "samba")
        self.assertEqual(results["master"]["software_name"], "postfix")
        self.assertNotIn("docker-proxy", results)
        self.assertEqual(map_software(self.host, [{"process": "master", "pid": 4}], []), [])
        path_only = map_software(self.host, [{"pid": 9}], [{"pid": 9, "cmd": "/usr/sbin/sshd"}])
        self.assertEqual(path_only[0]["software_name"], "openssh-server")

    def test_mapping_improves_for_existing_snapshots_without_sync(self):
        software = Software.objects.create(name="openssh-server", version="1")
        software.hosts.add(self.host)
        snapshot = WazuhContextSnapshot.objects.create(host=self.host, agent_id="001", ports=[{"pid": 1, "process": "sshd", "state": "listening", "protocol": "tcp", "local": {"port": 22}}])
        self.assertEqual(snapshot.software_matches, [])
        self.client.force_login(User.objects.create_user("snapshot-reader"))
        self.assertContains(self.client.get(reverse("port_list")), "openssh-server")

    def test_ambiguous_alias_does_not_select_a_package(self):
        for name in ("openssh", "openssh-server"):
            Software.objects.create(name=name, version="1").hosts.add(self.host)
        self.assertEqual(map_software(self.host, [{"process": "sshd"}], []), [])

    def test_postfix_mapping_does_not_trust_mismatched_process_or_arguments(self):
        Software.objects.create(name="postfix", version="1").hosts.add(self.host)
        port = [{"pid": 4, "process": "master"}]
        self.assertEqual(map_software(self.host, port, [{"pid": 4, "name": "other", "cmd": "/usr/lib/postfix/sbin/master"}]), [])
        self.assertEqual(map_software(self.host, port, [{"pid": 4, "name": "master", "cmd": "/usr/lib/postfix/sbin/master --secret=abc"}]), [])

    def test_port_categories_distinguish_listening_connections_and_udp_unknown(self):
        self.assertEqual(port_category({"protocol": "tcp6", "state": "listening"}), "listening")
        self.assertEqual(port_category({"protocol": "tcp", "state": "established"}), "connections")
        self.assertEqual(port_category({"protocol": "udp", "state": ""}), "udp_unknown")
        self.assertEqual(port_category({"protocol": "tcp", "state": ""}), "other")

    def test_host_and_port_pages_separate_wazuh_categories(self):
        self.client.force_login(User.objects.create_user("categorized-reader"))
        ports = [{"process": "listener", "protocol": "tcp", "state": "listening", "local": {"port": 80}},
                 {"process": "connection", "protocol": "tcp", "state": "established", "local": {"port": 40123}},
                 {"process": "datagram", "protocol": "udp", "local": {"port": 137}},
                 {"process": "docker-proxy", "protocol": "tcp", "state": "listening", "local": {"port": 8080}}]
        WazuhContextSnapshot.objects.create(host=self.host, agent_id="001", ports=ports)
        for url, params in [(reverse("port_list"), {}), (reverse("host_detail", args=[self.host.pk]), {"tab": "infrastructure"})]:
            response = self.client.get(url, params)
            for text in ("Listening ports", "Connections", "UDP sockets", "Container proxy", "listener", "connection", "datagram"):
                self.assertContains(response, text)

    def test_port_section_pagination_keeps_other_filters(self):
        self.client.force_login(User.objects.create_user("paging-reader"))
        ports = [{"process": "listener", "protocol": "tcp", "state": "listening", "local": {"port": 8000 + i}} for i in range(41)]
        WazuhContextSnapshot.objects.create(host=self.host, agent_id="001", ports=ports)
        response = self.client.get(reverse("port_list"), {"q": "listener", "udp_page": 2})
        self.assertContains(response, "listen_page=2")
        self.assertContains(response, "udp_page=2")
        self.assertContains(response, "q=listener")
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
        session.post.return_value = auth
        session.get.side_effect = [page1, page2]
        self.assertEqual([item["id"] for item in fetch_wazuh_agents()], ["001", "002"])
        self.assertEqual(session.get.call_args_list[-1].kwargs["params"]["offset"], 1)

    @patch.dict("os.environ", {"WAZUH_CONTEXT_API_URL": "https://wazuh.example:55000", "WAZUH_CONTEXT_API_USER": "user", "WAZUH_CONTEXT_API_PASSWORD": "secret"})
    @patch("vuln_manager.utils.wazuh_context.requests.Session")
    def test_fetch_filters_sensitive_fields_and_rejects_partial_results(self, session_class):
        session = session_class.return_value.__enter__.return_value
        auth = Mock(status_code=200)
        auth.json.return_value = {"data": {"token": "token"}}
        ports = Mock(status_code=200)
        ports.json.return_value = {"error": 0, "data": {"total_affected_items": 1, "affected_items": [{"pid": 42, "process": "apache", "scan": {"time": "now"}}]}}
        processes = Mock(status_code=200)
        processes.json.return_value = {"error": 0, "data": {"total_affected_items": 1, "affected_items": [{"pid": 42, "name": "apache", "cmd": "/usr/sbin/apache", "argvs": "secret"}]}}
        session.post.return_value = auth
        session.get.side_effect = [ports, processes]
        result = fetch_wazuh_context("001")
        self.assertEqual(result[1], [{"pid": 42, "name": "apache", "cmd": "/usr/sbin/apache"}])
        self.assertFalse(any(call.kwargs.get("allow_redirects") for call in session.get.call_args_list))
        ports.json.return_value["data"]["total_failed_items"] = 1
        session.get.side_effect = [ports]
        with self.assertRaises(ValueError):
            fetch_wazuh_context("001")

    def test_api_configuration_requires_staff_and_keeps_password_secret(self):
        user = User.objects.create_user("api-admin", is_staff=True)
        self.client.force_login(user)
        url = reverse("save_wazuh_api_config")
        self.assertEqual(self.client.post(url, {"wazuh_api_url": "http://bad", "wazuh_api_user": "a"}).status_code, 400)
        self.client.post(url, {"wazuh_api_url": "https://wazuh.example:55000", "wazuh_api_user": "analyst", "wazuh_api_password": "s3cret"})
        settings = SystemSettings.objects.get(pk=1)
        self.assertEqual(settings.wazuh_api_password, "s3cret")
        self.client.post(url, {"wazuh_api_url": "https://wazuh.example:55000", "wazuh_api_user": "analyst", "wazuh_api_password": ""})
        settings.refresh_from_db()
        self.assertEqual(settings.wazuh_api_password, "s3cret")
        self.assertNotContains(self.client.get(reverse("extensions")), "s3cret")
        user.is_staff = False
        user.save()
        self.client.post(url, {"wazuh_api_url": "https://wrong.example", "wazuh_api_user": "wrong"})
        settings.refresh_from_db()
        self.assertEqual(settings.wazuh_api_url, "https://wazuh.example:55000")

    @patch.dict("os.environ", {"WAZUH_CONTEXT_API_URL": "https://env.example", "WAZUH_CONTEXT_API_USER": "env-user", "WAZUH_CONTEXT_API_PASSWORD": "env-secret"})
    def test_environment_credentials_are_not_mixed_with_saved_api_settings(self):
        from vuln_manager.utils.wazuh_context import wazuh_api_config
        self.assertEqual(wazuh_api_config(), ("https://env.example", "env-user", "env-secret"))
        SystemSettings.objects.create(pk=1, wazuh_api_url="https://saved.example", wazuh_api_user="saved-user")
        self.assertEqual(wazuh_api_config(), ("https://saved.example", "saved-user", ""))

    @patch("vuln_manager.utils.wazuh_context.requests.Session")
    def test_verify_option_applies_to_authentication_and_all_inventory_requests(self, session_class):
        settings = SystemSettings.objects.create(pk=1, wazuh_api_url="https://wazuh.example:55000", wazuh_api_user="user", wazuh_api_password="secret")
        session = session_class.return_value.__enter__.return_value
        auth = Mock(status_code=200)
        auth.json.return_value = {"data": {"token": "token"}}
        empty = Mock(status_code=200)
        empty.json.return_value = {"error": 0, "data": {"total_affected_items": 0, "affected_items": []}}
        session.post.return_value = auth
        session.get.return_value = empty
        for verify in (True, False):
            settings.wazuh_verify_ssl = verify
            settings.save(update_fields=["wazuh_verify_ssl"])
            session.reset_mock()
            fetch_wazuh_agents()
            fetch_wazuh_context("001")
            self.assertEqual(session.post.call_count, 2)
            self.assertEqual(session.get.call_count, 3)
            for call in list(session.post.call_args_list) + list(session.get.call_args_list):
                self.assertIs(call.kwargs["verify"], verify)

    def test_staff_can_change_verify_checkbox(self):
        user = User.objects.create_user("verify-admin", is_staff=True)
        self.client.force_login(user)
        url = reverse("save_wazuh_api_config")
        data = {"wazuh_api_url": "https://wazuh.example:55000", "wazuh_api_user": "user", "wazuh_api_password": "secret"}
        self.client.post(url, {**data, "wazuh_verify_ssl": "1"})
        settings = SystemSettings.objects.get(pk=1)
        self.assertTrue(settings.wazuh_verify_ssl)
        self.assertContains(self.client.get(reverse("extensions")), 'name="wazuh_verify_ssl" value="1" checked')
        self.client.post(url, data)
        settings.refresh_from_db()
        self.assertFalse(settings.wazuh_verify_ssl)
        self.assertContains(self.client.get(reverse("extensions")), 'name="wazuh_verify_ssl" value="1" >')
