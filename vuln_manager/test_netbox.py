from unittest.mock import MagicMock, patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from vuln_manager.extensions import netbox
from vuln_manager.models import (
    Extension,
    Host,
    HostAddress,
    HostSoftwareRelationship,
    Software,
    SystemSettings,
)
from vuln_manager.utils.identity import merge_hosts


class FakeClient:
    """Stands in for NetboxClient: returns canned results per API path."""

    def __init__(self, devices=(), vms=(), ips=()):
        self.data = {
            "/api/dcim/devices/": list(devices),
            "/api/virtualization/virtual-machines/": list(vms),
            "/api/ipam/ip-addresses/": list(ips),
        }

    def paginate(self, path, params=None):
        return iter(self.data[path])


def _device(pk, name, primary=None, cf=None, tags=()):
    return {
        "id": pk,
        "name": name,
        "primary_ip4": {"address": primary} if primary else None,
        "custom_fields": cf or {},
        "tags": [{"name": t, "slug": t} for t in tags],
    }


def _configure(**overrides):
    s, _ = SystemSettings.objects.get_or_create(pk=1)
    s.netbox_url = "https://netbox.example.test"
    s.netbox_api_token = "abc123"
    s.netbox_source_type = "custom_field"
    s.netbox_source_name = "criticality"
    s.netbox_value_mapping = None
    for key, value in overrides.items():
        setattr(s, key, value)
    s.save()
    return s


def _add_host(ip, hostname=None, criticality=None):
    host = Host.objects.create(ip_address=ip, hostname=hostname, criticality=criticality)
    HostAddress.objects.get_or_create(
        ip_address=ip, defaults={"host": host, "source": "manual"}
    )
    return host


class NetboxValueParsingTests(TestCase):
    def test_mapping_parse_and_lookup(self):
        mapping = netbox.parse_value_mapping("kritisch=Critical, hoch = high\n1=LOW; bogus=Nope")
        self.assertEqual(mapping, {"kritisch": "Critical", "hoch": "High", "1": "Low"})
        self.assertEqual(netbox.map_value("Kritisch", mapping), "Critical")
        self.assertEqual(netbox.map_value("medium", mapping), "Medium")
        self.assertIsNone(netbox.map_value("whatever", mapping))
        self.assertIsNone(netbox.map_value("", mapping))

    def test_custom_field_choice_dict_and_case_insensitive_name(self):
        obj = {"custom_fields": {"Criticality": {"value": "high", "label": "High"}}}
        self.assertEqual(
            netbox.resolve_level(obj, "custom_field", "criticality", {}), "High"
        )

    def test_tag_prefix_takes_highest(self):
        obj = {"tags": [{"name": "crit-low", "slug": "crit-low"},
                        {"name": "Crit: Critical", "slug": "crit-critical"},
                        {"name": "linux", "slug": "linux"}]}
        self.assertEqual(netbox.resolve_level(obj, "tag", "crit-", {}), "Critical")

    def test_auth_header_v1_and_v2_tokens(self):
        self.assertEqual(netbox._auth_header("abc"), "Token abc")
        self.assertEqual(netbox._auth_header("nbt_k.s"), "Bearer nbt_k.s")


class NetboxSyncTests(TestCase):
    def setUp(self):
        Extension.objects.create(name_id="netbox", is_active=True)
        self.settings = _configure()

    def test_matches_by_primary_ip_and_overwrites(self):
        host = _add_host("10.0.0.5", criticality="Low")
        client = FakeClient(devices=[_device(1, "srv-a", "10.0.0.5/24", {"criticality": "Critical"})])

        result = netbox.sync_criticality(self.settings, client)

        host.refresh_from_db()
        self.assertEqual(host.criticality, "Critical")
        self.assertEqual(host.criticality_source, "netbox")
        self.assertIsNotNone(host.criticality_synced_at)
        self.assertEqual(result["changed"], 1)

    def test_matches_secondary_ip_via_ipam_and_vm(self):
        host = _add_host("192.168.1.10")
        HostAddress.objects.create(host=host, ip_address="172.16.0.10", source="agent")
        vm = _device(7, "vm-b", None, {"criticality": "hoch"})
        client = FakeClient(
            vms=[vm],
            ips=[{"address": "172.16.0.10/16",
                  "assigned_object": {"virtual_machine": {"id": 7}}}],
        )
        self.settings.netbox_value_mapping = "hoch=High"

        netbox.sync_criticality(self.settings, client)

        host.refresh_from_db()
        self.assertEqual(host.criticality, "High")

    def test_matches_by_short_hostname(self):
        host = _add_host("10.9.9.9", hostname="DB01.corp.local")
        client = FakeClient(devices=[_device(2, "db01", None, {"criticality": "medium"})])

        netbox.sync_criticality(self.settings, client)

        host.refresh_from_db()
        self.assertEqual(host.criticality, "Medium")

    def test_unknown_netbox_objects_do_not_create_hosts(self):
        client = FakeClient(devices=[_device(3, "ghost", "10.1.1.1/32", {"criticality": "High"})])
        netbox.sync_criticality(self.settings, client)
        self.assertFalse(Host.objects.exists())

    def test_missing_value_keeps_criticality_and_releases_lock(self):
        host = _add_host("10.0.0.6", criticality="High")
        host.criticality_source = "netbox"
        host.save()
        client = FakeClient(devices=[_device(4, "srv-c", "10.0.0.6/24", {"criticality": None})])

        result = netbox.sync_criticality(self.settings, client)

        host.refresh_from_db()
        self.assertEqual(host.criticality, "High")
        self.assertEqual(host.criticality_source, "manual")
        self.assertEqual(result["without_value"], 1)

    def test_host_gone_from_netbox_is_released(self):
        host = _add_host("10.0.0.7", criticality="High")
        host.criticality_source = "netbox"
        host.save()
        netbox.sync_criticality(self.settings, FakeClient())
        host.refresh_from_db()
        self.assertEqual(host.criticality_source, "manual")
        self.assertEqual(host.criticality, "High")

    def test_tag_source(self):
        host = _add_host("10.0.0.8")
        self.settings.netbox_source_type = "tag"
        self.settings.netbox_source_name = "crit-"
        client = FakeClient(devices=[_device(5, "srv-d", "10.0.0.8/24", tags=["crit-low"])])

        netbox.sync_criticality(self.settings, client)

        host.refresh_from_db()
        self.assertEqual(host.criticality, "Low")

    def test_sync_and_record_writes_error_status(self):
        with patch.object(netbox, "sync_criticality", side_effect=netbox.NetboxError("boom")):
            netbox.sync_and_record()
        status = SystemSettings.objects.get(pk=1).netbox_last_status
        self.assertEqual(status, "error: boom")


class NetboxLockTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="nb", password="pw12345", is_staff=True)
        self.client.force_login(self.user)
        Extension.objects.create(name_id="netbox", is_active=True)
        self.host = _add_host("10.0.1.1", criticality="Low")
        self.host.criticality_source = "netbox"
        self.host.save()

    def test_manual_update_is_forbidden_while_managed(self):
        response = self.client.post(
            reverse("update_host_criticality", args=[self.host.pk]),
            {"criticality": "Critical"},
        )
        self.assertEqual(response.status_code, 403)
        self.host.refresh_from_db()
        self.assertEqual(self.host.criticality, "Low")

    def test_host_form_keeps_netbox_value(self):
        self.client.post(
            reverse("host_edit", args=[self.host.pk]),
            {"ip_address": "10.0.1.1", "hostname": "x", "operating_system": "",
             "criticality": "Critical"},
        )
        self.host.refresh_from_db()
        self.assertEqual(self.host.criticality, "Low")
        self.assertEqual(self.host.hostname, "x")

    def test_software_propagation_skipped_for_managed_host(self):
        sw = Software.objects.create(name="openssl", version="1.0", criticality="Critical")
        sw.hosts.add(self.host)
        self.client.post(
            reverse("update_software_criticality", args=[sw.pk]),
            {"criticality": "Critical"},
        )
        self.host.refresh_from_db()
        self.assertEqual(self.host.criticality, "Low")

    def test_lock_lifted_when_module_inactive(self):
        Extension.objects.filter(name_id="netbox").update(is_active=False)
        self.client.post(
            reverse("update_host_criticality", args=[self.host.pk]),
            {"criticality": "Critical"},
        )
        self.host.refresh_from_db()
        self.assertEqual(self.host.criticality, "Critical")
        self.assertEqual(self.host.criticality_source, "manual")

    def test_host_pages_show_lock(self):
        detail = self.client.get(reverse("host_detail", args=[self.host.pk]))
        self.assertContains(detail, "Synced from NetBox")
        form = self.client.get(reverse("host_edit", args=[self.host.pk]))
        self.assertContains(form, "Synced from NetBox")

    def test_merge_keeps_netbox_value(self):
        manual = _add_host("10.0.1.2", criticality="Critical")
        merge_hosts(manual, self.host)
        manual.refresh_from_db()
        self.assertEqual(manual.criticality, "Low")
        self.assertEqual(manual.criticality_source, "netbox")


class NetboxConfigViewTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(username="admin", password="pw", is_staff=True)
        self.user = User.objects.create_user(username="user", password="pw")

    def _post(self, **data):
        payload = {
            "netbox_url": "https://netbox.example.test",
            "netbox_api_token": "tok",
            "netbox_verify_ssl": "1",
            "netbox_source_type": "tag",
            "netbox_source_name": "crit-",
            "netbox_value_mapping": "hoch=High",
            "netbox_sync_interval_hours": "2",
        }
        payload.update(data)
        return self.client.post(reverse("save_netbox_config"), payload)

    def test_staff_can_save_and_blank_token_keeps_existing(self):
        self.client.force_login(self.staff)
        self.assertEqual(self._post().status_code, 302)
        self._post(netbox_api_token="", netbox_verify_ssl="")
        s = SystemSettings.objects.get(pk=1)
        self.assertEqual(s.netbox_api_token, "tok")
        self.assertFalse(s.netbox_verify_ssl)
        self.assertEqual(s.netbox_source_type, "tag")
        self.assertEqual(s.netbox_sync_interval_hours, 2)

    def test_non_staff_forbidden(self):
        self.client.force_login(self.user)
        self.assertEqual(self._post().status_code, 403)

    def test_invalid_url_rejected(self):
        self.client.force_login(self.staff)
        self.assertEqual(self._post(netbox_url="ftp://x").status_code, 403)

    def test_extensions_page_renders_netbox_card(self):
        self.client.force_login(self.staff)
        response = self.client.get(reverse("extensions"))
        self.assertContains(response, "NetBox Configuration")

    def test_connection_test_records_status(self):
        _configure()
        self.client.force_login(self.staff)
        fake = MagicMock()
        fake.status.return_value = {"netbox-version": "4.2.1"}
        with patch.object(netbox, "client_from_settings", return_value=fake):
            self.client.post(reverse("netbox_test_connection"))
        self.assertEqual(
            SystemSettings.objects.get(pk=1).netbox_last_status,
            "connection ok: NetBox 4.2.1",
        )
