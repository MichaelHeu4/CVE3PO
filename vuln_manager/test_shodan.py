from unittest.mock import call, patch

from django.test import TestCase

from vuln_manager.extensions.shodan import enrich_host_with_shodan
from vuln_manager.models import Host, HostAddress, Port, Scan


@patch("vuln_manager.extensions.shodan.time.sleep")
@patch("vuln_manager.extensions.shodan.lookup_host")
class ShodanHostAddressesTests(TestCase):
    def setUp(self):
        self.host = Host.objects.create(ip_address="10.0.0.10")
        HostAddress.objects.create(host=self.host, ip_address="203.0.113.10")
        HostAddress.objects.create(host=self.host, ip_address="2001:db8::10")
        self.ips = ["10.0.0.10", "203.0.113.10", "2001:db8::10"]

    def test_secondary_hit_sets_exposure_even_if_primary_not_found(self, lookup, sleep):
        lookup.side_effect = [None, {"data": [{"port": 443}]}, None]

        result = enrich_host_with_shodan(self.host.pk, api_key="test-key")

        self.assertEqual(lookup.call_args_list, [call(ip, "test-key") for ip in self.ips])
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(result["status"], "found")
        self.assertEqual(result["found_ips"], ["203.0.113.10"])
        self.host.refresh_from_db()
        self.assertTrue(self.host.is_exposed)
        self.assertTrue(Port.objects.filter(host=self.host, port_number=443).exists())

    def test_combines_ports_from_all_ips_without_duplicates(self, lookup, sleep):
        lookup.side_effect = [
            {"data": [{"port": 22}]},
            {"data": [{"port": 443}, {"port": 22}]},
            {"data": [{"port": 80}]},
        ]

        result = enrich_host_with_shodan(self.host.pk, api_key="test-key")

        self.assertEqual(result["ports"], [22, 80, 443])
        self.assertEqual(result["ports_created"], 3)
        self.assertEqual(result["checked_ips"], self.ips)
        self.assertEqual(Port.objects.filter(host=self.host).count(), 3)

        lookup.side_effect = None
        lookup.return_value = {"data": [{"port": 443}]}
        result = enrich_host_with_shodan(self.host.pk, api_key="test-key")
        self.assertEqual(result["ports_created"], 0)
        self.assertFalse(result["newly_exposed"])

    def test_all_ips_missing_leaves_host_unexposed(self, lookup, sleep):
        lookup.return_value = None

        result = enrich_host_with_shodan(self.host.pk, api_key="test-key")

        self.assertEqual(result["status"], "not_found")
        self.assertEqual(result["checked_ips"], self.ips)
        self.assertEqual(lookup.call_count, 3)
        self.host.refresh_from_db()
        self.assertFalse(self.host.is_exposed)
        self.assertFalse(Scan.objects.filter(scan_type="SHODAN").exists())

    def test_primary_is_checked_without_mirrored_address(self, lookup, sleep):
        self.host.addresses.all().delete()
        lookup.return_value = {"data": []}

        result = enrich_host_with_shodan(self.host.pk, api_key="test-key")

        lookup.assert_called_once_with(self.host.ip_address, "test-key")
        sleep.assert_not_called()
        self.assertEqual(result["status"], "found")
