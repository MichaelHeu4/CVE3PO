from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.auth.models import User
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from vuln_manager.models import CTIFeed, CTIItem, CTIMatch, Extension, Host, NotificationDelivery, NotificationEvent, NotificationRule, Scan, Software, Vulnerability
from vuln_manager.utils.cti import fetch_feed, parse_feed, suggest_matches, run_feeds
from vuln_manager.utils.notifications import deliver, emit, queue_deliveries, queue_due_events

ATOM = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>one</id><title>OpenSSL vulnerability</title><link href="https://www.heise.de/news/example.html"/><summary>OpenSSL advisory without a CVE</summary><published>2026-11-20T09:00:00Z</published></entry></feed>'''


class CTITests(TestCase):
    def setUp(self):
        resolver = patch("vuln_manager.utils.cti.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))])
        resolver.start()
        self.addCleanup(resolver.stop)
        self.user = User.objects.create_user("analyst", password="password")
        self.staff = User.objects.create_user("staff", password="password", is_staff=True)
        self.client.force_login(self.user)
        self.feed = CTIFeed.objects.get(name="Heise Security Alerts")

    @patch("vuln_manager.utils.cti.requests.get")
    def test_import_is_idempotent_and_never_creates_findings(self, get):
        software = Software.objects.create(name="OpenSSL", version="1.0")
        response = Mock(status_code=200)
        response.iter_content.return_value = [ATOM]
        get.return_value = response
        fetch_feed(self.feed)
        fetch_feed(self.feed)
        self.assertEqual(CTIItem.objects.count(), 1)
        item = CTIItem.objects.get()
        self.assertEqual(item.cves, [])
        self.assertEqual(CTIMatch.objects.filter(item=item, software=software).count(), 1)
        self.assertEqual(NotificationEvent.objects.filter(event_type="cti_match").count(), 1)
        self.assertEqual(Vulnerability.objects.count(), 0)
        self.assertEqual(self.client.get(reverse("cti_detail", args=[item.pk])).status_code, 200)

    @patch("vuln_manager.utils.cti.requests.get")
    def test_feed_follows_trusted_redirect(self, get):
        redirect_response = Mock(status_code=301, headers={"Location": "/security/Alerts/feed.xml"})
        final_response = Mock(status_code=200)
        final_response.iter_content.return_value = [ATOM]
        get.side_effect = [redirect_response, final_response]
        self.assertEqual(fetch_feed(self.feed), 1)
        self.assertEqual(get.call_args_list[1].args[0], "https://www.heise.de/security/Alerts/feed.xml")
        redirect_response.close.assert_called_once()
        final_response.close.assert_called_once()

    @patch("vuln_manager.utils.cti.requests.get")
    def test_feed_rejects_untrusted_redirects(self, get):
        for target in ("http://www.heise.de/feed", "https://www.heise.de:8443/feed", "https://www.heise.de@evil.example/feed"):
            with self.subTest(target=target):
                response = Mock(status_code=301, headers={"Location": target})
                get.reset_mock()
                get.return_value = response
                with self.assertRaisesRegex(ValueError, "Invalid public feed URL"):
                    fetch_feed(self.feed)
                self.assertEqual(get.call_count, 1)
                response.close.assert_called_once()

    @patch("vuln_manager.utils.cti.requests.get")
    def test_feed_rejects_redirect_loop(self, get):
        response = Mock(status_code=301, headers={"Location": "/loop"})
        get.return_value = response
        with self.assertRaisesRegex(ValueError, "Too many"):
            fetch_feed(self.feed)
        self.assertEqual(get.call_count, 4)
        self.assertEqual(response.close.call_count, 4)

    def test_allows_external_and_rejects_javascript_article_links(self):
        self.assertEqual(len(list(parse_feed(ATOM.replace(b"https://www.heise.de/news/example.html", b"https://example.com/")))), 1)
        self.assertEqual(list(parse_feed(ATOM.replace(b"https://www.heise.de/news/example.html", b"javascript:alert(1)"))), [])

    @patch("vuln_manager.utils.cti.socket.getaddrinfo")
    def test_private_feed_address_is_rejected_before_fetch(self, resolve):
        resolve.return_value = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with patch("vuln_manager.utils.cti.requests.get") as get:
            with self.assertRaisesRegex(ValueError, "public addresses"):
                fetch_feed(self.feed)
            get.assert_not_called()

    @patch("vuln_manager.utils.cti.fetch_feed")
    def test_disabled_module_pauses_imports_and_hides_inbox(self, fetch):
        Extension.objects.filter(name_id="cti").update(is_active=False)
        run_feeds()
        fetch.assert_not_called()
        self.assertEqual(self.client.get(reverse("cti_inbox")).status_code, 404)
        self.assertEqual(self.client.post(reverse("cti_refresh_feed", args=[self.feed.pk])).status_code, 404)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_disabled_module_pauses_cti_notifications_only(self):
        NotificationRule.objects.create(name="cti", enabled=True, event_type="cti_match", email="soc@example.com")
        event = emit("cti:pause", "cti_match", "CTI")
        queue_deliveries()
        self.assertEqual(event.deliveries.count(), 1)
        Extension.objects.filter(name_id="cti").update(is_active=False)
        deliver()
        self.assertEqual(len(mail.outbox), 0)
        event.deliveries.get().refresh_from_db()
        self.assertEqual(event.deliveries.get().status, "pending")
        Extension.objects.filter(name_id="cti").update(is_active=True)
        deliver()
        self.assertEqual(len(mail.outbox), 1)

    def test_generic_rss_preserves_article_query(self):
        rss = b'<rss version="2.0"><channel><item><title>Vendor advisory</title><link>https://example.com/news?id=123</link><description>Information</description></item></channel></rss>'
        entries = list(parse_feed(rss))
        self.assertEqual(entries[0]["url"], "https://example.com/news?id=123")
        with self.assertRaisesRegex(ValueError, "Unsupported feed format"):
            list(parse_feed(b"<html><body>Error</body></html>"))

    def test_staff_can_add_edit_disable_feeds(self):
        url = reverse("cti_feed_add")
        self.assertEqual(self.client.post(url, {"name": "Vendor", "url": "https://example.com/feed"}).status_code, 403)
        self.client.force_login(self.staff)
        self.assertEqual(self.client.post(url, {"name": "Vendor", "url": "https://example.com/feed"}).status_code, 302)
        feed = CTIFeed.objects.get(name="Vendor")
        self.assertEqual(self.client.post(reverse("cti_feed_edit", args=[feed.pk]), {"name": "Vendor news", "url": "https://example.com/new"}).status_code, 302)
        self.assertEqual(self.client.post(reverse("cti_toggle_feed", args=[feed.pk]), {"from_modules": "1"}).status_code, 302)
        feed.refresh_from_db()
        self.assertFalse(feed.enabled)
        self.assertEqual(feed.url, "https://example.com/new")
        self.assertEqual(self.client.get(reverse("extensions")).status_code, 200)

    def test_manual_confirmation_creates_one_linked_finding(self):
        software = Software.objects.create(name="OpenSSL", version="1")
        item = CTIItem.objects.create(source=self.feed, external_id="1", title="OpenSSL issue", url="https://www.heise.de/news/x", summary="OpenSSL problem")
        suggest_matches(item)
        url = reverse("cti_create_finding", args=[item.pk])
        self.assertEqual(self.client.post(url, {"software": software.pk, "severity": "high"}).status_code, 302)
        self.assertEqual(self.client.post(url, {"software": software.pk, "severity": "high"}).status_code, 302)
        item.refresh_from_db()
        self.assertEqual(item.findings.count(), 1)
        self.assertEqual(item.findings.get().cve_id, f"CTI-{item.pk}")

    def test_cve_match_alerts_even_if_finding_has_only_a_host(self):
        host = Host.objects.create(ip_address="192.0.2.14", criticality="Critical", is_exposed=True)
        scan = Scan.objects.create(scan_type="MANUAL")
        vuln = Vulnerability.objects.create(scan=scan, host=host, cve_id="CVE-2026-12345", severity="high", name="Example")
        item = CTIItem.objects.create(source=self.feed, external_id="host-only", title="Example", url="https://www.heise.de/news/x", cves=[vuln.cve_id])
        NotificationRule.objects.create(name="matching CTI", enabled=True, event_type="cti_match", critical_host=True, exposed_host=True, email="soc@example.com")
        suggest_matches(item)
        queue_deliveries()
        self.assertTrue(NotificationDelivery.objects.filter(event__item=item, event__vulnerability=vuln).exists())

    def test_only_staff_can_configure_rules_or_feeds(self):
        self.assertEqual(self.client.get(reverse("notification_rules")).status_code, 403)
        self.assertEqual(self.client.post(reverse("cti_toggle_feed", args=[self.feed.pk])).status_code, 403)
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get(reverse("notification_rules")).status_code, 200)
        self.assertEqual(self.client.get(reverse("cti_inbox")).status_code, 200)

    def test_rule_checks_critical_and_exposed_on_same_host(self):
        software = Software.objects.create(name="OpenSSL", version="1")
        a = Host.objects.create(ip_address="192.0.2.1", criticality="Critical", is_exposed=False)
        b = Host.objects.create(ip_address="192.0.2.2", criticality="Low", is_exposed=True)
        software.hosts.add(a, b)
        rule = NotificationRule.objects.create(name="important", enabled=True, event_type="cti_match", critical_host=True, exposed_host=True, email="soc@example.com")
        event = emit("test:1", "cti_match", "test", software=software)
        queue_deliveries()
        self.assertFalse(event.deliveries.exists())
        a.is_exposed = True
        a.save()
        event2 = emit("test:2", "cti_match", "test", software=software)
        queue_deliveries()
        self.assertEqual(event2.deliveries.count(), 1)

    def test_host_specific_finding_does_not_inherit_other_host_exposure(self):
        software = Software.objects.create(name="OpenSSL", version="1")
        target = Host.objects.create(ip_address="192.0.2.10", criticality="Low", is_exposed=False)
        other = Host.objects.create(ip_address="192.0.2.11", criticality="Critical", is_exposed=True)
        software.hosts.add(target, other)
        scan = Scan.objects.create(scan_type="MANUAL")
        vuln = Vulnerability.objects.create(scan=scan, host=target, software=software, cve_id="CVE-2026-22222", severity="high", name="Example")
        NotificationRule.objects.create(name="kev", enabled=True, event_type="kev_added", critical_host=True, exposed_host=True, email="soc@example.com")
        event = emit("kev:host-specific", "kev_added", "test", vulnerability=vuln)
        queue_deliveries()
        self.assertFalse(event.deliveries.exists())

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_sla_delivery_is_deduplicated(self):
        NotificationRule.objects.create(name="due", enabled=True, event_type="sla_tomorrow", email="soc@example.com")
        scan = Scan.objects.create(scan_type="MANUAL")
        vuln = Vulnerability.objects.create(scan=scan, cve_id="CVE-2026-12345", severity="high", name="test", due_date=timezone.localdate()+timedelta(days=1))
        queue_due_events()
        queue_due_events()
        queue_deliveries()
        deliver()
        deliver()
        self.assertEqual(NotificationEvent.objects.filter(event_type="sla_tomorrow", vulnerability=vuln).count(), 1)
        self.assertEqual(len(mail.outbox), 1)

    @patch("vuln_manager.utils.notifications.requests.post")
    def test_webhook_errors_are_recorded_for_retry(self, post):
        post.return_value.status_code = 503
        NotificationRule.objects.create(name="webhook", enabled=True, event_type="new_finding", webhook_url="https://example.com/hook")
        emit("test:retry", "new_finding", "Test")
        queue_deliveries()
        deliver()
        delivery = NotificationDelivery.objects.get()
        self.assertEqual(delivery.status, "pending")
        self.assertEqual(delivery.attempts, 1)
        self.assertIn("503", delivery.error)
