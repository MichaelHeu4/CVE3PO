"""Rule-based notifications. Finding/ticket creation is never an action here."""
import logging
from datetime import timedelta

import requests
from django.core.mail import send_mail
from django.db.models import Q
from django.utils import timezone
from vuln_manager.models import Host, NotificationDelivery, NotificationEvent, NotificationRule, Vulnerability

logger = logging.getLogger(__name__)


def emit(key, event_type, title, **relations):
    return NotificationEvent.objects.get_or_create(key=key, defaults={"event_type": event_type, "title": title, **relations})[0]


def _matches(rule, event):
    vuln = event.vulnerability
    if rule.severity and (not vuln or vuln.severity != rule.severity):
        return False
    if rule.critical_host or rule.exposed_host:
        hosts = Host.objects.none()
        if vuln:
            if vuln.host_id:
                hosts = Host.objects.filter(pk=vuln.host_id)
            elif vuln.software_id:
                hosts = Host.objects.filter(software_inventory=vuln.software_id)
        elif event.software_id:
            hosts = Host.objects.filter(software_inventory=event.software_id)
        if rule.critical_host:
            hosts = hosts.filter(criticality="Critical")
        if rule.exposed_host:
            hosts = hosts.filter(is_exposed=True)
        if not hosts.exists():
            return False
    return True


def queue_due_events():
    if not NotificationRule.objects.filter(enabled=True, event_type="sla_tomorrow").exists():
        return
    tomorrow = timezone.localdate() + timedelta(days=1)
    for vuln in Vulnerability.objects.filter(status__in=["open", "in_progress", "verification"], due_date=tomorrow).iterator():
        emit(f"sla:{vuln.pk}:{tomorrow}", "sla_tomorrow", f"SLA due tomorrow: {vuln.cve_id}", vulnerability=vuln)


def queue_deliveries():
    from vuln_manager.utils.cti import cti_enabled
    events = NotificationEvent.objects.filter(processed_at__isnull=True)
    if not cti_enabled():
        events = events.exclude(event_type="cti_match")
    for event in events.order_by("created_at")[:500]:
        rules = NotificationRule.objects.filter(enabled=True, event_type=event.event_type, created_at__lte=event.created_at)
        for rule in rules:
            if not _matches(rule, event):
                continue
            for channel, destination in (("email", rule.email), ("webhook", rule.webhook_url)):
                if destination:
                    NotificationDelivery.objects.get_or_create(event=event, rule=rule, channel=channel, defaults={"destination": destination})
        NotificationEvent.objects.filter(pk=event.pk, processed_at__isnull=True).update(processed_at=timezone.now())


def deliver():
    now = timezone.now()
    # Claims are atomic, so concurrent workers do not normally send twice.
    # After a crash during delivery, retries are at-least-once; receivers should
    # deduplicate using the stable delivery_id in the webhook body.
    pending = NotificationDelivery.objects.filter(Q(status="pending", next_attempt__lte=now) | Q(status="sending", claimed_at__lt=now-timedelta(minutes=10))).order_by("pk")
    from vuln_manager.utils.cti import cti_enabled
    if not cti_enabled():
        pending = pending.exclude(event__event_type="cti_match")
    for delivery in list(pending[:100]):
        claimed = NotificationDelivery.objects.filter(pk=delivery.pk).filter(Q(status="pending", next_attempt__lte=now) | Q(status="sending", claimed_at__lt=now-timedelta(minutes=10))).update(status="sending", claimed_at=now)
        if not claimed:
            continue
        event = delivery.event
        payload = {"delivery_id": delivery.pk, "event": event.event_type, "title": event.title, "vulnerability_id": event.vulnerability_id, "cti_item_id": event.item_id, "software_id": event.software_id, "source_url": event.item.url if event.item_id else None}
        try:
            if delivery.channel == "email":
                if send_mail("CVE3PO: " + event.title, "\n".join(f"{k}: {v}" for k, v in payload.items()), None, [delivery.destination], fail_silently=False) != 1:
                    raise RuntimeError("Mail backend did not accept the message")
            else:
                response = requests.post(delivery.destination, json=payload, timeout=10, allow_redirects=False)
                if not 200 <= response.status_code < 300:
                    raise RuntimeError(f"Webhook returned HTTP {response.status_code}")
            NotificationDelivery.objects.filter(pk=delivery.pk).update(status="sent", sent_at=timezone.now(), error="")
        except Exception as exc:
            attempts = delivery.attempts + 1
            NotificationDelivery.objects.filter(pk=delivery.pk).update(status="failed" if attempts >= 5 else "pending", attempts=attempts, next_attempt=timezone.now()+timedelta(minutes=5*2**(attempts-1)), error=str(exc)[:500])
            logger.warning("Notification delivery %s failed", delivery.pk)


def tick():
    queue_due_events()
    queue_deliveries()
    deliver()
