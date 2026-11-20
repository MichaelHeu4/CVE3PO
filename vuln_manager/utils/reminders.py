"""Opt-in daily reminders, claimed per recipient to avoid duplicate workers."""
import logging
from datetime import timedelta
from django.core.mail import send_mail
from django.db import IntegrityError
from django.utils import timezone
from vuln_manager.models import ReminderDelivery, SystemSettings, Vulnerability

logger = logging.getLogger(__name__)


def run_reminders():
    settings = SystemSettings.objects.first()
    if not settings or not settings.reminders_enabled:
        return
    today = timezone.localdate()
    active = Vulnerability.objects.select_related("assignee").filter(status__in=["open", "in_progress", "verification"], due_date__lte=today + timedelta(days=1))
    escalation = [x.strip() for x in settings.escalation_recipients.replace(";", ",").split(",") if x.strip()]
    for vuln in active.iterator():
        recipients = set()
        if vuln.assignee and vuln.assignee.email:
            recipients.add(vuln.assignee.email.lower())
        if vuln.due_date <= today - timedelta(days=settings.escalation_after_days):
            recipients.update(x.lower() for x in escalation)
        for recipient in recipients:
            delivery = None
            try:
                delivery, created = ReminderDelivery.objects.get_or_create(vulnerability=vuln, date=today, kind="due", recipient=recipient)
                if not created:
                    # Retry abandoned/failed attempts after one hour; claim atomically.
                    if delivery.sent_at or not ReminderDelivery.objects.filter(pk=delivery.pk, sent_at__isnull=True, claimed_at__lt=timezone.now()-timedelta(hours=1)).update(claimed_at=timezone.now(), error=""):
                        continue
                sent = send_mail(
                    f"CVE3PO: {vuln.cve_id} due {vuln.due_date}",
                    f"Finding: {vuln.name}\nStatus: {vuln.get_status_display()}\nDue: {vuln.due_date}\nTeam: {vuln.owner_team or 'Unassigned'}\nFinding ID: {vuln.pk}",
                    None, [recipient], fail_silently=False)
                if sent != 1:
                    raise RuntimeError("Mail backend did not accept the message")
                ReminderDelivery.objects.filter(pk=delivery.pk).update(sent_at=timezone.now(), error="")
            except IntegrityError:
                continue
            except Exception as exc:
                logger.exception("Reminder failed for finding %s", vuln.pk)
                if delivery and delivery.pk:
                    ReminderDelivery.objects.filter(pk=delivery.pk).update(error=str(exc)[:500])
