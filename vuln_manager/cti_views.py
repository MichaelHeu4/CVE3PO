from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator, validate_email
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotFound
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from vuln_manager.models import CTIFeed, CTIItem, CTIMatch, DebianAdvisorySnapshot, DebianTrackerSnapshot, NotificationDelivery, NotificationRule, Scan, Software, Vulnerability
from vuln_manager.utils.audit import log_vulnerability_event
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability
from vuln_manager.utils.cti import cti_enabled, validate_feed_url


def active_cti(view):
    from functools import wraps
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not cti_enabled():
            return HttpResponseNotFound("CTI module disabled")
        return view(request, *args, **kwargs)
    return wrapped


@login_required
@active_cti
def inbox(request):
    status = request.GET.get("status", "new")
    items = CTIItem.objects.select_related("source").prefetch_related("matches__software").order_by("-received_at")
    if status in ("new", "reviewed", "dismissed"):
        items = items.filter(status=status)
    from django.core.paginator import Paginator
    return render(request, "vuln_manager/cti_inbox.html", {"items": Paginator(items, 30).get_page(request.GET.get("page")), "status": status, "feeds": CTIFeed.objects.all()})


@login_required
@active_cti
def detail(request, pk):
    item = get_object_or_404(CTIItem.objects.select_related("source").prefetch_related("matches__software", "findings"), pk=pk)
    include_fixed = request.GET.get("include_fixed") == "1"
    related = Vulnerability.objects.filter(cve_id__in=item.cves).select_related("host", "software")
    linked_findings = item.findings.all()
    if not include_fixed:
        related = related.exclude(status="fixed")
        linked_findings = linked_findings.exclude(status="fixed")
    related = related[:50]
    from vuln_manager.utils.debian_advisories import advisory_ids
    from vuln_manager.utils.cti_assessments import assessment_groups
    ids = advisory_ids(item)
    advisory_sources = DebianAdvisorySnapshot.objects.filter(kind__in={value[:3] for value in ids}).only("kind", "fetched_at", "error")
    snapshot = DebianTrackerSnapshot.objects.filter(pk=1).first() if item.cves and item.matches.exists() else None
    context = {"item": item, "related": related, "linked_findings": linked_findings, "include_fixed": include_fixed, "tracker_snapshot": snapshot, "advisory_ids": ids, "advisory_sources": advisory_sources, "severity_choices": Vulnerability.SEVERITY_CHOICES}
    context.update(assessment_groups(request, item, snapshot))
    return render(request, "vuln_manager/cti_detail.html", context)


@login_required
@require_POST
@active_cti
def set_status(request, pk):
    item = get_object_or_404(CTIItem, pk=pk)
    status = request.POST.get("status")
    if status not in {"new", "reviewed", "dismissed"}:
        return HttpResponse("Invalid status", status=400)
    item.status = status
    item.save(update_fields=["status"])
    return redirect("cti_detail", pk=pk)


@login_required
@require_POST
@active_cti
def create_finding(request, pk):
    item = get_object_or_404(CTIItem, pk=pk)
    software_id = request.POST.get("software", "")
    software = None
    if software_id:
        match = get_object_or_404(CTIMatch.objects.select_related("software"), item=item, software_id=software_id)
        software = match.software
    cve = (request.POST.get("cve") or "").strip().upper()
    if cve and cve not in item.cves:
        return HttpResponse("Choose a CVE from this item", status=400)
    severity = request.POST.get("severity", "info")
    if severity not in dict(Vulnerability.SEVERITY_CHOICES):
        return HttpResponse("Invalid severity", status=400)
    scan = Scan.objects.filter(scan_type="MANUAL").order_by("-uploaded_at").first()
    if scan is None:
        scan = Scan.objects.create(scan_type="MANUAL")
    vuln = create_or_update_vulnerability(scan=scan, cve_id=cve or f"CTI-{item.pk}", severity=severity, name=item.title[:255], description=f"{item.summary}\n\nSource: {item.url}", software=software, actor=f"user:{request.user.username}")
    item.findings.add(vuln)
    item.status = "reviewed"
    item.save(update_fields=["status"])
    log_vulnerability_event(vuln, "updated", user=request.user, details={"cti_item_id": item.pk, "source": item.url})
    return redirect("vuln_detail", pk=vuln.pk)


@login_required
@require_POST
def toggle_feed(request, pk):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    feed = get_object_or_404(CTIFeed, pk=pk)
    feed.enabled = not feed.enabled
    feed.save(update_fields=["enabled"])
    return redirect("extensions") if request.POST.get("from_modules") else redirect("cti_inbox")


@login_required
@require_POST
@active_cti
def refresh_feed(request, pk):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    from django.utils import timezone
    from vuln_manager.utils.cti import fetch_feed
    feed = get_object_or_404(CTIFeed, pk=pk)
    feed.last_attempt = timezone.now()
    try:
        fetch_feed(feed)
        feed.last_success = timezone.now()
        feed.last_error = ""
        # Refreshing an external advisory index can take longer than a web
        # request; continue in the background, like the other manual jobs.
        import threading
        from django.db import close_old_connections
        def enrich_background():
            close_old_connections()
            try:
                if cti_enabled():
                    from vuln_manager.utils.debian_advisories import enrich_existing_items
                    enrich_existing_items()
            finally:
                close_old_connections()
        threading.Thread(target=enrich_background, daemon=True).start()
    except Exception as exc:
        feed.last_error = str(exc)[:500]
    feed.save(update_fields=["last_attempt", "last_success", "last_error"])
    return redirect("extensions") if request.POST.get("from_modules") else redirect("cti_inbox")


@login_required
@require_POST
@active_cti
def link_finding(request, pk, vuln_pk):
    item = get_object_or_404(CTIItem, pk=pk)
    vuln = get_object_or_404(Vulnerability, pk=vuln_pk, cve_id__in=item.cves)
    item.findings.add(vuln)
    log_vulnerability_event(vuln, "updated", user=request.user, details={"cti_item_id": item.pk, "action": "linked"})
    return redirect("cti_detail", pk=pk)


@login_required
@require_POST
def save_feed(request, pk=None):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    name = request.POST.get("name", "").strip()
    url = request.POST.get("url", "").strip()
    try:
        if not name or len(name) > 100 or len(url) > 200:
            raise ValueError("Invalid feed name or URL")
        URLValidator(schemes=["https"])(url)
        validate_feed_url(url, resolve=False)
    except (ValueError, ValidationError):
        return HttpResponse("Invalid feed: use a public HTTPS URL and a name", status=400)
    if CTIFeed.objects.filter(name=name).exclude(pk=pk).exists() or CTIFeed.objects.filter(url=url).exclude(pk=pk).exists():
        return HttpResponse("Feed name or URL already exists", status=400)
    if pk:
        feed = get_object_or_404(CTIFeed, pk=pk)
        if feed.url != url:
            feed.last_success = None
        feed.name, feed.url, feed.last_attempt, feed.last_error = name, url, None, ""
        feed.save(update_fields=["name", "url", "last_attempt", "last_success", "last_error"])
    else:
        CTIFeed.objects.create(name=name, url=url)
    return redirect("extensions")


@login_required
@require_POST
def delete_feed(request, pk):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    from django.db.models.deletion import ProtectedError
    feed = get_object_or_404(CTIFeed, pk=pk)
    try:
        feed.delete()
    except ProtectedError:
        return HttpResponse("Feed has saved items; disable it to retain its history.", status=409)
    return redirect("extensions")


@login_required
def rules(request):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    return render(request, "vuln_manager/notification_rules.html", {"rules": NotificationRule.objects.all().order_by("name"), "events": NotificationRule.EVENTS, "severities": Vulnerability.SEVERITY_CHOICES, "deliveries": NotificationDelivery.objects.select_related("rule", "event").order_by("-pk")[:50]})


@login_required
@require_POST
def add_rule(request, pk=None):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    name = request.POST.get("name", "").strip()
    event = request.POST.get("event_type", "")
    severity = request.POST.get("severity", "")
    email = request.POST.get("email", "").strip()
    url = request.POST.get("webhook_url", "").strip()
    try:
        if not name or len(name) > 100 or event not in dict(NotificationRule.EVENTS) or (severity and severity not in dict(Vulnerability.SEVERITY_CHOICES)) or not (email or url):
            raise ValidationError("Invalid rule")
        if email:
            validate_email(email)
        if url:
            URLValidator(schemes=["http", "https"])(url)
    except ValidationError:
        return HttpResponse("Invalid rule, email or webhook URL", status=400)
    values = dict(name=name, event_type=event, severity=severity, critical_host=request.POST.get("critical_host") == "on", exposed_host=request.POST.get("exposed_host") == "on", email=email, webhook_url=url)
    if pk:
        from django.utils import timezone
        rule = get_object_or_404(NotificationRule, pk=pk)
        rule.deliveries.filter(status="pending").update(status="cancelled")
        for key, value in values.items():
            setattr(rule, key, value)
        rule.created_at = timezone.now()
        rule.save()
    else:
        NotificationRule.objects.create(**values, enabled=True)
    return redirect("notification_rules")


@login_required
@require_POST
def change_rule(request, pk):
    if not request.user.is_staff:
        return HttpResponseForbidden()
    rule = get_object_or_404(NotificationRule, pk=pk)
    action = request.POST.get("action")
    if action == "toggle":
        rule.enabled = not rule.enabled
        rule.save(update_fields=["enabled"])
        if not rule.enabled:
            rule.deliveries.filter(status="pending").update(status="cancelled")
    elif action == "delete":
        rule.delete()
    else:
        return HttpResponse("Invalid action", status=400)
    return redirect("notification_rules")
