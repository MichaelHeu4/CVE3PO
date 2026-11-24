from collections import defaultdict
from datetime import timedelta

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Case, Count, IntegerField, Q, Value, When
from django.shortcuts import render
from django.utils import timezone

from .models import Extension, Host, Vulnerability

ACTIVE = ("open", "in_progress", "verification")


def dashboard_counts(active, today):
    return active.aggregate(
        act=Count("id", filter=Q(ai_result="Act")),
        attend=Count("id", filter=Q(ai_result="Attend")),
        pending=Count("id", filter=Q(ai_result="tbd")),
        verification=Count("id", filter=Q(status="verification")),
        overdue=Count("id", filter=Q(due_date__lt=today)),
        soon=Count("id", filter=Q(due_date__gte=today, due_date__lte=today + timedelta(days=7))),
        no_due=Count("id", filter=Q(due_date__isnull=True)),
        triaged=Count("id", filter=~Q(ai_result="tbd")),
    )


def exposed_host_data(active, today):
    # Construct host/finding pairs from both paths; a set removes duplicates
    # when a finding is linked to a host directly and through its software.
    hosts = list(Host.objects.filter(is_exposed=True).order_by("hostname", "ip_address"))
    host_ids = {h.pk for h in hosts}
    pairs = defaultdict(set)
    for vid, hid in active.filter(host_id__in=host_ids).values_list("id", "host_id"):
        pairs[hid].add(vid)
    for vid, hid in active.filter(software__hosts__in=host_ids).values_list("id", "software__hosts"):
        pairs[hid].add(vid)
    findings = {v.pk: v for v in active.filter(pk__in={vid for ids in pairs.values() for vid in ids}).select_related("assignee")}
    host_counts = {"total": len(hosts), "act": 0, "critical": 0, "pending": 0}
    for host in hosts:
        host.dashboard_findings = [findings[vid] for vid in pairs[host.pk] if vid in findings]
        host.dashboard_findings.sort(key=lambda v: ({"Act": 0, "Attend": 1, "Track*": 2, "Track": 3}.get(v.ai_result, 4), v.due_date is None, v.due_date or today, v.pk))
        host.act_count = sum(v.ai_result == "Act" for v in host.dashboard_findings)
        host.attend_count = sum(v.ai_result == "Attend" for v in host.dashboard_findings)
        host.pending_count = sum(v.ai_result == "tbd" for v in host.dashboard_findings)
        host.critical_count = sum(v.severity == "critical" for v in host.dashboard_findings)
        host.high_count = sum(v.severity == "high" for v in host.dashboard_findings)
        host.overdue_count = sum(v.due_date is not None and v.due_date < today for v in host.dashboard_findings)
        host.needs_attention = any(v.ai_result in ("Act", "Attend") or (v.ai_result == "tbd" and v.severity in ("critical", "high")) for v in host.dashboard_findings)
        host_counts["act"] += bool(host.act_count)
        host_counts["critical"] += bool(host.critical_count)
        host_counts["pending"] += bool(host.pending_count)
    return hosts, host_counts


def ordered_findings(findings):
    findings = findings.select_related("host", "software", "assignee").prefetch_related("software__hosts").annotate(
        ai_order=Case(When(ai_result="Act", then=Value(0)), When(ai_result="Attend", then=Value(1)), When(ai_result="Track*", then=Value(2)), When(ai_result="Track", then=Value(3)), default=Value(4), output_field=IntegerField()),
        no_due_order=Case(When(due_date__isnull=True, then=Value(1)), default=Value(0), output_field=IntegerField()),
    ).order_by("ai_order", "no_due_order", "due_date", "id")
    return findings


@login_required
def dashboard(request):
    today = timezone.localdate()
    active = Vulnerability.objects.filter(status__in=ACTIVE)
    counts = dashboard_counts(active, today)
    view = request.GET.get("view", "work")
    if view not in ("work", "hosts"):
        view = "work"
    context = {"view": view, "counts": counts, "today": today,
               "ai_enabled": Extension.objects.filter(name_id="ai_triage", is_active=True).exists()}
    if view == "work":
        work_filter = request.GET.get("filter", "all")
        filters = {
            "act": Q(ai_result="Act"), "attend": Q(ai_result="Attend"),
            "pending": Q(ai_result="tbd"), "verification": Q(status="verification"),
            "mine": Q(assignee=request.user), "unassigned": Q(assignee__isnull=True),
            "overdue": Q(due_date__lt=today),
            "soon": Q(due_date__gte=today, due_date__lte=today + timedelta(days=7)),
            "no_due": Q(due_date__isnull=True),
        }
        if work_filter not in filters:
            work_filter = "all"
        findings = active.filter(filters.get(work_filter, Q()))
        query = request.GET.get("q", "").strip()
        if query:
            findings = findings.filter(Q(cve_id__icontains=query) | Q(name__icontains=query) | Q(software__name__icontains=query) | Q(host__hostname__icontains=query) | Q(host__ip_address__icontains=query)).distinct()
        findings = ordered_findings(findings)
        page = Paginator(findings, 20).get_page(request.GET.get("page"))
        for finding in page:
            hosts = {h.pk: h for h in finding.software.hosts.all()} if finding.software else {}
            if finding.host_id:
                hosts[finding.host_id] = finding.host
            finding.dashboard_hosts = list(hosts.values())
            finding.dashboard_exposed_count = sum(h.is_exposed for h in hosts.values())
        context.update(page=page, work_filter=work_filter, query=query)
    else:
        hosts, host_counts = exposed_host_data(active, today)
        scope = request.GET.get("scope", "needs")
        if scope not in ("needs", "all"):
            scope = "needs"
        query = request.GET.get("q", "").strip()
        filtered = [h for h in hosts if (scope == "all" or h.needs_attention) and (not query or query.lower() in (h.hostname or "").lower() or query.lower() in h.ip_address.lower())]
        filtered.sort(key=lambda h: (not bool(h.act_count), not bool(h.attend_count), -h.critical_count, -h.high_count, (h.hostname or h.ip_address).lower(), h.pk))
        context.update(host_counts=host_counts, scope=scope, query=query, page=Paginator(filtered, 20).get_page(request.GET.get("page")))
    return render(request, "vuln_manager/operational_dashboard.html", context)
