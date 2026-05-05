from django.core.paginator import Paginator
from django.views.decorators.http import require_POST
from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Count, Q, Max, Case, When, Value, IntegerField, Avg
from .models import (
    Host,
    Port,
    Vulnerability,
    VulnerabilityAuditEvent,
    Scan,
    Software,
    Extension,
    SystemSettings,
)
from .parser import nmap
from .parser import nuclei
from .parser import openvas
from .parser import osvscanner
from .parser import semgrep
from .utils import ai_triage
from .utils.audit import log_vulnerability_event
from .utils.vuln_dedup import create_or_update_vulnerability
from .utils.osv_auto import enrich_software_with_feeds
from .utils.enrichment import get_cve_details
from .extensions import wrike as wrike_ext
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.utils.http import url_has_allowed_host_and_scheme
import io
from django.http import FileResponse, HttpResponse, HttpResponseForbidden, JsonResponse
from django.utils.timezone import now
from datetime import timedelta
import re

from xhtml2pdf import pisa
from django.template.loader import render_to_string
import json
import threading

CRITICALITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    None: 0,
    "": 0,
}


def get_system_settings():
    settings_obj, _ = SystemSettings.objects.get_or_create(
        pk=1, defaults={"disable_register": settings.DISABLE_REGISTER}
    )
    return settings_obj


def get_wrike_config():
    settings_obj = get_system_settings()
    wrike_extension, _ = Extension.objects.get_or_create(name_id="wrike")
    return wrike_extension, settings_obj


def get_ai_triage_config():
    settings_obj = get_system_settings()
    ai_extension, _ = Extension.objects.get_or_create(name_id="ai_triage")
    return ai_extension, settings_obj


def login_view(request):
    next_url = request.GET.get("next", "dashboard")
    error_message = None
    login_identifier = ""
    if not url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = "dashboard"
    if request.user.is_authenticated:
        return redirect(next_url)
    if request.method == "POST":
        login_identifier = (
            request.POST.get("identifier") or request.POST.get("email") or ""
        ).strip()
        password = request.POST.get("password") or ""

        if not login_identifier or not password:
            error_message = "Please provide username/email and password."
            return render(
                request,
                "vuln_manager/login.html",
                {
                    "login_error": error_message,
                    "login_identifier": login_identifier,
                },
            )

        user = authenticate(request, username=login_identifier, password=password)
        if user is None and "@" in login_identifier:
            user_by_email = User.objects.filter(email__iexact=login_identifier).first()
            if user_by_email:
                user = authenticate(
                    request, username=user_by_email.username, password=password
                )
        if user is not None:
            login(request, user)
            return redirect(next_url)
        error_message = "Invalid credentials. Please check username/email and password."
    return render(
        request,
        "vuln_manager/login.html",
        {
            "login_error": error_message,
            "login_identifier": login_identifier,
        },
    )


def register_view(request):
    system_settings = get_system_settings()
    if system_settings.disable_register:
        print("[*] Someone tried to register...")
        return redirect("login")
    if request.user.is_authenticated:
        return redirect("dashboard")
    if request.method == "POST":
        username = request.POST.get("email")
        password = request.POST.get("password")
        user = User.objects.create_user(username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("dashboard")
    return render(request, "vuln_manager/register.html")


@login_required
def logout_view(request):
    logout(request)
    return redirect("login")


def recalculate_host_criticality(host):
    max_weight = CRITICALITY_WEIGHTS.get(host.criticality, 0)
    for sw in host.software_inventory.all():
        sw_weight = CRITICALITY_WEIGHTS.get(sw.criticality, 0)
        if sw_weight > max_weight:
            max_weight = sw_weight
            host.criticality = sw.criticality
    host.save()


def _build_dashboard_report_context():
    all_vulns = Vulnerability.objects.exclude(status__in=["fixed", "false_positive"])
    critical_count = all_vulns.filter(severity="critical").count()
    high_count = all_vulns.filter(severity="high").count()
    host_count = Host.objects.count()
    vuln_hosts_count = (
        Host.objects.filter(
            Q(vulnerabilities__in=all_vulns)
            | Q(software_inventory__vulnerabilities__in=all_vulns)
        )
        .distinct()
        .count()
    )
    avg_proc_time_ms = (
        Vulnerability.objects.filter(ai_proc_time__gt=0).aggregate(Avg("ai_proc_time"))[
            "ai_proc_time__avg"
        ]
        or 0
    )
    resolved_count = Vulnerability.objects.filter(status="fixed").count()
    total_non_fp = Vulnerability.objects.exclude(status="false_positive").count()
    remediation_rate = round((resolved_count / total_non_fp) * 100, 1) if total_non_fp else 0
    exposure_rate = round((vuln_hosts_count / host_count) * 100, 1) if host_count else 0
    avg_open_age_days = 0
    open_ages = [
        max((now() - opened_at).days, 0)
        for opened_at in all_vulns.values_list("first_seen", flat=True)
        if opened_at
    ]
    if open_ages:
        avg_open_age_days = round(sum(open_ages) / len(open_ages), 1)
    oldest_open_days = max(open_ages) if open_ages else 0
    sla_breach_count = all_vulns.filter(
        Q(severity="critical", first_seen__lt=now() - timedelta(days=7))
        | Q(severity="high", first_seen__lt=now() - timedelta(days=30))
    ).count()
    reopened_30d = VulnerabilityAuditEvent.objects.filter(
        action="reopened", created_at__gte=now() - timedelta(days=30)
    ).count()

    top_hosts = Host.objects.annotate(
        num_vulns=Count(
            "vulnerabilities",
            filter=~Q(vulnerabilities__status__in=["fixed", "false_positive"]),
        )
    ).order_by("-num_vulns")[:5]
    top_software = (
        Software.objects.annotate(
            num_vulns=Count(
                "vulnerabilities",
                filter=~Q(vulnerabilities__status__in=["fixed", "false_positive"]),
            )
        )
        .filter(num_vulns__gt=0)
        .order_by("-num_vulns", "name")[:5]
    )

    recent_vulns = (
        Vulnerability.objects.filter(severity__in=["critical", "high"])
        .exclude(status__in=["fixed", "false_positive"])
        .order_by("-id")[:5]
    )

    return {
        "report_date": now(),
        "metrics": {
            "host_count": host_count,
            "vuln_count": all_vulns.count(),
            "critical_count": critical_count,
            "high_count": high_count,
            "vuln_hosts_count": vuln_hosts_count,
            "mttt": round(avg_proc_time_ms / 1000, 2),
            "resolved_count": resolved_count,
            "remediation_rate": remediation_rate,
            "exposure_rate": exposure_rate,
            "avg_open_age_days": avg_open_age_days,
            "oldest_open_days": oldest_open_days,
            "sla_breach_count": sla_breach_count,
            "reopened_30d": reopened_30d,
        },
        "top_hosts": top_hosts,
        "top_software": top_software,
        "recent_vulns": recent_vulns,
    }


def _render_dashboard_pdf_buffer():
    context = _build_dashboard_report_context()
    html = render_to_string("vuln_manager/report_pdf.html", context)
    buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=buffer)
    if pisa_status.err:
        return None
    buffer.seek(0)
    return buffer


@login_required
def export_dashboard_pdf(request):
    buffer = _render_dashboard_pdf_buffer()
    if buffer is None:
        return HttpResponse("Fehler bei der PDF-Erstellung", status=500)
    return FileResponse(
        buffer,
        as_attachment=True,
        filename=f"cve3po_report_{now().strftime('%Y%m%d')}.pdf",
    )


@login_required
def dashboard(request):
    host_count = Host.objects.count()
    latest_port_ids = Port.objects.values("host").annotate(
        latest_scan_id=Max("scan_id")
    )
    port_count = Port.objects.filter(
        scan_id__in=[
            item["latest_scan_id"] for item in latest_port_ids if item["latest_scan_id"]
        ]
    ).count()

    # Open vulnerabilities (excluding fixed/fp/info)
    all_open_vulns = Vulnerability.objects.exclude(
        status__in=["fixed", "false_positive"]
    )
    vuln_count = all_open_vulns.exclude(severity="info").count()
    resolved_count = Vulnerability.objects.filter(status="fixed").count()
    ignored_count = Vulnerability.objects.filter(status="risk_accepted").count()
    total_non_fp = Vulnerability.objects.exclude(status="false_positive").count()
    remediation_rate = round((resolved_count / total_non_fp) * 100, 1) if total_non_fp else 0
    impacted_assets_count = (
        Host.objects.filter(
            Q(vulnerabilities__in=all_open_vulns)
            | Q(software_inventory__vulnerabilities__in=all_open_vulns)
        )
        .distinct()
        .count()
    )
    exposure_rate = round((impacted_assets_count / host_count) * 100, 1) if host_count else 0
    open_ages = [
        max((now() - opened_at).days, 0)
        for opened_at in all_open_vulns.values_list("first_seen", flat=True)
        if opened_at
    ]
    avg_open_age_days = round(sum(open_ages) / len(open_ages), 1) if open_ages else 0
    oldest_open_days = max(open_ages) if open_ages else 0
    sla_breach_count = all_open_vulns.filter(
        Q(severity="critical", first_seen__lt=now() - timedelta(days=7))
        | Q(severity="high", first_seen__lt=now() - timedelta(days=30))
    ).count()
    reopened_30d = VulnerabilityAuditEvent.objects.filter(
        action="reopened", created_at__gte=now() - timedelta(days=30)
    ).count()

    # Severity distribution
    vuln_stats = all_open_vulns.values("severity").annotate(count=Count("id"))
    severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for stat in vuln_stats:
        severity_map[stat["severity"].lower()] = stat["count"]

    # Security Score Calculation
    # Critical=10, High=5, Medium=2, Low=1
    risk_points = (
        severity_map["critical"] * 10
        + severity_map["high"] * 5
        + severity_map["medium"] * 2
        + severity_map["low"] * 1
    )

    if host_count > 0:
        # Score starts at 100, drops based on risk density.
        score = max(0, 100 - (risk_points / (host_count * 0.5)))
    else:
        score = 100

    # Vulnerability Trend (Last 14 days)
    # We want to show "Active" vs "Fixed"
    trend_labels = []
    trend_open = []
    trend_fixed = []

    import datetime
    today = datetime.date.today()
    for i in range(13, -1, -1):
        day = today - datetime.timedelta(days=i)
        trend_labels.append(day.strftime("%d.%m"))

        # Open on that day (created before or on that day, and not fixed or fixed AFTER that day)
        open_count = (
            Vulnerability.objects.filter(scan__uploaded_at__date__lte=day)
            .exclude(
                status__in=["fixed", "false_positive"],
            )
            .count()
        )

        fixed_count = Vulnerability.objects.filter(
            status="fixed", scan__uploaded_at__date__lte=day
        ).count()

        trend_open.append(open_count)
        trend_fixed.append(fixed_count)

    # Top Risky Assets (Weighted)
    top_hosts = (
        Host.objects.annotate(
            risk_score=Count(
                "vulnerabilities", filter=Q(vulnerabilities__severity="critical")
            )
            * 10
            + Count("vulnerabilities", filter=Q(vulnerabilities__severity="high")) * 5
            + Count("vulnerabilities", filter=Q(vulnerabilities__severity="medium")) * 2
        )
        .filter(risk_score__gt=0)
        .order_by("-risk_score")[:5]
    )

    recent_vulns = all_open_vulns.select_related("host").order_by("-id")[:5]
    top_software = (
        Software.objects.annotate(
            active_vulns=Count(
                "vulnerabilities",
                filter=~Q(vulnerabilities__status__in=["fixed", "false_positive"]),
            )
        )
        .filter(active_vulns__gt=0)
        .order_by("-active_vulns", "name")[:5]
    )

    top_ports = (
        Port.objects.filter(
            scan_id__in=[
                item["latest_scan_id"]
                for item in latest_port_ids
                if item["latest_scan_id"]
            ]
        )
        .values("port_number", "service_name")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )

    software_count = Software.objects.count()

    avg_proc_time_ms = (
        Vulnerability.objects.filter(ai_proc_time__gt=0).aggregate(Avg("ai_proc_time"))[
            "ai_proc_time__avg"
        ]
        or 0
    )
    ai_context = {
        "proc_time": round(avg_proc_time_ms / 1000, 2),
    }
    status_map = {
        "open": Vulnerability.objects.filter(status="open").count(),
        "in_progress": Vulnerability.objects.filter(status="in_progress").count(),
        "fixed": resolved_count,
        "risk_accepted": ignored_count,
        "false_positive": Vulnerability.objects.filter(status="false_positive").count(),
    }

    context = {
        "host_count": host_count,
        "port_count": port_count,
        "vuln_count": vuln_count,
        "severity_map": severity_map,
        "score": round(score),
        "trend_labels": json.dumps(trend_labels),
        "trend_open": json.dumps(trend_open),
        "trend_fixed": json.dumps(trend_fixed),
        "top_hosts": top_hosts,
        "top_software": top_software,
        "recent_vulns": recent_vulns,
        "top_ports": top_ports,
        "software_count": software_count,
        "ai": ai_context,
        "resolved_count": resolved_count,
        "ignored_count": ignored_count,
        "impacted_assets_count": impacted_assets_count,
        "exposure_rate": exposure_rate,
        "remediation_rate": remediation_rate,
        "avg_open_age_days": avg_open_age_days,
        "oldest_open_days": oldest_open_days,
        "sla_breach_count": sla_breach_count,
        "reopened_30d": reopened_30d,
        "status_map": status_map,
        "user": User.objects.get(pk=request.user.id),
    }
    return render(request, "vuln_manager/dashboard.html", context)


@login_required
def host_list(request):
    hosts_query = Host.objects.all().order_by("ip_address")

    # Pagination
    paginator = Paginator(hosts_query, 25)  # 25 per page
    page_number = request.GET.get("page")
    hosts = paginator.get_page(page_number)

    for host in hosts:
        latest_scan = host.ports.aggregate(latest=Max("scan_id"))["latest"]
        host.current_port_count = (
            host.ports.filter(scan_id=latest_scan).count() if latest_scan else 0
        )
        inherited_q = (
            Vulnerability.objects.filter(Q(host=host) | Q(software__hosts=host))
            .exclude(status__in=["fixed", "false_positive"])
            .distinct()
        )
        host.num_vulns = inherited_q.exclude(severity="info").count()
        host.num_info = inherited_q.filter(severity="info").count()
    return render(request, "vuln_manager/host_list.html", {"hosts": hosts})


@login_required
def host_detail(request, pk):
    host = get_object_or_404(Host, pk=pk)
    latest_scan_id = host.ports.aggregate(latest=Max("scan_id"))["latest"]
    active_ports = host.ports.filter(scan_id=latest_scan_id).order_by("port_number")
    historic_ports = (
        host.ports.exclude(scan_id=latest_scan_id)
        .values("port_number", "service_name")
        .distinct()
    )
    active_port_nums = [p.port_number for p in active_ports]
    closed_ports = [
        p for p in historic_ports if p["port_number"] not in active_port_nums
    ]
    show_mode = request.GET.get("mode", "all")
    severity_filter = (request.GET.get("severity") or "").lower()
    allowed_severities = {choice[0] for choice in Vulnerability.SEVERITY_CHOICES}
    if severity_filter and severity_filter not in allowed_severities:
        severity_filter = ""
    if show_mode == "direct":
        vulns_query = host.vulnerabilities.exclude(status="false_positive").order_by(
            "-severity"
        )
    else:
        vulns_query = (
            Vulnerability.objects.filter(Q(host=host) | Q(software__hosts=host))
            .exclude(status="false_positive")
            .distinct()
            .order_by("-severity")
        )
    if severity_filter:
        vulns_query = vulns_query.filter(severity=severity_filter)

    # Paginate Threats
    vuln_paginator = Paginator(vulns_query, 20)
    vuln_page_number = request.GET.get("vuln_page")
    vulns = vuln_paginator.get_page(vuln_page_number)
    host_timeline_raw = (
        host.vulnerabilities.exclude(status="false_positive")
        .values("scan__id", "scan__uploaded_at")
        .annotate(count=Count("id"))
        .order_by("scan__uploaded_at")
    )
    host_timeline_labels = [
        item["scan__uploaded_at"].strftime("%d.%m %H:%M") for item in host_timeline_raw
    ]
    host_timeline_values = [item["count"] for item in host_timeline_raw]

    # Software Inventory with Pagination
    sw_query = host.software_inventory.annotate(
        active_vulns=Count(
            "vulnerabilities",
            filter=(
                Q(vulnerabilities__host=host) | Q(vulnerabilities__software__hosts=host)
            )
            & ~Q(vulnerabilities__status__in=["fixed", "false_positive"]),
        )
    ).order_by("name")

    sw_paginator = Paginator(sw_query, 20)
    sw_page_number = request.GET.get("sw_page")
    installed_software = sw_paginator.get_page(sw_page_number)

    active_tab = request.GET.get("tab", "threats")

    return render(
        request,
        "vuln_manager/host_detail.html",
        {
            "host": host,
            "active_ports": active_ports,
            "closed_ports": closed_ports,
            "vulns": vulns,
            "timeline_labels": json.dumps(host_timeline_labels),
            "timeline_values": json.dumps(host_timeline_values),
            "installed_software": installed_software,
            "show_mode": show_mode,
            "severity_filter": severity_filter,
            "severity_choices": Vulnerability.SEVERITY_CHOICES,
            "active_tab": active_tab,
            "criticality_choices": Host.CRITICALITY_CHOICES,
        },
    )


@login_required
def software_list(request):
    software_query = Software.objects.annotate(num_hosts=Count("hosts")).order_by(
        "name"
    )

    paginator = Paginator(software_query, 25)
    page_number = request.GET.get("page")
    software = paginator.get_page(page_number)

    return render(request, "vuln_manager/software_list.html", {"software": software})


@login_required
def software_detail(request, pk):
    item = get_object_or_404(Software, pk=pk)
    hosts = item.hosts.all()
    severity_filter = (request.GET.get("severity") or "").lower()
    allowed_severities = {choice[0] for choice in Vulnerability.SEVERITY_CHOICES}
    if severity_filter and severity_filter not in allowed_severities:
        severity_filter = ""
    vulns = (
        Vulnerability.objects.filter(software=item)
        .exclude(status="false_positive")
        .order_by("-severity")
    )
    if severity_filter:
        vulns = vulns.filter(severity=severity_filter)
    return render(
        request,
        "vuln_manager/software_detail.html",
        {
            "software": item,
            "hosts": hosts,
            "vulns": vulns,
            "severity_filter": severity_filter,
            "severity_choices": Vulnerability.SEVERITY_CHOICES,
            "criticality_choices": Software.CRITICALITY_CHOICES,
            "osv_rescan_possible": bool(item.version),
        },
    )


@login_required
@require_POST
def software_rescan_osv(request, pk):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    sw = get_object_or_404(Software, pk=pk)
    if not sw.version:
        return HttpResponseForbidden("missing_version")

    worker = threading.Thread(target=enrich_software_with_feeds, args=(sw.id,), daemon=True)
    worker.start()
    return redirect("software_detail", pk=pk)


@login_required
def software_form(request, pk=None):
    sw = None
    if pk:
        sw = get_object_or_404(Software, pk=pk)

    if request.method == "POST":
        name = request.POST.get("name")
        version = request.POST.get("version")
        vendor = request.POST.get("vendor")
        port = request.POST.get("listening_port")
        criticality = request.POST.get("criticality")
        host_ids = request.POST.getlist("hosts")

        if sw:
            sw.name = name
            sw.version = version
            sw.vendor = vendor
            sw.listening_port = port if port else None
            sw.criticality = criticality if criticality else None
            sw.save()
        else:
            sw = Software.objects.create(
                name=name,
                version=version,
                vendor=vendor,
                listening_port=port if port else None,
                criticality=criticality if criticality else None,
            )

        if host_ids:
            sw.hosts.set(host_ids)
            for host in sw.hosts.all():
                recalculate_host_criticality(host)
        else:
            sw.hosts.clear()

        return redirect("software_list")

    hosts = Host.objects.all().order_by("ip_address")
    return render(
        request,
        "vuln_manager/software_form.html",
        {
            "hosts": hosts,
            "software": sw,
            "criticality_choices": Software.CRITICALITY_CHOICES,
        },
    )


@login_required
def update_software_criticality(request, pk):
    if request.method == "POST":
        sw = get_object_or_404(Software, pk=pk)
        criticality = request.POST.get("criticality")
        sw.criticality = criticality if criticality != "" else None
        sw.save()
        for host in sw.hosts.all():
            recalculate_host_criticality(host)
    return redirect("software_detail", pk=pk)


@login_required
def delete_software(request, pk):
    if request.method == "POST":
        sw = get_object_or_404(Software, pk=pk)
        sw.delete()
    return redirect("software_list")


@login_required
def remove_host_from_software(request, software_pk, host_pk):
    if request.method == "POST":
        sw = get_object_or_404(Software, pk=software_pk)
        host = get_object_or_404(Host, pk=host_pk)
        sw.hosts.remove(host)
        recalculate_host_criticality(host)
    return redirect("software_detail", pk=software_pk)


@login_required
def update_host_criticality(request, pk):
    if request.method == "POST":
        host = get_object_or_404(Host, pk=pk)
        criticality = request.POST.get("criticality")
        host.criticality = criticality if criticality != "" else None
        host.save()
        recalculate_host_criticality(host)
    return redirect("host_detail", pk=pk)


@login_required
def vuln_add(request):
    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        cve_id = request.POST.get("cve_id")
        severity = request.POST.get("severity")
        name = request.POST.get("name")
        description = request.POST.get("description")
        poc = request.POST.get("poc")
        software_id = request.POST.get("software")
        host_obj = None
        if ip_address:
            host_obj, _ = Host.objects.get_or_create(ip_address=ip_address)
        manual_scan = (
            Scan.objects.filter(scan_type="MANUAL").order_by("-uploaded_at").first()
        )
        if not manual_scan:
            manual_scan = Scan.objects.create(scan_type="MANUAL")
        sw_obj = Software.objects.get(pk=software_id) if software_id else None
        vuln = create_or_update_vulnerability(
            host=host_obj,
            scan=manual_scan,
            software=sw_obj,
            cve_id=cve_id,
            severity=severity,
            name=name,
            description=description,
            nuclei_poc=poc,
            actor=f"user:{request.user.username}",
        )
        log_vulnerability_event(
            vuln, "updated", user=request.user, details={"source": "manual_entry"}
        )
        if host_obj:
            return redirect("host_detail", pk=host_obj.id)
        elif sw_obj:
            return redirect("software_detail", pk=sw_obj.id)
        return redirect("dashboard")
    return render(
        request,
        "vuln_manager/vuln_form.html",
        {
            "severity_choices": Vulnerability.SEVERITY_CHOICES,
            "software_list": Software.objects.all().order_by("name"),
        },
    )


@login_required
def delete_vulnerability(request, pk):
    if request.method == "POST":
        vuln = get_object_or_404(Vulnerability, pk=pk)
        host_id = vuln.host.id if vuln.host else None
        log_vulnerability_event(
            vuln,
            "deleted",
            user=request.user,
            details={"cve_id": vuln.cve_id, "name": vuln.name},
        )
        vuln.delete()
        if host_id:
            return redirect("host_detail", pk=host_id)
    return redirect("dashboard")


@login_required
def host_form(request, pk=None):
    host_obj = None
    if pk:
        host_obj = get_object_or_404(Host, pk=pk)

    if request.method == "POST":
        ip_address = request.POST.get("ip_address")
        hostname = request.POST.get("hostname")
        operating_system = request.POST.get("operating_system")
        criticality = request.POST.get("criticality")

        if not host_obj:
            host_obj = Host(ip_address=ip_address)
        else:
            host_obj.ip_address = ip_address

        host_obj.hostname = hostname
        host_obj.operating_system = operating_system
        host_obj.criticality = criticality
        host_obj.save()
        return redirect("host_list")

    context = {
        "host_obj": host_obj,
        "criticality_choices": Host.CRITICALITY_CHOICES,
    }
    return render(request, "vuln_manager/host_form.html", context)


@login_required
def port_list(request):
    latest_scan_ids = Port.objects.values("host").annotate(latest=Max("scan_id"))
    active_port_ids = [item["latest"] for item in latest_scan_ids if item["latest"]]
    active_ports = (
        Port.objects.filter(scan_id__in=active_port_ids)
        .select_related("host")
        .order_by("port_number")
    )
    port_groups = {}
    for port in active_ports:
        key = (port.port_number, port.service_name)
        if key not in port_groups:
            port_groups[key] = []
        port_groups[key].append(port.host)
    sorted_ports = sorted(port_groups.items(), key=lambda x: x[0][0])
    return render(request, "vuln_manager/port_list.html", {"port_groups": sorted_ports})


@login_required
def scan_list(request):
    scans = list(
        Scan.objects.annotate(num_vulns=Count("vulnerabilities")).order_by("-uploaded_at")
    )
    last_by_type = {}
    for scan in reversed(scans):
        scan.previous_same_type = last_by_type.get(scan.scan_type)
        last_by_type[scan.scan_type] = scan
    return render(request, "vuln_manager/scan_list.html", {"scans": scans})


@login_required
def scan_diff(request, pk):
    severity_order = Case(
        When(severity__iexact="critical", then=Value(5)),
        When(severity__iexact="high", then=Value(4)),
        When(severity__iexact="medium", then=Value(3)),
        When(severity__iexact="low", then=Value(2)),
        When(severity__iexact="info", then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    )

    current_scan = get_object_or_404(Scan, pk=pk)
    previous_scan = (
        Scan.objects.filter(
            scan_type=current_scan.scan_type, uploaded_at__lt=current_scan.uploaded_at
        )
        .order_by("-uploaded_at")
        .first()
    )
    next_scan = (
        Scan.objects.filter(
            scan_type=current_scan.scan_type, uploaded_at__gt=current_scan.uploaded_at
        )
        .order_by("uploaded_at")
        .first()
    )

    window_end = next_scan.uploaded_at if next_scan else now()

    new_findings = Vulnerability.objects.none()
    reopened_findings = Vulnerability.objects.none()
    fixed_findings = Vulnerability.objects.none()

    if previous_scan:
        current_detected = (
            Vulnerability.objects.filter(scan=current_scan)
            .exclude(status="false_positive")
            .annotate(sev_score=severity_order)
            .select_related("host", "software")
        )

        new_findings = current_detected.filter(
            first_seen__gt=previous_scan.uploaded_at
        ).order_by("-sev_score", "cve_id")

        reopened_findings = (
            current_detected.filter(
                audit_events__action="reopened",
                audit_events__created_at__gt=previous_scan.uploaded_at,
                audit_events__created_at__lte=window_end,
            )
            .distinct()
            .order_by("-sev_score", "cve_id")
        )

        fixed_findings = (
            Vulnerability.objects.filter(
                audit_events__action="status_changed",
                audit_events__details__to_status="fixed",
                audit_events__created_at__gt=previous_scan.uploaded_at,
                audit_events__created_at__lte=window_end,
            )
            .exclude(status="false_positive")
            .annotate(sev_score=severity_order)
            .select_related("host", "software")
            .distinct()
            .order_by("-sev_score", "cve_id")
        )

    context = {
        "current_scan": current_scan,
        "previous_scan": previous_scan,
        "next_scan": next_scan,
        "new_findings": new_findings,
        "reopened_findings": reopened_findings,
        "fixed_findings": fixed_findings,
        "summary": {
            "new_count": new_findings.count(),
            "reopened_count": reopened_findings.count(),
            "fixed_count": fixed_findings.count(),
        },
    }
    return render(request, "vuln_manager/scan_diff.html", context)


@login_required
def kanban_board(request):
    severity_order = Case(
        When(severity__iexact="critical", then=Value(5)),
        When(severity__iexact="high", then=Value(4)),
        When(severity__iexact="medium", then=Value(3)),
        When(severity__iexact="low", then=Value(2)),
        When(severity__iexact="info", then=Value(1)),
        default=Value(0),
        output_field=IntegerField(),
    )
    vulns = Vulnerability.objects.select_related("host").annotate(
        sev_score=severity_order
    )
    severity_filter = (request.GET.get("severity") or "").lower()
    allowed_severities = {choice[0] for choice in Vulnerability.SEVERITY_CHOICES}
    if severity_filter and severity_filter not in allowed_severities:
        severity_filter = ""
    if severity_filter:
        vulns = vulns.filter(severity=severity_filter)
    board_data = {
        "open": vulns.filter(status="open").order_by("-sev_score", "cve_id"),
        "in_progress": vulns.filter(status="in_progress").order_by(
            "-sev_score", "cve_id"
        ),
        "fixed": vulns.filter(status="fixed").order_by("-sev_score", "cve_id"),
        "risk_accepted": vulns.filter(status="risk_accepted").order_by(
            "-sev_score", "cve_id"
        ),
        "false_positive": vulns.filter(status="false_positive").order_by(
            "-sev_score", "cve_id"
        ),
    }
    return render(
        request,
        "vuln_manager/kanban_board.html",
        {
            "board": board_data,
            "severity_filter": severity_filter,
            "severity_choices": Vulnerability.SEVERITY_CHOICES,
        },
    )


@login_required
def update_vuln_status(request, pk):
    if request.method == "POST":
        vuln = get_object_or_404(Vulnerability, pk=pk)
        new_status = request.POST.get("status")
        if not new_status and request.content_type == "application/json":
            try:
                payload = json.loads(request.body or "{}")
                new_status = payload.get("status")
            except json.JSONDecodeError:
                new_status = None
        if new_status in dict(Vulnerability.STATUS_CHOICES):
            old_status = vuln.status
            vuln.status = new_status
            vuln.save()
            if old_status != new_status:
                log_vulnerability_event(
                    vuln,
                    "status_changed",
                    user=request.user,
                    details={"from_status": old_status, "to_status": new_status},
                )
        if request.content_type == "application/json":
            return JsonResponse({"status": "ok"}, status=200)
        referer = request.META.get("HTTP_REFERER")
        if referer and url_has_allowed_host_and_scheme(
            url=referer,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        ):
            return redirect(referer)
    return redirect("kanban_board")


@login_required
def vuln_list(request):
    severity = (request.GET.get("severity") or "").lower()
    allowed_severities = {choice[0] for choice in Vulnerability.SEVERITY_CHOICES}
    if severity and severity not in allowed_severities:
        severity = ""
    status_filter = request.GET.get("status", "active")
    active_vulns = Vulnerability.objects.exclude(status="false_positive")

    if status_filter == "resolved":
        vulns_query = active_vulns.filter(status="fixed")
    elif status_filter == "ignored":
        vulns_query = active_vulns.filter(status="risk_accepted")
    else:
        vulns_query = active_vulns.exclude(status="fixed")

    if severity:
        vulns_query = vulns_query.filter(severity=severity.lower())

    vulns_query = vulns_query.order_by("-severity", "cve_id")

    # Pagination
    paginator = Paginator(vulns_query, 50)  # 50 per page for vulns
    page_number = request.GET.get("page")
    vulns = paginator.get_page(page_number)

    metrics = {
        "critical": active_vulns.filter(severity="critical").count(),
        "high": active_vulns.filter(severity="high").count(),
        "impacted_assets": Host.objects.filter(vulnerabilities__in=active_vulns)
        .distinct()
        .count(),
        "assets_total": Host.objects.distinct().count(),
        "software_total": Software.objects.distinct().count(),
        "impacted_software": Software.objects.filter(vulnerabilities__in=active_vulns)
        .distinct()
        .count(),
    }
    return render(
        request,
        "vuln_manager/vuln_list.html",
        {
            "vulns": vulns,
            "severity": severity,
            "severity_choices": Vulnerability.SEVERITY_CHOICES,
            "status_filter": status_filter,
            "metrics": metrics,
        },
    )


@login_required
def vuln_detail(request, pk):
    vuln = get_object_or_404(
        Vulnerability.objects.select_related("host", "scan"), pk=pk
    )
    wrike_extension, settings_obj = get_wrike_config()
    wrike_ready = (
        wrike_extension.is_active
        and bool(wrike_extension.api_token)
        and bool(settings_obj.wrike_folder_id)
    )
    return render(
        request,
        "vuln_manager/vuln_detail.html",
        {
            "vuln": vuln,
            "wrike_ready": wrike_ready,
            "audit_events": VulnerabilityAuditEvent.objects.filter(vulnerability=vuln)
            .order_by("-created_at")[:20],
        },
    )


@login_required
def scan_import(request):
    sw_id = request.GET.get("software")
    pre_sw = get_object_or_404(Software, pk=sw_id) if sw_id else None
    if request.method == "POST":
        scan_type = request.POST.get("scan_type")
        raw_file = request.FILES.get("raw_file")
        software_id = request.POST.get("software_id")
        sw_obj = Software.objects.get(pk=software_id) if software_id else None
        if scan_type and raw_file:
            scan_obj = Scan.objects.create(scan_type=scan_type, raw_file=raw_file)
            file_path = scan_obj.raw_file.path
            if scan_type == "NMAP":
                nmap.parse_nmap_xml(file_path, scan_obj)
            elif scan_type == "NUCLEI":
                nuclei.parse_nuclei_jsonl(file_path, scan_obj)
            elif scan_type == "OPENVAS":
                openvas.parse_openvas_xml(file_path, scan_obj)
            elif scan_type == "SEMGREP":
                semgrep.parse_semgrep_json(file_path, scan_obj, software_obj=sw_obj)
            elif scan_type == "OSV":
                osvscanner.parse_osv_json(file_path, scan_obj, software_obj=sw_obj)
            if sw_obj:
                return redirect("software_detail", pk=sw_obj.id)
            return redirect("dashboard")
    context = {
        "pre_sw": pre_sw,
        "software_list": Software.objects.all().order_by("name"),
    }
    return render(request, "vuln_manager/scan_import.html", context)


@login_required
def delete_host(request, pk):
    if request.method == "POST":
        host = get_object_or_404(Host, pk=pk)
        host.delete()
        return redirect("host_list")
    return redirect("host_detail", pk=pk)


@login_required
def delete_scan(request, pk):
    if request.method == "POST":
        scan = get_object_or_404(Scan, pk=pk)
        scan.delete()
    return redirect("scan_list")


@login_required
def ki_dashboard(request):
    selected_vuln_id = request.GET.get("selected_vuln")
    selected_vuln = None
    if selected_vuln_id:
        selected_vuln = get_object_or_404(Vulnerability, pk=selected_vuln_id)

    all_vulns_query = (
        Vulnerability.objects.exclude(status="false_positive")
        .order_by("-severity", "cve_id")
        .distinct()
    )

    # AI Stats
    triaged_vulns = all_vulns_query.exclude(ai_result="tbd").count()
    action_required = all_vulns_query.filter(ai_result="Act").count()
    avg_proc_time_ms = (
        Vulnerability.objects.filter(ai_proc_time__gt=0).aggregate(Avg("ai_proc_time"))[
            "ai_proc_time__avg"
        ]
        or 0
    )

    # Pagination
    paginator = Paginator(all_vulns_query, 25)  # 25 per page
    page_number = request.GET.get("page")
    all_vulns = paginator.get_page(page_number)

    ai_extension, settings_obj = get_ai_triage_config()
    provider = (settings_obj.ai_triage_provider or "openrouter").lower()
    if not ai_extension.is_active:
        model_label = "Disabled"
    elif provider == "azure":
        model_label = f"Azure AI · {settings_obj.ai_azure_model or 'N/A'}"
    else:
        model_label = f"OpenRouter · {settings_obj.ai_openrouter_model or 'N/A'}"
    ai = {"model": model_label, "proc_time": round(avg_proc_time_ms / 1000, 2)}
    context = {
        "triaged_vulns": triaged_vulns,
        "all_vulns": all_vulns,
        "action_required": action_required,
        "ai": ai,
        "ai_module_active": ai_extension.is_active,
        "selected_vuln": selected_vuln,
    }
    return render(request, "vuln_manager/ki_dashboard.html", context)


@login_required
def extensions_view(request):
    # Metadata for active modules
    module_metadata = {
        "agent_api": {
            "name": "CVE3PO Agent",
            "description": "Activates the CVE3PO Agent API and lets you use the CVE3PO Agent to retrieve the SBOM of Server",
            "icon": "api",
            "color": "tertiary",
        },
        "wazuh": {
            "name": "Wazuh Connector",
            "description": "Real-time vulnerability streaming via webhooks. Automatically creates hosts and manages vulnerability lifecycles.",
            "icon": "webhook",
            "color": "primary",
        },
        "wrike": {
            "name": "Wrike Ticketing",
            "description": "Creates Wrike tasks from vulnerabilities and syncs completion status.",
            "icon": "assignment",
            "color": "secondary",
        },
        "ai_triage": {
            "name": "AI Triage",
            "description": "Runs SSVC-based vulnerability triage with selectable AI backend.",
            "icon": "psychology",
            "color": "secondary",
        },
        "email_reporting": {
            "name": "Email Reporting",
            "description": "Sends PDF dashboard reports to configured recipients.",
            "icon": "mail",
            "color": "primary",
        },
    }

    modules = []
    system_settings = get_system_settings()
    for mid, meta in module_metadata.items():
        ext, _ = Extension.objects.get_or_create(name_id=mid)
        modules.append(
            {
                "id": mid,
                "name": meta["name"],
                "description": meta["description"],
                "is_active": ext.is_active,
                "api_token": ext.api_token if request.user.is_staff else None,
                "wrike_folder_id": (
                    system_settings.wrike_folder_id if mid == "wrike" else None
                ),
                "email_report_recipients": (
                    system_settings.email_report_recipients
                    if mid == "email_reporting"
                    else None
                ),
                "ai_triage_provider": (
                    system_settings.ai_triage_provider if mid == "ai_triage" else None
                ),
                "ai_openrouter_model": (
                    system_settings.ai_openrouter_model if mid == "ai_triage" else None
                ),
                "ai_azure_endpoint": (
                    system_settings.ai_azure_endpoint if mid == "ai_triage" else None
                ),
                "ai_azure_model": (
                    system_settings.ai_azure_model if mid == "ai_triage" else None
                ),
                "ai_azure_api_version": (
                    system_settings.ai_azure_api_version
                    if mid == "ai_triage"
                    else None
                ),
                "icon": meta["icon"],
                "color": meta["color"],
            }
        )

    return render(request, "vuln_manager/extensions.html", {"modules": modules})


@login_required
@require_POST
def toggle_extension(request, name_id):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    ext = get_object_or_404(Extension, name_id=name_id)
    ext.is_active = not ext.is_active
    ext.save()
    return redirect("extensions")


@login_required
def user_admin(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("forbidden")
    managed_users = User.objects.all().order_by("username")
    system_settings = get_system_settings()
    return render(
        request,
        "vuln_manager/user_admin.html",
        {
            "managed_users": managed_users,
            "registration_disabled": system_settings.disable_register,
        },
    )


@login_required
@require_POST
def set_user_staff(request, pk):
    if not request.user.is_superuser:
        return HttpResponseForbidden("forbidden")
    target_user = get_object_or_404(User, pk=pk)
    target_user.is_staff = request.POST.get("is_staff") == "1"
    target_user.save(update_fields=["is_staff"])
    return redirect("user_admin")


@login_required
@require_POST
def delete_user(request, pk):
    if not request.user.is_superuser:
        return HttpResponseForbidden("forbidden")
    target_user = get_object_or_404(User, pk=pk)
    if target_user.pk == request.user.pk:
        return HttpResponseForbidden("cannot_delete_current_user")
    if target_user.is_superuser and User.objects.filter(is_superuser=True).count() <= 1:
        return HttpResponseForbidden("cannot_delete_last_superuser")
    target_user.delete()
    return redirect("user_admin")


@login_required
@require_POST
def save_wrike_config(request):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    wrike_api_token = (request.POST.get("wrike_api_token") or "").strip()
    folder_id = (request.POST.get("wrike_folder_id") or "").strip()
    wrike_extension, settings_obj = get_wrike_config()
    if wrike_api_token:
        wrike_extension.api_token = wrike_api_token
        wrike_extension.save(update_fields=["api_token"])
    settings_obj.wrike_folder_id = folder_id or None
    settings_obj.save(update_fields=["wrike_folder_id"])
    return redirect("extensions")


@login_required
@require_POST
def save_email_reporting_config(request):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    recipients = (request.POST.get("email_report_recipients") or "").strip()
    settings_obj = get_system_settings()
    settings_obj.email_report_recipients = recipients or None
    settings_obj.save(update_fields=["email_report_recipients"])
    return redirect("extensions")


@login_required
@require_POST
def save_ai_triage_config(request):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    provider = (request.POST.get("ai_triage_provider") or "openrouter").strip().lower()
    if provider not in {"openrouter", "azure"}:
        return HttpResponseForbidden("invalid_provider")
    openrouter_model = (
        request.POST.get("ai_openrouter_model") or "deepseek/deepseek-v4-flash"
    ).strip()
    azure_endpoint = (request.POST.get("ai_azure_endpoint") or "").strip() or None
    azure_model = (request.POST.get("ai_azure_model") or "").strip() or None
    azure_api_version = (request.POST.get("ai_azure_api_version") or "").strip()
    openrouter_key = (request.POST.get("ai_openrouter_api_key") or "").strip()
    azure_key = (request.POST.get("ai_azure_api_key") or "").strip()

    settings_obj = get_system_settings()
    settings_obj.ai_triage_provider = provider
    settings_obj.ai_openrouter_model = openrouter_model
    settings_obj.ai_azure_endpoint = azure_endpoint
    settings_obj.ai_azure_model = azure_model
    settings_obj.ai_azure_api_version = azure_api_version
    if openrouter_key:
        settings_obj.ai_openrouter_api_key = openrouter_key
    if azure_key:
        settings_obj.ai_azure_api_key = azure_key
    settings_obj.save(
        update_fields=[
            "ai_triage_provider",
            "ai_openrouter_model",
            "ai_azure_endpoint",
            "ai_azure_model",
            "ai_azure_api_version",
            "ai_openrouter_api_key",
            "ai_azure_api_key",
        ]
    )
    return redirect("extensions")


@login_required
@require_POST
def send_email_report_now(request):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    extension, _ = Extension.objects.get_or_create(name_id="email_reporting")
    if not extension.is_active:
        return HttpResponseForbidden("email_reporting_disabled")
    recipients_raw = get_system_settings().email_report_recipients or ""
    recipients = [
        email.strip()
        for email in re.split(r"[,;\n]", recipients_raw)
        if email.strip()
    ]
    if not recipients:
        return HttpResponseForbidden("email_reporting_not_configured")
    pdf_buffer = _render_dashboard_pdf_buffer()
    if pdf_buffer is None:
        return HttpResponseForbidden("report_generation_failed")
    subject = f"CVE3PO Report {now().strftime('%Y-%m-%d')}"
    body = "Attached is the latest CVE3PO dashboard report."
    email = EmailMessage(subject=subject, body=body, to=recipients)
    email.attach(
        f"cve3po_report_{now().strftime('%Y%m%d')}.pdf",
        pdf_buffer.getvalue(),
        "application/pdf",
    )
    email.send(fail_silently=False)
    return redirect("extensions")


@login_required
@require_POST
def create_wrike_ticket(request, pk):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    vuln = get_object_or_404(Vulnerability, pk=pk)
    wrike_extension, settings_obj = get_wrike_config()
    if (
        not wrike_extension.is_active
        or not wrike_extension.api_token
        or not settings_obj.wrike_folder_id
    ):
        return HttpResponseForbidden("wrike_not_configured")
    if vuln.wrike_task_id:
        return redirect("vuln_detail", pk=pk)
    try:
        task_id, task_url = wrike_ext.create_task(
            vuln, wrike_extension.api_token, settings_obj.wrike_folder_id
        )
        vuln.wrike_task_id = task_id
        vuln.wrike_task_url = task_url
        vuln.save(update_fields=["wrike_task_id", "wrike_task_url"])
        log_vulnerability_event(
            vuln,
            "ticket_synced",
            user=request.user,
            details={"wrike_task_id": task_id, "direction": "cve3po_to_wrike"},
        )
    except Exception:
        return HttpResponseForbidden("wrike_create_failed")
    return redirect("vuln_detail", pk=pk)


@login_required
@require_POST
def sync_wrike_ticket(request, pk):
    if not request.user.is_staff:
        return HttpResponseForbidden("forbidden")
    vuln = get_object_or_404(Vulnerability, pk=pk)
    wrike_extension, _ = get_wrike_config()
    if not wrike_extension.is_active or not wrike_extension.api_token:
        return HttpResponseForbidden("wrike_not_configured")
    if not vuln.wrike_task_id:
        return HttpResponseForbidden("wrike_ticket_missing")
    try:
        task = wrike_ext.get_task(wrike_extension.api_token, vuln.wrike_task_id)
        if task.get("completed"):
            if vuln.status != "fixed":
                old_status = vuln.status
                vuln.status = "fixed"
                vuln.save(update_fields=["status"])
                log_vulnerability_event(
                    vuln,
                    "ticket_synced",
                    user=request.user,
                    details={
                        "from_status": old_status,
                        "to_status": "fixed",
                        "direction": "wrike_to_cve3po",
                    },
                )
        else:
            should_complete = vuln.status in {"fixed", "false_positive", "risk_accepted"}
            wrike_ext.mark_task_completed(
                wrike_extension.api_token, vuln.wrike_task_id, should_complete
            )
            log_vulnerability_event(
                vuln,
                "ticket_synced",
                user=request.user,
                details={
                    "wrike_completed": should_complete,
                    "direction": "cve3po_to_wrike",
                },
            )
    except Exception:
        return HttpResponseForbidden("wrike_sync_failed")
    return redirect("vuln_detail", pk=pk)


@login_required
@require_POST
def toggle_register(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("forbidden")
    system_settings = get_system_settings()
    system_settings.disable_register = not system_settings.disable_register
    system_settings.save(update_fields=["disable_register"])
    return redirect("user_admin")


def run_triage_background():
    # 1. Alle unbewerteten (tbd)
    pending = Vulnerability.objects.exclude(
        status__in=["fixed", "false_positive", "risk_accepted"]
    ).filter(ai_result="tbd")

    for vuln in pending:
        ai_triage.triage(vuln)

    # 2. Bereits bewertete, bei denen sich die Asset-Kritikalität geändert hat
    triaged = Vulnerability.objects.exclude(
        status__in=["fixed", "false_positive", "risk_accepted"]
    ).exclude(ai_result="tbd")

    for vuln in triaged:
        current_crit = "Low"
        if vuln.most_critical_host:
            current_crit = vuln.most_critical_host.criticality or "Low"

        if vuln.ai_last_criticality != current_crit:
            print(
                f"[AI] Re-triaging {vuln.cve_id} due to criticality change: {vuln.ai_last_criticality} -> {current_crit}"
            )
            ai_triage.triage(vuln)


@login_required
def do_triage(request):
    ai_extension, _ = get_ai_triage_config()
    if not ai_extension.is_active:
        return HttpResponseForbidden("ai_triage_disabled")
    if request.method == "POST":
        thread = threading.Thread(target=run_triage_background)
        thread.start()
        print("[AI] Background triage started.")

    return redirect("ai_dashboard")


@login_required
@require_POST
def triage_single_vulnerability(request, pk):
    ai_extension, _ = get_ai_triage_config()
    if not ai_extension.is_active:
        return HttpResponseForbidden("ai_triage_disabled")
    vuln = get_object_or_404(Vulnerability, pk=pk)

    def _run_single_triage(vuln_id):
        triage_target = Vulnerability.objects.filter(pk=vuln_id).first()
        if not triage_target:
            return
        ai_triage.triage(triage_target)

    worker = threading.Thread(
        target=_run_single_triage,
        args=(vuln.id,),
        daemon=True,
    )
    worker.start()

    log_vulnerability_event(
        vuln,
        "updated",
        user=request.user,
        details={"source": "manual_retriage"},
    )
    return redirect("vuln_detail", pk=pk)


@login_required
@require_POST
def enrich_single_vulnerability(request, pk):
    vuln = get_object_or_404(Vulnerability, pk=pk)
    cvss, description = get_cve_details(vuln.cve_id)

    updated_fields = []
    if cvss and vuln.cvss != cvss:
        vuln.cvss = cvss
        updated_fields.append("cvss")
    if description and vuln.description != description:
        vuln.description = description
        updated_fields.append("description")

    if updated_fields:
        vuln.save(update_fields=updated_fields)
        log_vulnerability_event(
            vuln,
            "updated",
            user=request.user,
            details={"source": "manual_enrich", "fields": updated_fields},
        )

    return redirect("vuln_detail", pk=pk)
