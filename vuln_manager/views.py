from django.core.paginator import Paginator
from django.views.decorators.http import require_POST
from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Count, Q, Max, Case, When, Value, IntegerField, Avg
from django.db.models.functions import TruncDate
from .models import Host, Port, Vulnerability, Scan, Software, Extension, HostSoftwareRelationship
from .parser import nmap
from .parser import nuclei
from .parser import openvas
from .parser import osvscanner
from .parser import semgrep
from .utils import ai_triage
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.utils.http import url_has_allowed_host_and_scheme
import json
import os

CRITICALITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    None: 0,
    "": 0,
}


def login_view(request):
    next_url = request.GET.get("next", "dashboard")
    if not url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = "dashboard"
    if request.user.is_authenticated:
        return redirect(next_url)
    if request.method == "POST":
        username = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            print(next_url)
            return redirect(next_url)
    return render(request, "vuln_manager/login.html")


def register_view(request):
    if settings.DISABLE_REGISTER:
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


@csrf_exempt
@login_required
def api_update_vuln_status(request, pk):
    if request.method == "POST":
        try:
            vuln = Vulnerability.objects.get(pk=pk)
            data = json.loads(request.body)
            new_status = data.get("status")
            if new_status in dict(Vulnerability.STATUS_CHOICES):
                vuln.status = new_status
                vuln.save()
                return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({"status": "error"}, status=400)
    return JsonResponse({"status": "invalid method"}, status=405)


import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from django.http import FileResponse
from django.utils.timezone import now

from xhtml2pdf import pisa
from django.template.loader import render_to_string

@login_required
def export_dashboard_pdf(request):
    all_vulns = Vulnerability.objects.exclude(status__in=["fixed", "false_positive"])
    critical_count = all_vulns.filter(severity="critical").count()
    high_count = all_vulns.filter(severity="high").count()
    host_count = Host.objects.count()
    vuln_hosts_count = Host.objects.filter(vulnerabilities__in=all_vulns).distinct().count()
    avg_proc_time_ms = Vulnerability.objects.filter(ai_proc_time__gt=0).aggregate(Avg('ai_proc_time'))['ai_proc_time__avg'] or 0

    top_hosts = Host.objects.annotate(
        num_vulns=Count(
            "vulnerabilities",
            filter=~Q(vulnerabilities__status__in=["fixed", "false_positive"])
        )
    ).order_by("-num_vulns")[:5]

    recent_vulns = Vulnerability.objects.filter(
        severity__in=["critical", "high"]
    ).exclude(status__in=["fixed", "false_positive"]).order_by("-id")[:5]

    context = {
        "report_date": now(),
        "metrics": {
            "host_count": host_count,
            "vuln_count": all_vulns.count(),
            "critical_count": critical_count,
            "high_count": high_count,
            "vuln_hosts_count": vuln_hosts_count,
            "mttt": round(avg_proc_time_ms / 1000, 2),
        },
        "top_hosts": top_hosts,
        "recent_vulns": recent_vulns,
    }

    html = render_to_string("vuln_manager/report_pdf.html", context)
    buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=buffer)

    if pisa_status.err:
        return HttpResponse("Fehler bei der PDF-Erstellung", status=500)

    buffer.seek(0)
    return FileResponse(buffer, as_attachment=True, filename=f"cve3po_report_{now().strftime('%Y%m%d')}.pdf")


@csrf_exempt
@require_POST
def update_inventory_api(request):
    """
    API endpoint for agents to report software inventory (Strategy A).
    Payload must include 'X-API-Key' header.
    """
    try:
        # 1. Authentication Check
        api_ext, _ = Extension.objects.get_or_create(name_id="agent_api")
        provided_token = request.headers.get("X-API-Key")
        if not provided_token or provided_token != api_ext.api_token:
            return JsonResponse({"status": "error", "message": "unauthorized"}, status=401)

        data = json.loads(request.body)
        host_ip = data.get("host_ip")
        hostname = data.get("hostname")
        software_list = data.get("software", [])

        if not host_ip:
            return JsonResponse({"status": "error", "message": "host_ip is required"}, status=400)

        # 1. Host sicherstellen
        host, _ = Host.objects.get_or_create(ip_address=host_ip)
        if hostname and not host.hostname:
            host.hostname = hostname
            host.save()

        # 2. Strategy A: Alle bisherigen "agent" Einträge für diesen Host löschen
        HostSoftwareRelationship.objects.filter(host=host, source="agent").delete()

        added_count = 0
        for sw_item in software_list:
            name = sw_item.get("name")
            version = sw_item.get("version")
            vendor = sw_item.get("vendor")
            port = sw_item.get("port")

            if name:
                sw_obj, _ = Software.objects.get_or_create(
                    name=name,
                    version=version,
                    vendor=vendor,
                    listening_port=port
                )
                
                # Gezielt als "agent" Verknüpfung anlegen
                HostSoftwareRelationship.objects.get_or_create(
                    host=host,
                    software=sw_obj,
                    source="agent"
                )
                added_count += 1

        return JsonResponse({
            "status": "success", 
            "host": host.ip_address,
            "agent_software_synced": added_count
        }, status=200)

    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=400)


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
    all_open_vulns = Vulnerability.objects.exclude(status__in=["fixed", "false_positive"])
    vuln_count = all_open_vulns.exclude(severity="info").count()
    
    # Severity distribution
    vuln_stats = all_open_vulns.values("severity").annotate(count=Count("id"))
    severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for stat in vuln_stats:
        severity_map[stat["severity"].lower()] = stat["count"]
        
    # Security Score Calculation
    # Critical=10, High=5, Medium=2, Low=1
    risk_points = (severity_map["critical"] * 10 + 
                   severity_map["high"] * 5 + 
                   severity_map["medium"] * 2 + 
                   severity_map["low"] * 1)
    
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
        open_count = Vulnerability.objects.filter(
            scan__uploaded_at__date__lte=day
        ).exclude(
            status__in=["fixed", "false_positive"],
        ).count()
        
        fixed_count = Vulnerability.objects.filter(
            status="fixed",
            scan__uploaded_at__date__lte=day
        ).count()
        
        trend_open.append(open_count)
        trend_fixed.append(fixed_count)

    # Top Risky Assets (Weighted)
    top_hosts = (
        Host.objects.annotate(
            risk_score=Count('vulnerabilities', filter=Q(vulnerabilities__severity='critical')) * 10 +
                       Count('vulnerabilities', filter=Q(vulnerabilities__severity='high')) * 5 +
                       Count('vulnerabilities', filter=Q(vulnerabilities__severity='medium')) * 2
        ).filter(risk_score__gt=0).order_by('-risk_score')[:5]
    )

    recent_vulns = all_open_vulns.select_related("host").order_by("-id")[:5]
    
    top_ports = (
        Port.objects.filter(scan_id__in=[item["latest_scan_id"] for item in latest_port_ids if item["latest_scan_id"]])
        .values("port_number", "service_name")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    
    software_count = Software.objects.count()

    # AI Stats (MTTT)
    avg_proc_time_ms = Vulnerability.objects.filter(ai_proc_time__gt=0).aggregate(Avg('ai_proc_time'))['ai_proc_time__avg'] or 0
    ai_context = {
        "proc_time": round(avg_proc_time_ms / 1000, 2),
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
        "recent_vulns": recent_vulns,
        "top_ports": top_ports,
        "software_count": software_count,
        "ai": ai_context,
        "user": User.objects.get(pk=request.user.id),
    }
    return render(request, "vuln_manager/dashboard.html", context)


@login_required
def host_list(request):
    hosts_query = Host.objects.all().order_by("ip_address")
    
    # Pagination
    paginator = Paginator(hosts_query, 25) # 25 per page
    page_number = request.GET.get('page')
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
    
    # Paginate Threats
    vuln_paginator = Paginator(vulns_query, 20)
    vuln_page_number = request.GET.get('vuln_page')
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
            filter=(Q(vulnerabilities__host=host) | Q(vulnerabilities__software__hosts=host))
            & ~Q(vulnerabilities__status__in=["fixed", "false_positive"]),
        )
    ).order_by("name")
    
    sw_paginator = Paginator(sw_query, 20)
    sw_page_number = request.GET.get('sw_page')
    installed_software = sw_paginator.get_page(sw_page_number)
    
    active_tab = request.GET.get('tab', 'threats')

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
            "active_tab": active_tab,
            "criticality_choices": Host.CRITICALITY_CHOICES,
        },
    )


@login_required
def software_list(request):
    software_query = Software.objects.annotate(num_hosts=Count("hosts")).order_by("name")
    
    paginator = Paginator(software_query, 25)
    page_number = request.GET.get('page')
    software = paginator.get_page(page_number)
    
    return render(request, "vuln_manager/software_list.html", {"software": software})


@login_required
def software_detail(request, pk):
    item = get_object_or_404(Software, pk=pk)
    hosts = item.hosts.all()
    vulns = (
        Vulnerability.objects.filter(software=item)
        .exclude(status="false_positive")
        .order_by("-severity")
    )
    return render(
        request,
        "vuln_manager/software_detail.html",
        {
            "software": item,
            "hosts": hosts,
            "vulns": vulns,
            "criticality_choices": Software.CRITICALITY_CHOICES,
        },
    )


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
        Vulnerability.objects.create(
            host=host_obj,
            scan=manual_scan,
            software=sw_obj,
            cve_id=cve_id,
            severity=severity,
            name=name,
            description=description,
            nuclei_poc=poc,
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
        criticality = request.POST.get("criticality")

        if not host_obj:
            host_obj = Host(ip_address=ip_address)
        else:
            host_obj.ip_address = ip_address

        host_obj.hostname = hostname
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
    scans = Scan.objects.annotate(num_vulns=Count("vulnerabilities")).order_by(
        "-uploaded_at"
    )
    return render(request, "vuln_manager/scan_list.html", {"scans": scans})


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
    return render(request, "vuln_manager/kanban_board.html", {"board": board_data})


@login_required
def update_vuln_status(request, pk):
    if request.method == "POST":
        vuln = get_object_or_404(Vulnerability, pk=pk)
        new_status = request.POST.get("status")
        if new_status in dict(Vulnerability.STATUS_CHOICES):
            vuln.status = new_status
            vuln.save()
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
    severity = request.GET.get("severity")
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
    paginator = Paginator(vulns_query, 50) # 50 per page for vulns
    page_number = request.GET.get('page')
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
            "status_filter": status_filter,
            "metrics": metrics,
        },
    )


@login_required
def vuln_detail(request, pk):
    vuln = get_object_or_404(
        Vulnerability.objects.select_related("host", "scan"), pk=pk
    )
    return render(request, "vuln_manager/vuln_detail.html", {"vuln": vuln})


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


import threading
from django.db.models import Avg

@login_required
def ki_dashboard(request):
    selected_vuln_id = request.GET.get("selected_vuln")
    selected_vuln = None
    if selected_vuln_id:
        selected_vuln = get_object_or_404(Vulnerability, pk=selected_vuln_id)

    all_vulns_query = Vulnerability.objects.exclude(status="false_positive").order_by("-severity", "cve_id").distinct()

    # AI Stats
    triaged_vulns = all_vulns_query.exclude(ai_result="tbd").count()
    action_required = all_vulns_query.filter(ai_result="Act").count()
    avg_proc_time_ms = Vulnerability.objects.filter(ai_proc_time__gt=0).aggregate(Avg('ai_proc_time'))['ai_proc_time__avg'] or 0

    # Pagination
    paginator = Paginator(all_vulns_query, 25) # 25 per page
    page_number = request.GET.get('page')
    all_vulns = paginator.get_page(page_number)

    ai = {
        "model": "DeepSeek V4 Flash",
        "proc_time": round(avg_proc_time_ms / 1000, 2),
    }
    context = {
        "triaged_vulns": triaged_vulns,
        "all_vulns": all_vulns,
        "action_required": action_required,
        "ai": ai,
        "selected_vuln": selected_vuln
    }
    return render(request, "vuln_manager/ki_dashboard.html", context)
@login_required
def extensions_view(request):
    # Metadata for active modules
    module_metadata = {
        "agent_api": {
            "name": "Inventory API",
            "description": "Core API for external agents to report software inventory. Requires X-API-Key header.",
            "icon": "api",
            "color": "tertiary",
        },
        "wazuh": {
            "name": "Wazuh Connector",
            "description": "Real-time vulnerability streaming via webhooks. Automatically creates hosts and manages vulnerability lifecycles.",
            "icon": "webhook",
            "color": "primary",
        },
        "cloud_sentinel": {
            "name": "Cloud Sentinel",
            "description": "Continuous posture monitoring and threat detection across AWS, GCP, and Azure environments.",
            "icon": "cloud_sync",
            "color": "primary",
        },
        "docker_auditor": {
            "name": "Docker Auditor",
            "description": "Automated vulnerability scanning for container images and runtime security policy enforcement.",
            "icon": "view_in_ar",
            "color": "tertiary",
        },
        "slack_notifier": {
            "name": "Slack Notifier",
            "description": "Direct integration for instant critical vulnerability alerts and weekly security reports.",
            "icon": "chat_bubble",
            "color": "on-surface",
        },
    }

    modules = []
    for mid, meta in module_metadata.items():
        ext, _ = Extension.objects.get_or_create(name_id=mid)
        modules.append({
            "id": mid,
            "name": meta["name"],
            "description": meta["description"],
            "is_active": ext.is_active,
            "api_token": ext.api_token,
            "icon": meta["icon"],
            "color": meta["color"],
        })
        
    return render(request, "vuln_manager/extensions.html", {"modules": modules})

@login_required
@require_POST
def toggle_extension(request, name_id):
    ext = get_object_or_404(Extension, name_id=name_id)
    ext.is_active = not ext.is_active
    ext.save()
    return redirect("extensions")


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
            print(f"[AI] Re-triaging {vuln.cve_id} due to criticality change: {vuln.ai_last_criticality} -> {current_crit}")
            ai_triage.triage(vuln)

@login_required
def do_triage(request):
    if request.method == "POST":
        thread = threading.Thread(target=run_triage_background)
        thread.start()
        print("[AI] Background triage started.")

    return redirect("ai_dashboard")
