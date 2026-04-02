from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Count, Q, Max, Case, When, Value, IntegerField
from django.db.models.functions import TruncDate
from .models import Host, Port, Vulnerability, Scan, Software
from .utils import (
    parse_nmap_xml,
    parse_nuclei_jsonl,
    parse_openvas_xml,
    parse_semgrep_json,
)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
import json

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


@login_required
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
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    return JsonResponse({"status": "invalid method"}, status=405)


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
    vuln_count = (
        Vulnerability.objects.exclude(status__in=["fixed", "false_positive"])
        .exclude(severity="info")
        .count()
    )
    vuln_stats = (
        Vulnerability.objects.exclude(status__in=["fixed", "false_positive"])
        .values("severity")
        .annotate(count=Count("id"))
    )
    severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for stat in vuln_stats:
        severity_map[stat["severity"].lower()] = stat["count"]
    timeline_raw = (
        Vulnerability.objects.exclude(status__in=["fixed", "false_positive"])
        .annotate(date=TruncDate("scan__uploaded_at"))
        .values("date")
        .annotate(count=Count("id"))
        .order_by("date")
    )
    timeline_labels = [item["date"].strftime(
        "%d.%m.%Y") for item in timeline_raw]
    timeline_values = [item["count"] for item in timeline_raw]
    top_hosts = (
        Host.objects.annotate(
            num_vulns=Count(
                "vulnerabilities",
                filter=~Q(vulnerabilities__status__in=[
                          "fixed", "false_positive"])
                & ~Q(vulnerabilities__severity="info"),
            )
        )
        .filter(num_vulns__gt=0)
        .order_by("-num_vulns")[:5]
    )
    recent_vulns = (
        Vulnerability.objects.select_related("host")
        .exclude(status__in=["fixed", "false_positive"])
        .order_by("-id")[:5]
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
    top_vuln_types = (
        Vulnerability.objects.exclude(status__in=["fixed", "false_positive"])
        .exclude(severity="info")
        .values("cve_id", "name")
        .annotate(count=Count("id"))
        .order_by("-count")[:5]
    )
    last_scans = Scan.objects.all().order_by("-uploaded_at")[:5]
    software_count = Software.objects.count()
    context = {
        "host_count": host_count,
        "port_count": port_count,
        "vuln_count": vuln_count,
        "severity_map": severity_map,
        "last_scans": last_scans,
        "top_hosts": top_hosts,
        "recent_vulns": recent_vulns,
        "top_ports": top_ports,
        "top_vuln_types": top_vuln_types,
        "timeline_labels": json.dumps(timeline_labels),
        "timeline_values": json.dumps(timeline_values),
        "software_count": software_count,
        "user": User.objects.get(pk=request.user.id),
    }
    return render(request, "vuln_manager/dashboard.html", context)


@login_required
def host_list(request):
    hosts = Host.objects.all().order_by("ip_address")
    for host in hosts:
        latest_scan = host.ports.aggregate(latest=Max("scan_id"))["latest"]
        host.current_port_count = (
            host.ports.filter(
                scan_id=latest_scan).count() if latest_scan else 0
        )
        inherited_q = (
            Vulnerability.objects.filter(
                Q(host=host) | Q(software__hosts=host))
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
    active_ports = host.ports.filter(
        scan_id=latest_scan_id).order_by("port_number")
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
        vulns = host.vulnerabilities.exclude(status="false_positive").order_by(
            "-severity"
        )
    else:
        vulns = (
            Vulnerability.objects.filter(
                Q(host=host) | Q(software__hosts=host))
            .exclude(status="false_positive")
            .distinct()
            .order_by("-severity")
        )
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
    installed_software = host.software_inventory.annotate(
        active_vulns=Count(
            "vulnerabilities",
            filter=Q(vulnerabilities__host=host)
            | Q(vulnerabilities__software__hosts=host)
            & ~Q(vulnerabilities__status__in=["fixed", "false_positive"]),
        )
    ).order_by("name")
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
            "criticality_choices": Host.CRITICALITY_CHOICES,
        },
    )


@login_required
def software_list(request):
    software = Software.objects.annotate(
        num_hosts=Count("hosts")).order_by("name")
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
            # Propagate criticality
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
            Scan.objects.filter(scan_type="MANUAL").order_by(
                "-uploaded_at").first()
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
def port_list(request):
    latest_scan_ids = Port.objects.values(
        "host").annotate(latest=Max("scan_id"))
    active_port_ids = [item["latest"]
                       for item in latest_scan_ids if item["latest"]]
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
    return redirect(request.META.get("HTTP_REFERER", "kanban_board"))


@login_required
def vuln_list(request):
    severity = request.GET.get("severity")
    status_filter = request.GET.get("status", "active")
    active_vulns = Vulnerability.objects.exclude(status="false_positive")
    if status_filter == "resolved":
        vulns = active_vulns.filter(status="fixed")
    elif status_filter == "ignored":
        vulns = active_vulns.filter(status="risk_accepted")
    else:
        vulns = active_vulns.exclude(status="fixed")
    if severity:
        vulns = vulns.filter(severity=severity.lower())
    vulns = vulns.order_by("-severity", "cve_id")
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
            scan_obj = Scan.objects.create(
                scan_type=scan_type, raw_file=raw_file)
            file_path = scan_obj.raw_file.path
            if scan_type == "NMAP":
                parse_nmap_xml(file_path, scan_obj)
            elif scan_type == "NUCLEI":
                parse_nuclei_jsonl(file_path, scan_obj)
            elif scan_type == "OPENVAS":
                parse_openvas_xml(file_path, scan_obj)
            elif scan_type == "SEMGREP":
                parse_semgrep_json(file_path, scan_obj, software_obj=sw_obj)
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
