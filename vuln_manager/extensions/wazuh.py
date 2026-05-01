from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import JsonResponse
import json
from vuln_manager.models import Host, Scan, Vulnerability, Extension


@csrf_exempt
@require_POST
def webhook(request):
    """
    Wazuh Webhook Integration.
    Only processes data if the 'wazuh' extension is marked as active and token is valid.
    """
    try:
        wazuh_ext, _ = Extension.objects.get_or_create(name_id="wazuh")
        if not wazuh_ext.is_active:
            return JsonResponse(
                {"status": "ignored", "reason": "extension disabled"}, status=200
            )

        provided_token = request.headers.get("X-API-Key")
        if not provided_token or provided_token != wazuh_ext.api_token:
            return JsonResponse(
                {"status": "error", "message": "unauthorized"}, status=401
            )

        data = json.loads(request.body)

        # Wazuh Alert Parsing
        agent_data = data.get("agent", {})
        agent_ip = agent_data.get("ip")
        agent_name = agent_data.get("name")

        vuln_data = data.get("data", {}).get("vulnerability", {})
        cve_id = vuln_data.get("cve")
        severity_raw = str(vuln_data.get("severity", "info")).lower()
        title = vuln_data.get("title", f"Wazuh: {cve_id}")
        v_status = vuln_data.get("status", "").upper()  # VALID or SOLVED

        if not agent_ip or not cve_id:
            return JsonResponse(
                {"status": "ignored", "reason": "missing data"}, status=200
            )

        host, _ = Host.objects.get_or_create(ip_address=agent_ip)
        if agent_name and not host.hostname:
            host.hostname = agent_name
            host.save()

        scan, _ = Scan.objects.get_or_create(
            scan_type="WAZUH", defaults={"raw_file": None}
        )

        # Wazuh rule 23502 indicates a vulnerability has been removed/solved
        if v_status == "SOLVED" or data.get("rule", {}).get("id") == "23502":
            Vulnerability.objects.filter(host=host, cve_id=cve_id).update(
                status="fixed"
            )
            return JsonResponse({"status": "updated", "action": "fixed"}, status=200)

        exists = Vulnerability.objects.filter(host=host, cve_id=cve_id).exists()
        if not exists:
            sev = "info"
            if "critical" in severity_raw:
                sev = "critical"
            elif "high" in severity_raw:
                sev = "high"
            elif "medium" in severity_raw:
                sev = "medium"
            elif "low" in severity_raw:
                sev = "low"

            Vulnerability.objects.create(
                host=host,
                scan=scan,
                cve_id=cve_id,
                severity=sev,
                name=title,
                status="open",
            )
            return JsonResponse({"status": "created"}, status=201)

        return JsonResponse(
            {"status": "skipped", "reason": "already exists"}, status=200
        )

    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=400)
