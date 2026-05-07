from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseNotFound
import json
import logging
from vuln_manager.models import Host, Scan, Vulnerability, Extension
from vuln_manager.utils.audit import log_vulnerability_event
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability

logger = logging.getLogger(__name__)


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
            return HttpResponseNotFound()

        auth_header = request.headers.get("Authorization", "")
        bearer_token = None
        if auth_header.lower().startswith("bearer "):
            bearer_token = auth_header.split(" ", 1)[1].strip()
        provided_token = bearer_token or request.headers.get("X-API-Key")
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
            for vuln in Vulnerability.objects.filter(host=host, cve_id=cve_id):
                if vuln.status != "fixed":
                    old_status = vuln.status
                    vuln.status = "fixed"
                    vuln.save(update_fields=["status"])
                    log_vulnerability_event(
                        vuln,
                        "status_changed",
                        actor="wazuh_webhook",
                        details={"from_status": old_status, "to_status": "fixed"},
                    )
            return JsonResponse({"status": "updated", "action": "fixed"}, status=200)
        sev = "info"
        if "critical" in severity_raw:
            sev = "critical"
        elif "high" in severity_raw:
            sev = "high"
        elif "medium" in severity_raw:
            sev = "medium"
        elif "low" in severity_raw:
            sev = "low"

        create_or_update_vulnerability(
            host=host,
            scan=scan,
            cve_id=cve_id,
            severity=sev,
            name=title,
            description="Created from Wazuh webhook",
            actor="wazuh_webhook",
        )
        return JsonResponse({"status": "upserted"}, status=200)
    except Exception as e:
        logger.exception("Unhandled exception while processing Wazuh webhook")
        return JsonResponse(
            {"status": "error", "message": "An internal error has occurred."},
            status=400,
        )
