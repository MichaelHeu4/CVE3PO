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
        # Standard Wazuh alerts have top-level 'agent', 'rule', and 'data' objects
        agent_data = data.get("agent", {})
        if not agent_data and "data" in data:
            agent_data = data.get("data", {}).get("agent", {})
            
        agent_ip = agent_data.get("ip")
        agent_name = agent_data.get("name")

        # Robust data extraction: Support vulnerability at top level or inside 'data'
        vuln_data = data.get("vulnerability")
        if not vuln_data:
            vuln_data = data.get("data", {}).get("vulnerability", {})
            
        # Fallback if still empty
        if not vuln_data and not data.get("cve"):
             if "cve" in data:
                 vuln_data = data

        # Try to extract package information first
        package_data = vuln_data.get("package", {})
        software = None
        if package_data:
            from vuln_manager.models import Software
            pkg_name = package_data.get("name")
            pkg_version = package_data.get("version")
            if pkg_name:
                software, _ = Software.objects.get_or_create(
                    name=pkg_name,
                    version=pkg_version,
                    defaults={"vendor": "Wazuh Detection"}
                )

        # Try to find host by IP or Name
        host = None
        if agent_ip:
            host, _ = Host.objects.get_or_create(ip_address=agent_ip)
            if agent_name and not host.hostname:
                host.hostname = agent_name
                host.save()
        elif agent_name:
            # Fallback: Try to find host by name if IP is missing
            host = Host.objects.filter(hostname=agent_name).first()

        # Link software to host if both found
        if host and software:
            if host not in software.hosts.all():
                software.hosts.add(host)

        # Robust field extraction
        cve_id = vuln_data.get("cve") or data.get("cve")
        
        if not cve_id:
            logger.warning(f"Wazuh webhook ignored: missing cve_id. Data: {data}")
            return JsonResponse(
                {"status": "ignored", "reason": "missing cve_id"}, status=200
            )
            
        # If no host AND no software, we can't really place this vulnerability
        if not host and not software:
            logger.warning(f"Wazuh webhook ignored: no host and no software identified for {cve_id}. Data: {data}")
            return JsonResponse(
                {"status": "ignored", "reason": "missing identification data"}, status=200
            )

        severity_raw = str(
            vuln_data.get("severity") or 
            data.get("severity") or 
            "info"
        ).lower()
        
        title = (
            vuln_data.get("title") or 
            data.get("rule", {}).get("description") or 
            f"Wazuh: {cve_id}"
        )

        description = (
            vuln_data.get("rationale") or 
            vuln_data.get("description") or 
            "Created from Wazuh webhook"
        )
        
        # Wazuh status can be 'Active' or 'Solved'
        v_status = str(
            vuln_data.get("status") or 
            ""
        ).upper()

        scan, _ = Scan.objects.get_or_create(
            scan_type="WAZUH", defaults={"raw_file": None}
        )

        # Wazuh rule 23502 indicates a vulnerability has been removed/solved
        if v_status == "SOLVED" or data.get("rule", {}).get("id") == "23502":
            # If we have a host, filter by host, otherwise filter by software
            # If both are missing (which shouldn't happen here), it will solve 'global' vulns
            filter_kwargs = {"cve_id": cve_id}
            if host:
                filter_kwargs["host"] = host
            elif software:
                filter_kwargs["software"] = software
            
            for vuln in Vulnerability.objects.filter(**filter_kwargs):
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

        # Extract CVSS if available
        cvss_score = None
        cvss_data = vuln_data.get("cvss", {})
        if cvss_data:
            # Try CVSS3 first, then CVSS2
            cvss3 = cvss_data.get("cvss3", {})
            cvss2 = cvss_data.get("cvss2", {})
            cvss_score = cvss3.get("base_score") or cvss2.get("base_score")
        
        # Fallback to top-level score in vulnerability object
        if not cvss_score and "score" in vuln_data:
            cvss_score = vuln_data.get("score", {}).get("base")

        create_or_update_vulnerability(
            host=host,
            scan=scan,
            cve_id=cve_id,
            severity=sev,
            name=title,
            description=description,
            cvss=str(cvss_score) if cvss_score else None,
            software=software,
            actor="wazuh_webhook",
        )
        return JsonResponse({"status": "upserted"}, status=200)
    except Exception as e:
        logger.exception("Unhandled exception while processing Wazuh webhook")
        return JsonResponse(
            {"status": "error", "message": "An internal error has occurred."},
            status=400,
        )
