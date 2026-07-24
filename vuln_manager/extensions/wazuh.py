from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseNotFound
import json
import logging
from vuln_manager.models import (
    Host,
    Scan,
    Software,
    Vulnerability,
    Extension,
    HostSoftwareRelationship,
)
from vuln_manager.utils.audit import log_vulnerability_event
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability

logger = logging.getLogger(__name__)


def _unwrap_alert(item):
    """
    Normalize a webhook item into a standard Wazuh alert object.

    Supports the n8n-style envelope (``{"body": {"full_alert": {...}}}``) as well as
    raw Wazuh alerts and the ``{"data": {"vulnerability": ...}}`` shape posted directly.
    """
    if not isinstance(item, dict):
        return {}
    body = item.get("body")
    if isinstance(body, dict):
        full_alert = body.get("full_alert")
        return full_alert if isinstance(full_alert, dict) else body
    return item


# Order + value maps to assemble a CVSS v3 vector from Wazuh's component dict
# (data.vulnerability.cvss.cvss3.vector), which Wazuh sends instead of a string.
_CVSS3_METRICS = [
    ("attack_vector", "AV", {"network": "N", "adjacent": "A", "adjacent_network": "A", "local": "L", "physical": "P"}),
    ("attack_complexity", "AC", {"low": "L", "high": "H"}),
    ("privileges_required", "PR", {"none": "N", "low": "L", "high": "H"}),
    ("user_interaction", "UI", {"none": "N", "required": "R"}),
    ("scope", "S", {"unchanged": "U", "changed": "C"}),
    ("confidentiality_impact", "C", {"none": "N", "low": "L", "high": "H"}),
    ("integrity_impact", "I", {"none": "N", "low": "L", "high": "H"}),
    ("availability_impact", "A", {"none": "N", "low": "L", "high": "H"}),
]


def _cvss3_vector_from_components(vector):
    """Assemble a 'CVSS:3.1/AV:N/...' string from Wazuh's component dict."""
    if not isinstance(vector, dict):
        return None
    parts = []
    for key, abbr, mapping in _CVSS3_METRICS:
        raw = vector.get(key)
        if raw is None:
            return None  # incomplete — cannot build a valid vector
        code = mapping.get(str(raw).strip().lower())
        if code is None:
            return None
        parts.append(f"{abbr}:{code}")
    return "CVSS:3.1/" + "/".join(parts)


def _extract_cvss(vuln_data):
    """
    Best available CVSS representation as a string.

    Prefers a full vector (a ready-made 'CVSS:.../AV:.../...' string if present,
    otherwise assembled from the cvss3 component dict). Falls back to the numeric
    base score only when no vector is available.
    """
    cvss_data = vuln_data.get("cvss") or {}
    cvss3 = cvss_data.get("cvss3") or {}
    cvss2 = cvss_data.get("cvss2") or {}

    # 1) A ready-made vector string, wherever it may sit.
    for candidate in (
        cvss3.get("vector"),
        cvss2.get("vector"),
        vuln_data.get("cvss_vector"),
        vuln_data.get("vector"),
    ):
        if isinstance(candidate, str) and ("AV:" in candidate or candidate.startswith("CVSS:")):
            return candidate

    # 2) Assemble a v3 vector from Wazuh's component dict.
    assembled = _cvss3_vector_from_components(cvss3.get("vector"))
    if assembled:
        return assembled

    # 3) Fall back to the numeric base score.
    score = cvss3.get("base_score") or cvss2.get("base_score")
    if not score and isinstance(vuln_data.get("score"), dict):
        score = vuln_data["score"].get("base")
    return str(score) if score else None


def _handle_alert(data):
    # Standard Wazuh alerts carry top-level 'agent', 'rule' and 'data' objects
    agent_data = data.get("agent", {})
    if not agent_data and "data" in data:
        agent_data = data.get("data", {}).get("agent", {})

    agent_ip = agent_data.get("ip")
    agent_name = agent_data.get("name")

    # Support vulnerability at top level or inside 'data'
    vuln_data = data.get("vulnerability")
    if not vuln_data:
        vuln_data = data.get("data", {}).get("vulnerability", {})
    if not vuln_data and "cve" in data:
        vuln_data = data

    package_data = vuln_data.get("package", {})
    software = None
    if package_data:
        pkg_name = package_data.get("name")
        pkg_version = package_data.get("version")
        if pkg_name:
            software, _ = Software.objects.get_or_create(
                name=pkg_name,
                version=pkg_version,
                defaults={"vendor": "Wazuh Detection"},
            )

    host = None
    if agent_ip:
        host, _ = Host.objects.get_or_create(ip_address=agent_ip)
        if agent_name and not host.hostname:
            host.hostname = agent_name
            host.save()
    elif agent_name:
        host = Host.objects.filter(hostname=agent_name).first()

    if host and software:
        if not software.hosts.filter(pk=host.pk).exists():
            software.hosts.add(host)
        # Also record the explicit, source-tracked relationship (like the agent
        # and scanner flows do) so the host inventory shows where it came from.
        HostSoftwareRelationship.objects.get_or_create(
            host=host, software=software, defaults={"source": "scanner"}
        )

    cve_id = vuln_data.get("cve") or data.get("cve")
    if not cve_id:
        logger.warning("Wazuh webhook ignored: missing cve_id")
        return {"status": "ignored", "reason": "missing cve_id"}, 200

    if not host and not software:
        logger.warning(
            "Wazuh webhook ignored: no host and no software identified for %s", cve_id
        )
        return {"status": "ignored", "reason": "missing identification data"}, 200

    severity_raw = str(
        vuln_data.get("severity") or data.get("severity") or "info"
    ).lower()
    title = (
        vuln_data.get("title")
        or data.get("rule", {}).get("description")
        or data.get("description")
        or f"Wazuh: {cve_id}"
    )
    description = (
        vuln_data.get("rationale")
        or vuln_data.get("description")
        or "Created from Wazuh webhook"
    )
    v_status = str(vuln_data.get("status") or "").upper()
    rule_id = str(data.get("rule", {}).get("id") or data.get("rule_id") or "")

    scan, _ = Scan.objects.get_or_create(scan_type="WAZUH", defaults={"raw_file": None})

    # Wazuh rule 23502 indicates a vulnerability has been removed/solved
    if v_status == "SOLVED" or rule_id == "23502":
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
        return {"status": "updated", "action": "fixed"}, 200

    sev = "info"
    if "critical" in severity_raw:
        sev = "critical"
    elif "high" in severity_raw:
        sev = "high"
    elif "medium" in severity_raw:
        sev = "medium"
    elif "low" in severity_raw:
        sev = "low"

    cvss_value = _extract_cvss(vuln_data)

    create_or_update_vulnerability(
        host=host,
        scan=scan,
        cve_id=cve_id,
        severity=sev,
        name=title,
        description=description,
        cvss=cvss_value,
        software=software,
        actor="wazuh_webhook",
    )
    return {"status": "upserted"}, 200


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

        payload = json.loads(request.body)
        items = payload if isinstance(payload, list) else [payload]
        results = [_handle_alert(_unwrap_alert(item)) for item in items]

        if len(results) == 1:
            body, status = results[0]
            return JsonResponse(body, status=status)
        return JsonResponse(
            {
                "status": "processed",
                "count": len(results),
                "results": [body for body, _ in results],
            },
            status=200,
        )
    except Exception:
        logger.exception("Unhandled exception while processing Wazuh webhook")
        return JsonResponse(
            {"status": "error", "message": "An internal error has occurred."},
            status=400,
        )
