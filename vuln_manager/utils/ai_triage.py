from vuln_manager.models import Extension, SystemSettings, Vulnerability
import os
import json
import instructor
from django.conf import settings
from pydantic import BaseModel, Field
from openai import OpenAI


# ==========================================
# 1. DATEN-SCHEMA (PYDANTIC)
# ==========================================
class TriageErgebnis(BaseModel):
    gedankengang_analyst: str = Field(
        description="Schritt-für-Schritt Analyse nach dem SSVC-Framework."
    )
    ssvc_score: str = Field(
        description="Das finale Ergebnis. Erlaubte Werte: Track, Track*, Attend, Act."
    )
    patching_vorschlag: str = Field(
        description="Konkrete Handlungsempfehlung für das IT-Team basierend auf dem SSVC-Score und der CVE."
    )


# ==========================================
# 2. PROMPTS & REGELN
# ==========================================
SYSTEM_PROMPT = """Du bist ein Senior Security Analyst. Führe eine Triage nach unserem erweiterten SSVC-Framework durch.

1. Exploitation: Ist CISA KEV 'True' ODER der EPSS-Score > 0.1 ODER existiert ein öffentlicher PoC? -> 'Active'. Sonst 'None'.
2. Exposure: Ist das Asset aus dem Internet erreichbar ODER liegt es laut NetBox in einem Interconnect-Subnetz/VRF ODER hat eine netzübergreifende Rolle (z.B. SBC)? -> 'Open'. Sonst 'Controlled'.
3. Utility: Ist der CVSS-Vektor AV:N (Network) UND AC:L (Low Complexity) UND PR:N (No Privileges) UND UI:N (No User)? -> 'Automated'. Sonst 'Laborious'.
4. Impact: Ist das Asset in einer kritischen Assetgruppe UND die CVE-Beschreibung deutet auf RCE/System-Compromise ODER Denial-of-Service (DoS) hin? -> 'High'. Sonst 'Low'.

Entscheidungsmatrix (Bewerte exakt nach diesen 16 Pfaden):
1. None + Controlled + Laborious + Low = Track
2. None + Controlled + Laborious + High = Track
3. None + Controlled + Automated + Low = Track
4. None + Controlled + Automated + High = Track*
5. None + Open + Laborious + Low = Track
6. None + Open + Laborious + High = Attend
7. None + Open + Automated + Low = Track*
8. None + Open + Automated + High = Attend
9. Active + Controlled + Laborious + Low = Track*
10. Active + Controlled + Laborious + High = Attend
11. Active + Controlled + Automated + Low = Attend
12. Active + Controlled + Automated + High = Act
13. Active + Open + Laborious + Low = Attend
14. Active + Open + Laborious + High = Act
15. Active + Open + Automated + Low = Act
16. Active + Open + Automated + High = Act
"""

# Few-Shot Beispiel (Ein perfekt gelöster historischer Fall als Vorlage)
BEISPIEL_INPUT = """
CVE: CVE-2024-3094 (xz-utils backdoor)
CISA KEV: False
EPSS: 0.08
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
CVE-Beschreibung: Malicious code in xz-utils allows unauthenticated remote code execution...
Asset: Linux-Jump-Host
Asset Exposure: Internet Facing
Business Criticality: High
"""

BEISPIEL_OUTPUT = json.dumps(
    {
        "gedankengang_analyst": "1. Exploitation: CISA KEV ist False, aber der EPSS-Score von 0.08 liegt über dem Schwellenwert von 0.1, daher 'Active'. 2. Exposure:Das Asset ist Internet Facing, also 'Open'. 3. Utility: Der CVSS-Vektor zeigt AV:N, PR:N und UI:N, also 'Automated'. 4. Impact: Die CVE-Beschreibung deutet auf RCE hin und das Asset verarbeitet kritische Daten, daher 'High'. Laut Entscheidungsmatrix ergibt das 'Act'.",
        "ssvc_score": "Act",
        "patching_vorschlag": "Sofortiges Updaten des betroffenen Systems.",
    }
)

from .enrichment import get_epss_score, is_cisa_kev, get_cve_details


def _get_ai_config():
    ext, _ = Extension.objects.get_or_create(name_id="ai_triage")
    settings_obj, _ = SystemSettings.objects.get_or_create(
        pk=1, defaults={"disable_register": settings.DISABLE_REGISTER}
    )
    provider = (settings_obj.ai_triage_provider or "openrouter").strip().lower()
    return ext, settings_obj, provider


def _build_messages(current_finding):
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": BEISPIEL_INPUT},
        {"role": "assistant", "content": BEISPIEL_OUTPUT},
        {
            "role": "user",
            "content": f"Bitte bewerte diesen neuen Fund:\n{current_finding}",
        },
    ]


def _call_openrouter(messages, settings_obj):
    api_key = (settings_obj.ai_openrouter_api_key or os.getenv("OPENROUTER_API_KEY", "")).strip()
    if not api_key:
        raise RuntimeError("ai_triage_missing_openrouter_key")
    model = (settings_obj.ai_openrouter_model or "deepseek/deepseek-v4-flash").strip()
    client = instructor.from_openai(
        OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key),
        mode=instructor.Mode.JSON,
    )
    return client.chat.completions.create(
        model=model,
        response_model=TriageErgebnis,
        messages=messages,
        temperature=0.0,
    )


def _call_azure_ai(messages, settings_obj):
    endpoint = (settings_obj.ai_azure_endpoint or "").strip()
    api_key = (settings_obj.ai_azure_api_key or "").strip()
    model = (settings_obj.ai_azure_model or "").strip()
    if not endpoint or not api_key or not model:
        raise RuntimeError("ai_triage_missing_azure_config")

    from azure.ai.inference import ChatCompletionsClient
    from azure.ai.inference.models import AssistantMessage, SystemMessage, UserMessage
    from azure.core.credentials import AzureKeyCredential

    client = ChatCompletionsClient(
        endpoint=endpoint,
        credential=AzureKeyCredential(api_key),
    )
    azure_messages = []
    for msg in messages:
        if msg["role"] == "system":
            azure_messages.append(SystemMessage(msg["content"]))
        elif msg["role"] == "assistant":
            azure_messages.append(AssistantMessage(msg["content"]))
        else:
            azure_messages.append(UserMessage(msg["content"]))

    response = client.complete(messages=azure_messages, model=model, temperature=0)
    content = response.choices[0].message.content
    if isinstance(content, list):
        text = "".join(part.text for part in content if hasattr(part, "text"))
    else:
        text = str(content)
    return TriageErgebnis.model_validate_json(text)


def triage(vuln: Vulnerability):
    extension, settings_obj, provider = _get_ai_config()
    if not extension.is_active:
        raise RuntimeError("ai_triage_disabled")

    # Enrichment: Daten von externen APIs holen
    epss_score = get_epss_score(vuln.cve_id)
    is_kev = is_cisa_kev(vuln.cve_id)

    # JIT Enrichment für fehlende CVSS oder Beschreibung
    needs_update = False
    current_cvss = vuln.cvss
    current_desc = vuln.description

    if (
        not current_cvss
        or not current_desc
        or len(current_desc) < 20
        or "No description" in current_desc
    ):
        ext_cvss, ext_desc = get_cve_details(vuln.cve_id)
        if ext_cvss and not current_cvss:
            vuln.cvss = ext_cvss
            needs_update = True
        if ext_desc and (
            not current_desc
            or len(current_desc) < 20
            or "No description" in current_desc
        ):
            vuln.description = ext_desc
            needs_update = True

    if needs_update:
        vuln.save()
    host = vuln.most_critical_host
    host_name = "Unknown Asset"
    host_criticality = "Low"

    if host:
        host_name = host.hostname or host.ip_address
        host_criticality = host.criticality or "Low"

    # Exposure: In diesem Prototyp setzen wir Controlled als Standard,
    # außer wir haben Hinweise auf Internet-Exponierung.
    exposure = "Controlled"
    if host and host.ports.filter(port_number__in=[80, 443, 8080, 8443]).exists():
        exposure = "Internet Facing (Detected via Open Ports)"

    aktueller_fund = f"""
    CVE: {vuln.cve_id}
    CISA KEV: {is_kev}
    EPSS: {epss_score}
    CVSS Vector: {vuln.cvss or "N/A"}
    CVE-Beschreibung: {vuln.description}
    Asset: {host_name}
    Asset Exposure: {exposure}
    Business Criticality: {host_criticality}
    """

    messages = _build_messages(aktueller_fund)

    import time

    start_time = time.time()
    if provider == "azure":
        response = _call_azure_ai(messages, settings_obj)
    elif provider == "openrouter":
        response = _call_openrouter(messages, settings_obj)
    else:
        raise RuntimeError("ai_triage_invalid_provider")
    proc_time = (time.time() - start_time) * 1000  # In ms

    Vulnerability.objects.filter(pk=vuln.id).update(
        ai_reason=response.gedankengang_analyst,
        ai_result=response.ssvc_score,
        ai_suggestion=response.patching_vorschlag,
        ai_proc_time=proc_time,
        ai_last_criticality=host_criticality,
    )
