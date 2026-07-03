from .enrichment import get_epss_score, is_cisa_kev, get_cve_details
from vuln_manager.models import Extension, SystemSettings, Vulnerability, Software
import os
import json
import time
import instructor
from django.conf import settings
from django.utils import timezone
from pydantic import BaseModel, Field
from openai import AzureOpenAI, OpenAI


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


class SoftwareTriageErgebnis(BaseModel):
    gedankengang_analyst: str = Field(
        description="Schritt-für-Schritt Analyse nach dem SSVC-Software-Schema (Exploitation, Chaining & Utility, und getrennte Bewertung für Cluster 1, 2, 3 und 4)."
    )
    cluster_1_score: str = Field(
        description="SSVC-Score für Cluster 1 (Open + High). Erlaubte Werte: Track, Attend, Act."
    )
    cluster_2_score: str = Field(
        description="SSVC-Score für Cluster 2 (Open + Low). Erlaubte Werte: Track, Attend, Act."
    )
    cluster_3_score: str = Field(
        description="SSVC-Score für Cluster 3 (Controlled + High). Erlaubte Werte: Track, Attend, Act."
    )
    cluster_4_score: str = Field(
        description="SSVC-Score für Cluster 4 (Controlled + Low). Erlaubte Werte: Track, Attend, Act."
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
EPSS: 0.8
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
CVE-Beschreibung: Malicious code in xz-utils allows unauthenticated remote code execution...
Asset: Linux-Jump-Host
Asset Exposure: Internet Facing
Business Criticality: High
"""

BEISPIEL_OUTPUT = json.dumps(
    {
        "gedankengang_analyst": "1. Exploitation: CISA KEV ist False, aber der EPSS-Score von 0.8 liegt über dem Schwellenwert von 0.1, daher 'Active'. 2. Exposure:Das Asset ist Internet Facing, also 'Open'. 3. Utility: Der CVSS-Vektor zeigt AV:N, PR:N und UI:N, also 'Automated'. 4. Impact: Die CVE-Beschreibung deutet auf RCE hin und das Asset verarbeitet kritische Daten, daher 'High'. Laut Entscheidungsmatrix ergibt das 'Act'.",
        "ssvc_score": "Act",
        "patching_vorschlag": "Sofortiges Updaten des betroffenen Systems.",
    }
)

SYSTEM_PROMPT_SOFTWARE = """Du bist ein Expert Security Analyst und bewertest Software-Komponenten, die mehrere Sicherheitslücken aufweisen, für verschiedene Host-Cluster.
Führe eine Triage nach unserem SSVC-Software-Framework durch.

SSVC unterteilt in globale Software-Faktoren und lokale Cluster-Faktoren:
1. Aggregated Exploitation (Global): Ist für mindestens eine CVE der CISA KEV 'True' ODER der EPSS-Score > 0.1? -> 'Active'. Sonst 'None'.
2. Chaining & Utility (Global): Deuten die CVE-Beschreibungen auf eine Angriffskette hin (z.B. Info Leak + Exploitation) ODER ist bei mindestens einer CVE der Vektor AV:N UND AC:L UND PR:N UND UI:N? -> 'Synergistic'. Sonst 'Isolated'.
3. Exposure (Lokal): Ist das Host-Cluster netztechnisch exponiert (Internet/Interconnect)? -> 'Open'. Sonst (intern/isoliert) -> 'Controlled'.
4. Impact (Lokal): Gehört das Host-Cluster zu einer kritischen Assetgruppe (Risiko RCE/DoS)? -> 'High'. Sonst -> 'Low'.

Host-Cluster Definition:
- Cluster 1: Open + High (Exposure: Open, Impact: High)
- Cluster 2: Open + Low (Exposure: Open, Impact: Low)
- Cluster 3: Controlled + High (Exposure: Controlled, Impact: High)
- Cluster 4: Controlled + Low (Exposure: Controlled, Impact: Low)

Entscheidungsmatrix (Bewerte jedes Cluster separat nach diesen 16 Pfaden):
1. None + Controlled + Isolated + Low = Track
2. None + Controlled + Isolated + High = Track
3. None + Controlled + Synergistic + Low = Track
4. None + Controlled + Synergistic + High = Track
5. None + Open + Isolated + Low = Track
6. None + Open + Isolated + High = Attend
7. None + Open + Synergistic + Low = Track
8. None + Open + Synergistic + High = Attend
9. Active + Controlled + Isolated + Low = Track
10. Active + Controlled + Isolated + High = Attend
11. Active + Controlled + Synergistic + Low = Attend
12. Active + Controlled + Synergistic + High = Act
13. Active + Open + Isolated + Low = Attend
14. Active + Open + Isolated + High = Act
15. Active + Open + Synergistic + Low = Act
16. Active + Open + Synergistic + High = Act
"""

BEISPIEL_INPUT_SOFTWARE = """
Software: Apache HTTP Server v2.4.48
CVE-Details:
- CVE-2021-40438: CISA KEV: True, EPSS: 0.85, CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H. Beschreibung: Server-side request forgery (SSRF) bypass in mod_proxy allows remote code execution or data exposure.
- CVE-2021-33193: CISA KEV: False, EPSS: 0.05, CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L. Beschreibung: Denial of service when handling large request bodies.
"""

BEISPIEL_OUTPUT_SOFTWARE = json.dumps(
    {
        "gedankengang_analyst": "1. Aggregated Exploitation (Global): CVE-2021-40438 hat CISA KEV 'True' und EPSS 0.85 (> 0.1), also 'Active'. 2. Chaining & Utility (Global): CVE-2021-40438 hat AV:N/AC:L/PR:N/UI:N, also 'Synergistic'. 3. Cluster 1 (Open + High): Active + Open + Synergistic + High = Act. 4. Cluster 2 (Open + Low): Active + Open + Synergistic + Low = Act. 5. Cluster 3 (Controlled + High): Active + Controlled + Synergistic + High = Act. 6. Cluster 4 (Controlled + Low): Active + Controlled + Synergistic + Low = Attend.",
        "cluster_1_score": "Act",
        "cluster_2_score": "Act",
        "cluster_3_score": "Act",
        "cluster_4_score": "Attend",
    }
)

BEISPIEL_INPUT_SOFTWARE_2 = """
Software: PostgreSQL Database v14.1
CVE-Details:
- CVE-2022-1597: CISA KEV: False, EPSS: 0.15, CVSS Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H. Beschreibung: A privilege escalation vulnerability exists in PostgreSQL copy commands where an authenticated high-privilege attacker can trigger RCE.
"""

BEISPIEL_OUTPUT_SOFTWARE_2 = json.dumps(
    {
        "gedankengang_analyst": "1. Aggregated Exploitation (Global): CVE-2022-1597 hat EPSS 0.15 (> 0.1), also 'Active'. 2. Chaining & Utility (Global): Die CVE erfordert hohe Privilegien (PR:H) und hohe Komplexität (AC:H). Die Beschreibung deutet auf keinen Chain-Angriff hin, also 'Isolated'. 3. Cluster 1 (Open + High): Active + Open + Isolated + High = Act. 4. Cluster 2 (Open + Low): Active + Open + Isolated + Low = Attend. 5. Cluster 3 (Controlled + High): Active + Controlled + Isolated + High = Attend. 6. Cluster 4 (Controlled + Low): Active + Controlled + Isolated + Low = Track.",
        "cluster_1_score": "Act",
        "cluster_2_score": "Attend",
        "cluster_3_score": "Attend",
        "cluster_4_score": "Track",
    }
)

BEISPIEL_INPUT_SOFTWARE_3 = """
Software: Node.js Express Framework v4.16.0
CVE-Details:
- CVE-2023-28154: CISA KEV: False, EPSS: 0.02, CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N. Beschreibung: IP spoofing vulnerability in express request handling allows unauthenticated remote bypass of rate limits.
"""

BEISPIEL_OUTPUT_SOFTWARE_3 = json.dumps(
    {
        "gedankengang_analyst": "1. Aggregated Exploitation (Global): CVE-2023-28154 hat CISA KEV 'False' und EPSS 0.02 (< 0.1), also 'None'. 2. Chaining & Utility (Global): CVE-2023-28154 hat den Vektor AV:N/AC:L/PR:N/UI:N, also 'Synergistic'. 3. Cluster 1 (Open + High): None + Open + Synergistic + High = Attend. 4. Cluster 2 (Open + Low): None + Open + Synergistic + Low = Track. 5. Cluster 3 (Controlled + High): None + Controlled + Synergistic + High = Track. 6. Cluster 4 (Controlled + Low): None + Controlled + Synergistic + Low = Track.",
        "cluster_1_score": "Attend",
        "cluster_2_score": "Track",
        "cluster_3_score": "Track",
        "cluster_4_score": "Track",
    }
)

BEISPIEL_INPUT_SOFTWARE_4 = """
Software: Redis In-Memory Store v6.2.0
CVE-Details:
- CVE-2023-4516: CISA KEV: False, EPSS: 0.005, CVSS Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N. Beschreibung: Local information leak in Redis CLI configuration parsing under very specific conditions.
"""

BEISPIEL_OUTPUT_SOFTWARE_4 = json.dumps(
    {
        "gedankengang_analyst": "1. Aggregated Exploitation (Global): CVE-2023-4516 hat CISA KEV 'False' und EPSS 0.005 (< 0.1), also 'None'. 2. Chaining & Utility (Global): Der Vektor ist lokal (AV:L), komplex (AC:H) und erfordert Benutzerinteraktion (UI:R), also 'Isolated'. 3. Cluster 1 (Open + High): None + Open + Isolated + High = Attend. 4. Cluster 2 (Open + Low): None + Open + Isolated + Low = Track. 5. Cluster 3 (Controlled + High): None + Controlled + Isolated + High = Track. 6. Cluster 4 (Controlled + Low): None + Controlled + Isolated + Low = Track.",
        "cluster_1_score": "Attend",
        "cluster_2_score": "Track",
        "cluster_3_score": "Track",
        "cluster_4_score": "Track",
    }
)


def _get_ai_config():
    ext, _ = Extension.objects.get_or_create(name_id="ai_triage")
    settings_obj, _ = SystemSettings.objects.get_or_create(
        pk=1, defaults={"disable_register": settings.DISABLE_REGISTER}
    )
    provider = (settings_obj.ai_triage_provider or "openrouter").strip().lower()
    return ext, settings_obj, provider


def _build_messages(current_finding, system_prompt=SYSTEM_PROMPT):
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": BEISPIEL_INPUT},
        {"role": "assistant", "content": BEISPIEL_OUTPUT},
        {
            "role": "user",
            "content": f"Bitte bewerte diesen neuen Fund:\n{current_finding}",
        },
    ]


def _call_openrouter(messages, settings_obj, response_model=TriageErgebnis):
    api_key = (
        settings_obj.ai_openrouter_api_key or os.getenv(
            "OPENROUTER_API_KEY", "")
    ).strip()
    if not api_key:
        raise RuntimeError("ai_triage_missing_openrouter_key")
    model = (settings_obj.ai_openrouter_model or "deepseek/deepseek-v4-flash").strip()
    client = instructor.from_openai(
        OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key),
        mode=instructor.Mode.JSON,
    )
    return client.chat.completions.create(
        model=model,
        response_model=response_model,
        messages=messages,
        temperature=0.0,
    )


def _call_azure_ai(messages, settings_obj, response_model=TriageErgebnis):
    endpoint = (settings_obj.ai_azure_endpoint or "").strip()
    api_key = (settings_obj.ai_azure_api_key or "").strip()
    deployment = (settings_obj.ai_azure_model or "").strip()
    api_version = (settings_obj.ai_azure_api_version or "").strip()
    if not endpoint or not api_key or not deployment:
        raise RuntimeError("ai_triage_missing_azure_config")

    if "openai.azure.com" in endpoint or "cognitiveservices.azure.com" in endpoint:
        azure_client = AzureOpenAI(
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_version or "2025-01-01-preview",
        )
        client = instructor.from_openai(
            azure_client, mode=instructor.Mode.JSON)
        return client.chat.completions.create(
            model=deployment,
            response_model=response_model,
            messages=messages,
            temperature=0.0,
        )

    from azure.ai.inference import ChatCompletionsClient
    from azure.ai.inference.models import AssistantMessage, SystemMessage, UserMessage
    from azure.core.credentials import AzureKeyCredential

    client_kwargs = {
        "endpoint": endpoint,
        "credential": AzureKeyCredential(api_key),
    }
    if api_version:
        client_kwargs["api_version"] = api_version
    client = ChatCompletionsClient(**client_kwargs)
    azure_messages = []
    for msg in messages:
        if msg["role"] == "system":
            azure_messages.append(SystemMessage(msg["content"]))
        elif msg["role"] == "assistant":
            azure_messages.append(AssistantMessage(msg["content"]))
        else:
            azure_messages.append(UserMessage(msg["content"]))

    response = client.complete(
        messages=azure_messages, model=deployment, temperature=0)
    content = response.choices[0].message.content
    if isinstance(content, list):
        text = "".join(part.text for part in content if hasattr(part, "text"))
    else:
        text = str(content)
    return response_model.model_validate_json(text)


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
    if host:
        exposure = "Open" if host.is_exposed else "Controlled"

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

    custom_prompt = settings_obj.ai_cve_system_prompt or SYSTEM_PROMPT
    messages = _build_messages(aktueller_fund, system_prompt=custom_prompt)

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


def triage_software(software: Software):
    extension, settings_obj, provider = _get_ai_config()
    if not extension.is_active:
        raise RuntimeError("ai_triage_disabled")

    # Exclude false positives
    vulns = software.vulnerabilities.exclude(status="false_positive")

    # 1. Triage each vulnerability first
    for vuln in vulns:
        triage(vuln)

    # If no vulnerabilities, default to Track
    if not vulns.exists():
        software.ai_reason = "No vulnerabilities associated with this software."
        software.ai_result_cluster_1 = "Track"
        software.ai_result_cluster_2 = "Track"
        software.ai_result_cluster_3 = "Track"
        software.ai_result_cluster_4 = "Track"
        software.ai_triage_time = timezone.now()
        software.save()
        return

    # Build the prompt payload
    vuln_details_list = []
    for v in vulns:
        is_kev = is_cisa_kev(v.cve_id)
        epss_score = get_epss_score(v.cve_id)
        vuln_details_list.append(
            f"- {v.cve_id}: CISA KEV: {is_kev}, EPSS: {epss_score}, CVSS Vector: {v.cvss or 'N/A'}. Beschreibung: {v.description}"
        )
    vuln_details_str = "\n".join(vuln_details_list)

    aktueller_fund = f"""
Software: {software.name} {software.version or ''}
CVE-Details:
{vuln_details_str}
"""

    custom_sw_prompt = settings_obj.ai_software_system_prompt or SYSTEM_PROMPT_SOFTWARE
    messages = [
        {"role": "system", "content": custom_sw_prompt},
        # Beispiel 1: Active + Synergistic
        {"role": "user", "content": BEISPIEL_INPUT_SOFTWARE},
        {"role": "assistant", "content": BEISPIEL_OUTPUT_SOFTWARE},
        # Beispiel 2: Active + Isolated
        {"role": "user", "content": BEISPIEL_INPUT_SOFTWARE_2},
        {"role": "assistant", "content": BEISPIEL_OUTPUT_SOFTWARE_2},
        # Beispiel 3: None + Synergistic
        {"role": "user", "content": BEISPIEL_INPUT_SOFTWARE_3},
        {"role": "assistant", "content": BEISPIEL_OUTPUT_SOFTWARE_3},
        # Beispiel 4: None + Isolated
        {"role": "user", "content": BEISPIEL_INPUT_SOFTWARE_4},
        {"role": "assistant", "content": BEISPIEL_OUTPUT_SOFTWARE_4},
        {
            "role": "user",
            "content": f"Bitte bewerte diese Software-Komponente:\n{aktueller_fund}",
        },
    ]

    if provider == "azure":
        response = _call_azure_ai(messages, settings_obj, response_model=SoftwareTriageErgebnis)
    elif provider == "openrouter":
        response = _call_openrouter(messages, settings_obj, response_model=SoftwareTriageErgebnis)
    else:
        raise RuntimeError("ai_triage_invalid_provider")

    c1_score = response.cluster_1_score
    c2_score = response.cluster_2_score
    c3_score = response.cluster_3_score
    c4_score = response.cluster_4_score

    # Apply Escalation Rules (Vulnerability Debt)
    # Rule 1: Total CVEs > 10 => Track becomes Attend
    total_cves = vulns.count()
    if total_cves > 10:
        if c1_score == "Track": c1_score = "Attend"
        if c2_score == "Track": c2_score = "Attend"
        if c3_score == "Track": c3_score = "Attend"
        if c4_score == "Track": c4_score = "Attend"

    # Rule 2: > 3 CVEs that force 'Attend' (meaning status is Attend or Act) => Attend becomes Act
    attend_forcing_count = vulns.filter(ai_result__in=["Attend", "Act"]).count()
    if attend_forcing_count > 3:
        if c1_score == "Attend": c1_score = "Act"
        if c2_score == "Attend": c2_score = "Act"
        if c3_score == "Attend": c3_score = "Act"
        if c4_score == "Attend": c4_score = "Act"

    # Save to database
    software.ai_reason = response.gedankengang_analyst
    software.ai_result_cluster_1 = c1_score
    software.ai_result_cluster_2 = c2_score
    software.ai_result_cluster_3 = c3_score
    software.ai_result_cluster_4 = c4_score
    software.ai_triage_time = timezone.now()
    software.save()
