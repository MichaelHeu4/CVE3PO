from vuln_manager.models import Vulnerability
import os
import json
import instructor
from pydantic import BaseModel, Field
from openai import OpenAI

# ==========================================
# 1. DATEN-SCHEMA (PYDANTIC)
# ==========================================
class TriageErgebnis(BaseModel):
    gedankengang_analyst: str = Field(description="Schritt-für-Schritt Analyse nach dem SSVC-Framework.")
    ssvc_score: str = Field(description="Das finale Ergebnis. Erlaubte Werte: Track, Track*, Attend, Act.")
    patching_vorschlag: str = Field(description="Konkrete Handlungsempfehlung für das IT-Team basierend auf dem SSVC-Score und der CVE.")

# ==========================================
# 2. API-CLIENT SETUP (OPENROUTER)
# ==========================================
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

client = instructor.from_openai(
    OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=OPENROUTER_API_KEY
    ),
    mode=instructor.Mode.JSON
)

# ==========================================
# 3. PROMPTS & REGELN
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

BEISPIEL_OUTPUT = json.dumps({
    "gedankengang_analyst": "1. Exploitation: CISA KEV ist False, aber der EPSS-Score von 0.08 liegt über dem Schwellenwert von 0.1, daher 'Active'. 2. Exposure:Das Asset ist Internet Facing, also 'Open'. 3. Utility: Der CVSS-Vektor zeigt AV:N, PR:N und UI:N, also 'Automated'. 4. Impact: Die CVE-Beschreibung deutet auf RCE hin und das Asset verarbeitet kritische Daten, daher 'High'. Laut Entscheidungsmatrix ergibt das 'Act'.",
    "ssvc_score": "Act",
    "patching_vorschlag": "Sofortiges Updaten des betroffenen Systems."
})

def triage(vuln: Vulnerability):
    # TODO Use the right params, so enrich the data with CVE Api, KEV API, SSOT, etc.
    aktueller_fund = """
    CVE: {{ vuln.cve_id }}
    CISA KEV: False
    EPSS: 0.04
    CVSS Vector: {{ vuln.cvss }}
    CVE-Beschreibung: {{ vuln.description }}
    Asset: {{ vuln.most_critical_host() }}
    Asset Exposure: Internet Facing
    Business Criticality: {{ vuln.most_critical_host().criticality }}
    """

    # ==========================================
    # 5. DER API-CALL
    # ==========================================
    try:
        response = client.chat.completions.create(
            model="deepseek/deepseek-v4-flash", # Nutzt das aktuelle DeepSeek Modell via OpenRouter
            response_model=TriageErgebnis,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": BEISPIEL_INPUT},
                {"role": "assistant", "content": BEISPIEL_OUTPUT},
                {"role": "user", "content": f"Bitte bewerte diesen neuen Fund:\n{aktueller_fund}"}
            ],
            temperature=0.0 # Wichtig für deterministische, logische Ausgaben!
        )

        Vulnerability.objects.filter(pk=vuln.id).update(ai_reason=response.gedankengang_analyst)
        Vulnerability.objects.filter(pk=vuln.id).update(ai_result=response.ssvc_score)
        Vulnerability.objects.filter(pk=vuln.id).update(ai_suggestion=response.patching_vorschlag)

    except Exception as e:
        print(f"❌ Fehler bei der API-Anfrage: {e}")