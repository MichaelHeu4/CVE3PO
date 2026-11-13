import logging
import requests
import re
from html import unescape

logger = logging.getLogger(__name__)

_kev_cache = None

def sync_cisa_kev_to_db():
    from vuln_manager.models import CisaKevEntry
    try:
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            
            existing = set(CisaKevEntry.objects.values_list('cve_id', flat=True))
            new_entries = []
            for v in vulns:
                cve_id = v.get("cveID", "").upper()
                if cve_id and cve_id not in existing:
                    new_entries.append(CisaKevEntry(cve_id=cve_id))
                    existing.add(cve_id)
            
            if new_entries:
                CisaKevEntry.objects.bulk_create(new_entries)
            return len(new_entries)
    except Exception:
        logger.exception("Error bulk syncing CISA KEV")
    return 0


def get_epss_score(cve_id):
    """
    Holt den EPSS-Score von der FIRST.org API mit DB-Caching.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    
    cve_upper = cve_id.upper()
    try:
        from vuln_manager.models import EpssEntry
        cached = EpssEntry.objects.filter(cve_id=cve_upper).first()
        if cached:
            return cached.score
    except Exception:
        logger.exception("Error reading EPSS cache")

    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("data"):
                score = float(data["data"][0].get("epss", 0.0))
                percentile = float(data["data"][0].get("percentile", 0.0))
                try:
                    from vuln_manager.models import EpssEntry
                    EpssEntry.objects.update_or_create(
                        cve_id=cve_upper,
                        defaults={"score": score, "percentile": percentile}
                    )
                except Exception:
                    logger.exception("Error saving EPSS to cache")
                return score
    except Exception:
        logger.exception("Error fetching EPSS for %s", cve_id)
    return 0.0


def is_cisa_kev(cve_id):
    """
    Prüft, ob eine CVE in der CISA Known Exploited Vulnerabilities Liste steht.
    Nutzt lokalen DB-Cache und JIT Sync falls DB leer.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return False
    
    cve_upper = cve_id.upper()
    try:
        from vuln_manager.models import CisaKevEntry
        if CisaKevEntry.objects.count() == 0:
            logger.info("CISA KEV cache empty, starting JIT sync")
            sync_cisa_kev_to_db()
        
        return CisaKevEntry.objects.filter(cve_id=cve_upper).exists()
    except Exception:
        logger.exception("Error checking CISA KEV cache for %s", cve_id)
        
    global _kev_cache
    if _kev_cache is None:
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                _kev_cache = [v.get("cveID") for v in data.get("vulnerabilities", [])]
            else:
                _kev_cache = []
        except Exception:
            logger.exception("Error fetching CISA KEV")
            _kev_cache = []
    return cve_upper in {entry.upper() for entry in _kev_cache if entry}
            
def get_cve_details(cve_id):
    cvss, description, _ = get_cve_enrichment(cve_id)
    return cvss, description


def get_cve_enrichment(cve_id):
    """
    Return (CVSS vector, description, severity), with None for unavailable data.
    Read CVE JSON manufacturer ratings too: new CVEs may not have CVSS yet.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None, None, None

    cvss = description = severity = None
        
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data:
                cvss = _extract_cvss_vector(data)
                description = _extract_description(data)
                severity = _extract_severity(data, cvss)
    except Exception:
        logger.exception("Error fetching CVE details for %s", cve_id)
        
    if severity is None:
        from vuln_manager.utils.osv_auto import (
            query_nvd_by_cve_id, _extract_nvd_cvss_and_severity,
            extract_nvd_description,
        )
        record = query_nvd_by_cve_id(cve_id)
        if record:
            nvd_cvss, severity = _extract_nvd_cvss_and_severity(record)
            cvss = nvd_cvss or cvss
            nvd_description = extract_nvd_description(record)
            if not description and nvd_description != "No description provided.":
                description = nvd_description
    return cvss, description, severity


def _extract_severity(data, vector=None):
    from vuln_manager.parser.osvscanner import (
        extract_cvss_base_score, normalize_severity_from_score,
    )
    score = extract_cvss_base_score(vector)
    if score is not None:
        return normalize_severity_from_score(score)

    def search(node):
        if isinstance(node, dict):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0", "cvssData"):
                metric = node.get(key)
                if isinstance(metric, dict):
                    try:
                        score = float(metric["baseScore"])
                        if 0 <= score <= 10:
                            return normalize_severity_from_score(score)
                    except (KeyError, TypeError, ValueError):
                        pass
            for key in ("baseSeverity", "severity"):
                value = node.get(key)
                if isinstance(value, str) and value.lower() in {
                    "critical", "high", "medium", "low", "none",
                }:
                    return "info" if value.lower() == "none" else value.lower()
            # CVE JSON 5: CNA may publish a textual rating without any CVSS.
            other = node.get("other")
            if isinstance(other, dict) and other.get("type") == "Textual description of severity":
                value = (other.get("content") or {}).get("text")
                if isinstance(value, str) and value.strip().lower() in {"critical", "high", "medium", "low"}:
                    return value.strip().lower()
            for value in node.values():
                found = search(value)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for value in node:
                found = search(value)
                if found is not None:
                    return found
        return None

    return search(data)


def apply_cve_enrichment(vuln, details, *, user=None, actor=None):
    """Update existing findings without replacing known ratings with missing data."""
    from vuln_manager.utils.audit import log_vulnerability_event

    cvss, description, severity = details
    fields = []
    for field, value in (("cvss", cvss), ("description", description), ("severity", severity)):
        if value is not None and value != "" and getattr(vuln, field) != value:
            setattr(vuln, field, value)
            fields.append(field)
    if fields:
        vuln.save(update_fields=fields)
        log_vulnerability_event(
            vuln, "updated", user=user, actor=actor,
            details={"source": actor or "manual_enrich", "fields": fields},
        )
    return fields


def _extract_description(data):
    def _clean_text(value):
        if not isinstance(value, str):
            return None
        text = unescape(re.sub(r"<[^>]+>", " ", value))
        text = re.sub(r"\s+", " ", text).strip()
        return text or None

    def _from_descriptions(descriptions):
        if not isinstance(descriptions, list):
            return None
        english_value = None
        fallback_value = None
        for entry in descriptions:
            if not isinstance(entry, dict):
                continue
            value = _clean_text(entry.get("value"))
            if not value:
                media = entry.get("supportingMedia") or []
                for media_item in media:
                    if not isinstance(media_item, dict):
                        continue
                    value = _clean_text(media_item.get("value"))
                    if value:
                        break
            if not value:
                continue
            if entry.get("lang") == "en":
                english_value = value
                break
            if not fallback_value:
                fallback_value = value
        return english_value or fallback_value

    direct = _clean_text(data.get("summary") or data.get("description"))
    if direct:
        return direct

    description = _from_descriptions(data.get("descriptions"))
    if description:
        return description

    containers = data.get("containers") or {}
    for container_name in ("cna", "adp"):
        container = containers.get(container_name)
        if isinstance(container, dict):
            description = _from_descriptions(container.get("descriptions"))
            if description:
                return description
        elif isinstance(container, list):
            for item in container:
                if not isinstance(item, dict):
                    continue
                description = _from_descriptions(item.get("descriptions"))
                if description:
                    return description
    return None


def _extract_cvss_vector(data):
    direct = data.get("cvss-vector")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()

    def _looks_like_vector(value):
        if not isinstance(value, str):
            return False
        candidate = value.strip()
        return candidate.startswith("CVSS:") or "AV:" in candidate

    def _search(node):
        if isinstance(node, dict):
            for key in ("vectorString", "cvssVector", "cvss-vector", "cvss"):
                value = node.get(key)
                if _looks_like_vector(value):
                    return value.strip()
            for value in node.values():
                found = _search(value)
                if found:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = _search(item)
                if found:
                    return found
        return None

    return _search(data)
