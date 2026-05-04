import requests
import re
from html import unescape

_kev_cache = None

def get_epss_score(cve_id):
    """
    Holt den EPSS-Score von der FIRST.org API.
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return 0.0
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("data"):
                return float(data["data"][0].get("epss", 0.0))
    except Exception as e:
        print(f"Error fetching EPSS for {cve_id}: {e}")
    return 0.0

def is_cisa_kev(cve_id):
    """
    Prüft, ob eine CVE in der CISA Known Exploited Vulnerabilities Liste steht.
    Nutzt einen einfachen In-Memory Cache für den aktuellen Lauf.
    """
    global _kev_cache
    if not cve_id or not cve_id.startswith("CVE-"):
        return False
    
    if _kev_cache is None:
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                _kev_cache = [v.get("cveID") for v in data.get("vulnerabilities", [])]
            else:
                _kev_cache = []
        except Exception as e:
            print(f"Error fetching CISA KEV: {e}")
            _kev_cache = []
    return cve_id.upper() in {entry.upper() for entry in _kev_cache if entry}
            
def get_cve_details(cve_id):
    """
    Holt CVSS und Beschreibung von der CIRCL CVE API (Fallback auf NVD-ähnliche Daten).
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None, None
        
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data:
                cvss = _extract_cvss_vector(data)
                description = _extract_description(data)
                return cvss, description
    except Exception as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")
        
    return None, None


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
