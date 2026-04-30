import requests

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
                cvss = data.get("cvss-vector") or data.get("cvss")
                description = data.get("summary")
                return cvss, description
    except Exception as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")
        
    return None, None
