import logging
import time

import requests

from django.db import connections

from vuln_manager.models import Extension, Host, Port, Scan

logger = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"

# Free-plan Shodan allows ~1 request/second; keep bulk scans polite.
_BULK_DELAY_SECONDS = 1.0


def get_api_key():
    """Return the configured Shodan API key if the module is active, else None."""
    ext = Extension.objects.filter(name_id="shodan", is_active=True).first()
    if not ext or not ext.api_token:
        return None
    return ext.api_token.strip() or None


def lookup_host(ip, api_key):
    """
    Query the Shodan host endpoint for a single IP.

    Returns the parsed JSON dict when the host is known to Shodan, or None
    when it is not found (HTTP 404), the key is invalid, or the call fails.
    """
    try:
        response = requests.get(
            SHODAN_HOST_URL.format(ip=ip),
            params={"key": api_key},
            timeout=15,
        )
    except Exception:
        logger.exception("Shodan lookup request failed for %s", ip)
        return None

    if response.status_code == 404:
        # Shodan has no record for this IP -> not internet-exposed per Shodan.
        return None
    if response.status_code == 401:
        logger.warning("Shodan lookup rejected (invalid API key)")
        return None
    if response.status_code == 429:
        logger.warning("Shodan rate limit hit for %s", ip)
        return None

    try:
        response.raise_for_status()
        return response.json()
    except Exception:
        logger.exception("Shodan lookup returned an unexpected response for %s", ip)
        return None


def _service_label(service_entry):
    shodan_meta = service_entry.get("_shodan") or {}
    label = (
        shodan_meta.get("module")
        or service_entry.get("product")
        or service_entry.get("transport")
        or "unknown"
    )
    return str(label)[:100]


def enrich_host_with_shodan(host_id, api_key=None):
    """
    Pull ports/services for one host from Shodan.

    On a hit the host's ports are upserted under a dedicated SHODAN scan and
    the host's Internet Exposure flag (is_exposed) is forced to True.
    Returns a small result dict describing the outcome.
    """
    host = Host.objects.filter(pk=host_id).first()
    if not host:
        return {"status": "missing"}

    key = api_key or get_api_key()
    if not key:
        return {"status": "no_key"}

    data = lookup_host(host.ip_address, key)
    if data is None:
        return {"status": "not_found", "ip": host.ip_address}

    scan_obj, _ = Scan.objects.get_or_create(
        scan_type="SHODAN", defaults={"raw_file": None}
    )

    services = data.get("data", []) or []
    seen_ports = set()
    created = 0
    for service_entry in services:
        port_number = service_entry.get("port")
        if not port_number:
            continue
        port_number = int(port_number)
        if port_number in seen_ports:
            continue
        seen_ports.add(port_number)

        service_name = _service_label(service_entry)
        port_obj, was_created = Port.objects.get_or_create(
            host=host,
            scan=scan_obj,
            port_number=port_number,
            defaults={"service_name": service_name, "state": "open"},
        )
        if was_created:
            created += 1
        elif port_obj.service_name != service_name or port_obj.state != "open":
            port_obj.service_name = service_name
            port_obj.state = "open"
            port_obj.save(update_fields=["service_name", "state"])

    # Found on Shodan => reachable from the internet. Auto-set the exposure flag.
    newly_exposed = False
    if not host.is_exposed:
        host.is_exposed = True
        host.save(update_fields=["is_exposed"])
        newly_exposed = True

    return {
        "status": "found",
        "ip": host.ip_address,
        "ports": sorted(seen_ports),
        "ports_created": created,
        "newly_exposed": newly_exposed,
    }


def refresh_all_hosts():
    """
    Run a Shodan lookup for every known host. Intended to be called from a
    background thread or the scheduler. Closes DB connections when done so a
    worker thread never leaks SQLite handles.
    """
    key = get_api_key()
    if not key:
        logger.info("Shodan refresh skipped: module inactive or no API key set")
        return {"status": "no_key"}

    host_ids = list(Host.objects.values_list("id", flat=True))
    found = 0
    exposed = 0
    try:
        for host_id in host_ids:
            result = enrich_host_with_shodan(host_id, api_key=key)
            if result.get("status") == "found":
                found += 1
                if result.get("newly_exposed"):
                    exposed += 1
            time.sleep(_BULK_DELAY_SECONDS)
    finally:
        connections.close_all()

    logger.info(
        "Shodan refresh finished: %s hosts checked, %s found, %s newly exposed",
        len(host_ids),
        found,
        exposed,
    )
    return {
        "status": "done",
        "hosts": len(host_ids),
        "found": found,
        "newly_exposed": exposed,
    }
