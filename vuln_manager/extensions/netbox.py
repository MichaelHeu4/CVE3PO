"""NetBox module: one-way sync of server criticality from NetBox into CVE3PO.

The criticality is read from either a custom field or a tag (prefix) on NetBox
devices and virtual machines. Objects are matched to existing CVE3PO hosts by
IP address first (primary + all assigned IPs, against every known HostAddress)
and by short hostname second. Unknown NetBox objects are ignored; CVE3PO hosts
are never created by this module.

NetBox is the source of truth: a matched host with a value gets its criticality
overwritten and is marked ``criticality_source="netbox"`` (locked in the UI).
Hosts for which NetBox provides no value are released back to ``manual`` and
keep whatever criticality they currently have.
"""

import ipaddress
import logging
import re

import requests

from django.utils import timezone

from vuln_manager.models import CRITICALITY_WEIGHTS, Extension, Host, HostAddress

logger = logging.getLogger(__name__)

_PAGE_SIZE = 500
_TIMEOUT_SECONDS = 30

_LEVELS = ("Critical", "High", "Medium", "Low")


class NetboxError(Exception):
    """Raised when NetBox cannot be reached or rejects the request."""


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #


def _settings():
    from vuln_manager.models import SystemSettings

    settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)
    return settings_obj


def is_active():
    return Extension.objects.filter(name_id="netbox", is_active=True).exists()


def is_configured(settings_obj=None):
    settings_obj = settings_obj or _settings()
    return bool(
        (settings_obj.netbox_url or "").strip()
        and (settings_obj.netbox_api_token or "").strip()
        and (settings_obj.netbox_source_name or "").strip()
    )


def manages_host(host):
    """True when the host's criticality is currently owned by NetBox."""
    return getattr(host, "criticality_source", "manual") == "netbox" and is_active()


def parse_value_mapping(text):
    """Parse ``"kritisch=Critical, hoch=High"`` (commas or newlines) into a dict.

    Keys are compared case-insensitively. Targets must be one of the CVE3PO
    levels (case-insensitive); invalid lines are skipped.
    """
    mapping = {}
    for raw in re.split(r"[,\n;]", text or ""):
        if "=" not in raw:
            continue
        key, _, target = raw.partition("=")
        key = key.strip().lower()
        target = _canonical_level(target)
        if key and target:
            mapping[key] = target
    return mapping


def _canonical_level(value):
    value = str(value or "").strip().lower()
    for level in _LEVELS:
        if level.lower() == value:
            return level
    return None


def map_value(raw, mapping):
    """Translate one NetBox value into a CVE3PO level, or None."""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    key = text.lower()
    if key in mapping:
        return mapping[key]
    return _canonical_level(text)


# --------------------------------------------------------------------------- #
# NetBox API client
# --------------------------------------------------------------------------- #


def _auth_header(token):
    token = token.strip()
    # NetBox >= 4.5 v2 tokens ("nbt_<key>.<secret>") use the Bearer scheme;
    # classic v1 tokens use "Token".
    if token.startswith("nbt_"):
        return f"Bearer {token}"
    return f"Token {token}"


class NetboxClient:
    def __init__(self, base_url, token, verify_ssl=True):
        self.base_url = base_url.rstrip("/")
        if self.base_url.endswith("/api"):
            self.base_url = self.base_url[: -len("/api")]
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": _auth_header(token),
                "Accept": "application/json",
            }
        )
        self.session.verify = verify_ssl

    def _get(self, url, params=None):
        try:
            response = self.session.get(url, params=params, timeout=_TIMEOUT_SECONDS)
        except requests.exceptions.SSLError as exc:
            raise NetboxError("SSL verification failed") from exc
        except requests.RequestException as exc:
            raise NetboxError(f"connection failed: {exc.__class__.__name__}") from exc
        if response.status_code in (401, 403):
            raise NetboxError(f"authentication rejected (HTTP {response.status_code})")
        if response.status_code >= 400:
            raise NetboxError(f"HTTP {response.status_code} for {url}")
        try:
            return response.json()
        except ValueError as exc:
            raise NetboxError("unexpected non-JSON response") from exc

    def status(self):
        return self._get(f"{self.base_url}/api/status/")

    def paginate(self, path, params=None):
        params = dict(params or {})
        params.setdefault("limit", _PAGE_SIZE)
        url = f"{self.base_url}{path}"
        while url:
            data = self._get(url, params=params)
            for item in data.get("results", []) or []:
                yield item
            url = data.get("next")
            # "next" already carries the query string.
            params = None


def client_from_settings(settings_obj=None):
    settings_obj = settings_obj or _settings()
    if not is_configured(settings_obj):
        raise NetboxError("NetBox URL, API token or source name not configured")
    return NetboxClient(
        settings_obj.netbox_url.strip(),
        settings_obj.netbox_api_token,
        verify_ssl=settings_obj.netbox_verify_ssl,
    )


def check_connection(settings_obj=None):
    """Return the NetBox version string or raise NetboxError."""
    data = client_from_settings(settings_obj).status()
    return str(data.get("netbox-version") or "unknown version")


# --------------------------------------------------------------------------- #
# Value extraction
# --------------------------------------------------------------------------- #


def _flatten_custom_field(value):
    """Reduce a custom-field value (str/int/choice dict/list) to a scalar."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, dict):
        for key in ("value", "label", "name", "display"):
            if value.get(key) not in (None, ""):
                return value[key]
        return None
    return value


def extract_raw_values(obj, source_type, source_name):
    """Return every candidate raw criticality value found on a NetBox object."""
    source_name = (source_name or "").strip()
    if source_type == "tag":
        prefix = source_name.lower()
        values = []
        for tag in obj.get("tags") or []:
            for candidate in (tag.get("slug"), tag.get("name")):
                candidate = str(candidate or "")
                if candidate.lower().startswith(prefix):
                    rest = candidate[len(prefix):].strip(" -_:/=")
                    if rest:
                        values.append(rest)
        return values

    custom_fields = obj.get("custom_fields") or {}
    if source_name in custom_fields:
        value = custom_fields[source_name]
    else:
        # Be lenient about the field name's case.
        lowered = {k.lower(): v for k, v in custom_fields.items()}
        value = lowered.get(source_name.lower())
    value = _flatten_custom_field(value)
    return [value] if value not in (None, "") else []


def resolve_level(obj, source_type, source_name, mapping):
    """Highest CVE3PO level a NetBox object carries, or None."""
    best = None
    for raw in extract_raw_values(obj, source_type, source_name):
        level = map_value(raw, mapping)
        if level and CRITICALITY_WEIGHTS[level] > CRITICALITY_WEIGHTS.get(best, 0):
            best = level
    return best


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def _strip_prefix(address):
    """'10.0.0.5/24' -> '10.0.0.5' (normalised), or None."""
    if not address:
        return None
    try:
        return str(ipaddress.ip_interface(str(address).strip()).ip)
    except ValueError:
        return None


def _short_name(name):
    name = (name or "").strip().lower()
    if not name:
        return None
    try:
        ipaddress.ip_address(name)
        return None  # hostnames that are just IPs are not useful for matching
    except ValueError:
        pass
    return name.split(".", 1)[0] or None


def _collect_assigned_ips(client):
    """Map ("device"|"vm", object id) -> set of IPs from IPAM assignments."""
    assigned = {}
    for ip in client.paginate("/api/ipam/ip-addresses/"):
        obj = ip.get("assigned_object") or {}
        addr = _strip_prefix(ip.get("address"))
        if not addr:
            continue
        if obj.get("device"):
            key = ("device", obj["device"].get("id"))
        elif obj.get("virtual_machine"):
            key = ("vm", obj["virtual_machine"].get("id"))
        else:
            continue
        assigned.setdefault(key, set()).add(addr)
    return assigned


def _object_ips(obj, kind, assigned):
    ips = set(assigned.get((kind, obj.get("id")), set()))
    for field in ("primary_ip", "primary_ip4", "primary_ip6", "oob_ip"):
        ref = obj.get(field) or {}
        addr = _strip_prefix(ref.get("address")) if isinstance(ref, dict) else None
        if addr:
            ips.add(addr)
    return ips


def _build_host_index():
    by_ip = {}
    for ip, host_id in HostAddress.objects.values_list("ip_address", "host_id"):
        by_ip[ip] = host_id
    by_name = {}
    ambiguous = set()
    for host_id, ip, hostname in Host.objects.values_list(
        "id", "ip_address", "hostname"
    ):
        by_ip.setdefault(ip, host_id)
        short = _short_name(hostname)
        if not short:
            continue
        if short in by_name and by_name[short] != host_id:
            ambiguous.add(short)
        by_name[short] = host_id
    for short in ambiguous:
        by_name.pop(short, None)
    return by_ip, by_name


def match_host_id(obj, ips, by_ip, by_name):
    for ip in sorted(ips):
        if ip in by_ip:
            return by_ip[ip]
    return by_name.get(_short_name(obj.get("name")))


# --------------------------------------------------------------------------- #
# Sync
# --------------------------------------------------------------------------- #


def sync_criticality(settings_obj=None, client=None):
    """Pull criticality from NetBox and apply it to matching CVE3PO hosts."""
    settings_obj = settings_obj or _settings()
    client = client or client_from_settings(settings_obj)
    source_type = settings_obj.netbox_source_type or "custom_field"
    source_name = settings_obj.netbox_source_name or ""
    mapping = parse_value_mapping(settings_obj.netbox_value_mapping)

    # Fetch everything first so a NetBox failure aborts before any DB change.
    assigned = _collect_assigned_ips(client)
    objects = [
        ("device", obj)
        for obj in client.paginate("/api/dcim/devices/", {"exclude": "config_context"})
    ] + [
        ("vm", obj)
        for obj in client.paginate(
            "/api/virtualization/virtual-machines/", {"exclude": "config_context"}
        )
    ]

    by_ip, by_name = _build_host_index()

    # host_id -> highest level any matching NetBox object reports (None = no value)
    desired = {}
    matched_objects = 0
    for kind, obj in objects:
        host_id = match_host_id(obj, _object_ips(obj, kind, assigned), by_ip, by_name)
        if host_id is None:
            continue
        matched_objects += 1
        level = resolve_level(obj, source_type, source_name, mapping)
        current = desired.get(host_id)
        if current is None or (
            level and CRITICALITY_WEIGHTS[level] > CRITICALITY_WEIGHTS[current]
        ):
            desired[host_id] = level

    now = timezone.now()
    changed = 0
    applied = 0
    released = 0
    for host in Host.objects.filter(id__in=desired.keys()):
        level = desired[host.id]
        if level:
            applied += 1
            if host.criticality != level:
                changed += 1
            host.criticality = level
            host.criticality_source = "netbox"
            host.criticality_synced_at = now
            host.save(
                update_fields=[
                    "criticality",
                    "criticality_source",
                    "criticality_synced_at",
                ]
            )
        elif host.criticality_source == "netbox":
            released += 1
            host.criticality_source = "manual"
            host.save(update_fields=["criticality_source"])

    # Hosts NetBox managed before but no longer matches: release the lock.
    released += (
        Host.objects.filter(criticality_source="netbox")
        .exclude(id__in=[hid for hid, lvl in desired.items() if lvl])
        .update(criticality_source="manual")
    )

    result = {
        "objects": len(objects),
        "matched_hosts": len(desired),
        "matched_objects": matched_objects,
        "applied": applied,
        "changed": changed,
        "without_value": len(desired) - applied,
        "released": released,
    }
    logger.info("NetBox criticality sync finished: %s", result)
    return result


def sync_and_record():
    """Run the sync and stamp the outcome on SystemSettings. Never raises."""
    from vuln_manager.models import SystemSettings

    try:
        result = sync_criticality()
        status = (
            f"ok: {result['objects']} NetBox objects, "
            f"{result['matched_hosts']} hosts matched, "
            f"{result['changed']} changed, "
            f"{result['without_value']} without value"
        )
    except NetboxError as exc:
        result = {"error": str(exc)}
        status = f"error: {exc}"
        logger.warning("NetBox sync failed: %s", exc)
    except Exception as exc:  # pragma: no cover - defensive
        result = {"error": str(exc)}
        status = f"error: {exc.__class__.__name__}"
        logger.exception("NetBox sync failed")
    try:
        SystemSettings.objects.filter(pk=1).update(
            netbox_last_run=timezone.now(), netbox_last_status=status[:255]
        )
    except Exception:
        logger.exception("Failed to record NetBox sync status")
    return result
