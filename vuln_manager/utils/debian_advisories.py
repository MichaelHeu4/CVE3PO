"""Read Debian's published DSA/DLA lists, not advisory page HTML."""
import re
from datetime import timedelta

import requests
from django.db.models import Q
from django.utils import timezone

from vuln_manager.models import CTIItem, DebianAdvisorySnapshot

SOURCES = {
    kind: f"https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/{kind}/list"
    for kind in ("DSA", "DLA")
}
ADVISORY_RE = re.compile(r"\b(?:DSA|DLA)-\d+-\d+\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
HEADER_RE = re.compile(r"^\[[^\]]+\]\s+((?:DSA|DLA)-\d+-\d+)\s+", re.I)
FIX_RE = re.compile(r"^\s*\[([a-z0-9][a-z0-9-]*)\]\s+-\s+([a-z0-9][a-z0-9+.-]*)\s+(\S+)")
MAX_BYTES = 8 * 1024 * 1024


def advisory_ids(item):
    # Prefer identifiers in the headline: a news item may mention unrelated
    # advisories in its body. A short official feed can put the ID in the text.
    title_ids = ADVISORY_RE.findall(item.title or "")
    return sorted({value.upper() for value in (title_ids or ADVISORY_RE.findall(item.summary or ""))})


def parse_advisory_list(text, kind):
    from vuln_manager.utils.debian_cti import VERSION_RE
    records = {}
    current = None
    in_cves = False
    for line in text.splitlines():
        header = HEADER_RE.match(line)
        if header:
            key = header.group(1).upper()
            current = {"cves": [], "fixes": []} if key.startswith(kind + "-") else None
            in_cves = False
            if current is not None:
                records[key] = current
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("{"):
            in_cves = True
        if in_cves:
            current["cves"].extend(value.upper() for value in CVE_RE.findall(line))
            if "}" in line:
                in_cves = False
            continue
        fix = FIX_RE.match(line)
        if fix:
            release, package, version = fix.groups()
            if VERSION_RE.fullmatch(version):
                current["fixes"].append({"release": release, "source_package": package, "fixed_version": version})
    for record in records.values():
        record["cves"] = sorted(set(record["cves"]))
    if not records:
        raise ValueError(f"No {kind} records found in Debian advisory list")
    return records


def refresh_advisory_snapshots(kinds):
    now = timezone.now()
    for kind in kinds:
        if kind not in SOURCES:
            continue
        snapshot, _ = DebianAdvisorySnapshot.objects.get_or_create(kind=kind)
        if snapshot.fetched_at and snapshot.fetched_at >= now - timedelta(hours=24):
            continue
        claimed = DebianAdvisorySnapshot.objects.filter(pk=snapshot.pk).filter(Q(last_attempt__isnull=True) | Q(last_attempt__lt=now-timedelta(hours=1))).update(last_attempt=now)
        if not claimed:
            continue
        try:
            with requests.get(SOURCES[kind], timeout=(10, 60), stream=True, allow_redirects=False) as response:
                response.raise_for_status()
                if response.status_code != 200:
                    raise ValueError(f"Unexpected advisory list status {response.status_code}")
                content = bytearray()
                for chunk in response.iter_content(65536):
                    content.extend(chunk)
                    if len(content) > MAX_BYTES:
                        raise ValueError("Advisory list exceeds size limit")
            data = parse_advisory_list(content.decode("utf-8"), kind)
            DebianAdvisorySnapshot.objects.filter(pk=snapshot.pk).update(data=data, fetched_at=timezone.now(), error="")
        except Exception as exc:
            # Keep the last successful snapshot and report staleness in the UI.
            DebianAdvisorySnapshot.objects.filter(pk=snapshot.pk).update(error=str(exc)[:500])


def apply_advisory_data(item, snapshots):
    ids = advisory_ids(item)
    records = {}
    for advisory_id in ids:
        snapshot = snapshots.get(advisory_id[:3])
        if not snapshot or not snapshot.fetched_at:
            if advisory_id in item.debian_advisories:
                records[advisory_id] = item.debian_advisories[advisory_id]
            continue
        data = snapshot.data.get(advisory_id)
        if isinstance(data, dict):
            records[advisory_id] = {"cves": data.get("cves", []), "fixes": data.get("fixes", []), "fetched_at": snapshot.fetched_at.isoformat()}
    cves = sorted(set(item.feed_cves or []) | {cve for data in records.values() for cve in data["cves"]})
    if records != item.debian_advisories or cves != item.cves:
        item.debian_advisories = records
        item.cves = cves
        item.save(update_fields=["debian_advisories", "cves"])
        return True
    return False


def enrich_existing_items():
    """Enrich existing as well as newly imported items, even without feed CVEs."""
    items = list(CTIItem.objects.all())
    kinds = {value[:3] for item in items for value in advisory_ids(item)}
    if not kinds:
        return
    refresh_advisory_snapshots(kinds)
    snapshots = {s.kind: s for s in DebianAdvisorySnapshot.objects.filter(kind__in=kinds)}
    from vuln_manager.utils.cti import suggest_matches
    for item in items:
        if advisory_ids(item) and apply_advisory_data(item, snapshots):
            suggest_matches(item)
