"""Debian source-package assessments using the Debian Security Tracker."""
import re
import json
from datetime import timedelta

import ijson
import requests
from django.db.models import F, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from vuln_manager.models import DebianTrackerSnapshot, HostSoftwareRelationship

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
# These bounds apply to the decompressed stream and the retained subset,
# respectively. The upstream compressed Content-Length is not sufficient.
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_RETAINED_BYTES = 64 * 1024 * 1024
RELEASES = {"8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}
VERSION_RE = re.compile(r"^(?:(\d+):)?([0-9][A-Za-z0-9.+:~\-]*?)(?:-([A-Za-z0-9.+~]+))?$")
_snapshot_cache = (None, {})


def current_tracker_data():
    """Reuse the last fresh snapshot per worker instead of parsing it per item."""
    global _snapshot_cache
    fetched_at = DebianTrackerSnapshot.objects.filter(pk=1).values_list("fetched_at", flat=True).first()
    if not fetched_at or fetched_at < timezone.now() - timedelta(hours=48):
        return {}
    if _snapshot_cache[0] != fetched_at:
        data = DebianTrackerSnapshot.objects.filter(pk=1).values_list("data", flat=True).first()
        _snapshot_cache = (fetched_at, data if isinstance(data, dict) else {})
    return _snapshot_cache[1]


def _part_compare(left, right):
    def order(ch):
        if ch == "~":
            return -1
        if not ch:
            return 0
        if ("A" <= ch <= "Z") or ("a" <= ch <= "z"):
            return ord(ch)
        return ord(ch) + 256

    i = j = 0
    while i < len(left) or j < len(right):
        while (i < len(left) and not left[i].isdigit()) or (j < len(right) and not right[j].isdigit()):
            a = left[i] if i < len(left) and not left[i].isdigit() else ""
            b = right[j] if j < len(right) and not right[j].isdigit() else ""
            if order(a) != order(b):
                return -1 if order(a) < order(b) else 1
            i += bool(a)
            j += bool(b)
        a = i
        b = j
        while i < len(left) and left[i].isdigit():
            i += 1
        while j < len(right) and right[j].isdigit():
            j += 1
        number_a, number_b = int(left[a:i] or 0), int(right[b:j] or 0)
        if number_a != number_b:
            return -1 if number_a < number_b else 1
    return 0


def compare_debian_versions(left, right):
    parsed = []
    for value in (left, right):
        match = VERSION_RE.fullmatch(value or "")
        if not match:
            raise ValueError("Invalid Debian version")
        epoch, upstream, revision = match.groups()
        parsed.append((int(epoch or 0), upstream, revision or "0"))
    a, b = parsed
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    return _part_compare(a[1], b[1]) or _part_compare(a[2], b[2])


def debian_release(os_name):
    text = (os_name or "").lower()
    if not re.match(r"^debian(?:\s|/|$)", text):
        return None
    for codename in RELEASES.values():
        if re.search(r"\b" + codename + r"\b", text):
            return codename
    match = re.search(r"\b(?:gnu/linux\s*)?(\d+)(?:\.\d+)?\b", text)
    return RELEASES.get(match.group(1)) if match else None


_RELATION_UNSET = object()


def assess_host(item, software, host, snapshot, *, relation=_RELATION_UNSET):
    result = {"host": host, "status": "unknown", "label": "Unknown", "reason": "No reliable Debian assessment available", "source_url": "https://security-tracker.debian.org/tracker/", "checked_at": snapshot.fetched_at if snapshot else None}
    release = debian_release(host.operating_system)
    if not release:
        result["reason"] = "Debian release not identified; version not evaluated"
        return result
    if relation is _RELATION_UNSET:
        relation = HostSoftwareRelationship.objects.filter(host=host, software=software, package_manager="dpkg").first()
    if not relation or not relation.source_package or not relation.source_version:
        result["reason"] = "Debian source package/version missing from agent inventory"
        return result
    # A Debian advisory can itself supply an authoritative source-package fix
    # for this release, even where its feed summary contains no CVE IDs.
    from vuln_manager.utils.debian_advisories import advisory_ids
    ids = advisory_ids(item)
    if len(ids) == 1:
        record = item.debian_advisories.get(ids[0], {})
        try:
            fetched = parse_datetime(record.get("fetched_at", ""))
        except (TypeError, ValueError):
            fetched = None
        if fetched and timezone.is_aware(fetched) and fetched >= timezone.now() - timedelta(hours=48):
            fixes = [entry.get("fixed_version") for entry in record.get("fixes", []) if entry.get("source_package") == relation.source_package and entry.get("release") == release and entry.get("fixed_version")]
            try:
                if fixes:
                    fixed = fixes[0]
                    for candidate in fixes[1:]:
                        if compare_debian_versions(candidate, fixed) > 0:
                            fixed = candidate
                    comparison = compare_debian_versions(relation.source_version, fixed)
                    result.update(
                        status="below_fix" if comparison < 0 else "fixed",
                        label="Potentially affected" if comparison < 0 else "At or above Debian fix",
                        reason=f"{ids[0]}: source {relation.source_package} {relation.source_version}; Debian {release} fixed version {fixed}",
                        checked_at=fetched,
                        source_url=f"https://security-tracker.debian.org/tracker/{ids[0]}",
                    )
                    return result
            except (TypeError, ValueError):
                pass
    if not item.cves:
        result["reason"] = "No CVE in the feed item; tracker cannot be queried reliably"
        return result
    if not snapshot or not snapshot.fetched_at or snapshot.fetched_at < timezone.now() - timedelta(hours=48):
        result["reason"] = "Debian tracker data missing or older than 48 hours"
        return result
    assessments = []
    for cve in item.cves:
        entry = snapshot.data.get(relation.source_package, {}).get(cve, {}).get("releases", {}).get(release)
        if not isinstance(entry, dict):
            assessments.append(("unknown", f"{cve}: no tracker entry for {relation.source_package}/{release}"))
            continue
        fixed = entry.get("fixed_version")
        if entry.get("status") != "resolved" or not fixed or fixed == "0":
            assessments.append(("unknown", f"{cve}: tracker status {entry.get('status', 'unknown')}; no usable fixed version"))
            continue
        try:
            comparison = compare_debian_versions(relation.source_version, fixed)
        except ValueError:
            assessments.append(("unknown", f"{cve}: unable to compare Debian versions"))
            continue
        status = "below_fix" if comparison < 0 else "fixed"
        assessments.append((status, f"{cve}: source {relation.source_package} {relation.source_version}; Debian {release} fixed version {fixed}"))
    if any(status == "below_fix" for status, _ in assessments):
        result.update(status="below_fix", label="Potentially affected")
    elif all(status == "fixed" for status, _ in assessments):
        result.update(status="fixed", label="At or above Debian fix")
    result["reason"] = "; ".join(reason for _, reason in assessments)
    result["source_url"] = f"https://security-tracker.debian.org/tracker/{item.cves[0]}"
    return result


class _BoundedReader:
    def __init__(self, raw, limit):
        self.raw = raw
        self.limit = limit
        self.total = 0

    def read(self, size=-1):
        # ijson normally requests bounded blocks. Do not allow read(-1) to
        # allocate the entire remote dataset if a different backend is used.
        if size < 0:
            size = 65536
        chunk = self.raw.read(size)
        self.total += len(chunk)
        if self.total > self.limit:
            raise ValueError("Debian tracker snapshot exceeds size limit")
        return chunk


def _inventory_packages():
    return sorted(set(HostSoftwareRelationship.objects.filter(package_manager="dpkg").exclude(source_package="").values_list("source_package", flat=True)))


def _read_relevant_packages(response, packages):
    """Stream the source-package index and retain only fields used by CTI."""
    response.raw.decode_content = True
    stream = _BoundedReader(response.raw, MAX_SNAPSHOT_BYTES)
    wanted = set(packages)
    result = {}
    seen = 0
    retained_bytes = 0
    for name, entries in ijson.kvitems(stream, ""):
        seen += 1
        if not isinstance(entries, dict):
            raise ValueError("Invalid Debian tracker package data")
        if name not in wanted:
            continue
        compact = {}
        for cve, details in entries.items():
            releases = details.get("releases", {}) if isinstance(details, dict) else {}
            if not isinstance(releases, dict):
                releases = {}
            compact[cve] = {"releases": {
                release: {"status": entry.get("status"), "fixed_version": entry.get("fixed_version")}
                for release, entry in releases.items() if isinstance(entry, dict)
            }}
        retained_bytes += len(json.dumps(compact, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        if retained_bytes > MAX_RETAINED_BYTES:
            raise ValueError("Debian tracker inventory subset exceeds size limit")
        result[name] = compact
    if not seen:
        raise ValueError("Invalid or empty Debian tracker snapshot")
    return result


def refresh_tracker():
    """Stream a bounded snapshot; preserve the last valid subset on failure."""
    packages = _inventory_packages()
    if not packages:
        return
    snapshot, _ = DebianTrackerSnapshot.objects.defer("data").get_or_create(pk=1)
    now = timezone.now()
    if (snapshot.fetched_at and snapshot.fetched_at >= now-timedelta(hours=24)
            and sorted(snapshot.covered_packages or []) == packages):
        return
    # New packages trigger a refresh immediately after a successful run.
    # Failures retry after an hour, and only one worker may claim a refresh.
    claimed = DebianTrackerSnapshot.objects.filter(pk=snapshot.pk).filter(
        Q(last_attempt__isnull=True) | Q(last_attempt__lt=now-timedelta(hours=1))
        | Q(fetched_at__isnull=False, last_attempt__lte=F("fetched_at"))
    ).update(last_attempt=now)
    if not claimed:
        return
    try:
        with requests.get(TRACKER_URL, timeout=(10, 60), stream=True, allow_redirects=False) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError(f"Unexpected tracker status {response.status_code}")
            data = _read_relevant_packages(response, packages)
        DebianTrackerSnapshot.objects.filter(pk=1).update(data=data, covered_packages=packages, fetched_at=timezone.now(), error="")
    except Exception as exc:
        DebianTrackerSnapshot.objects.filter(pk=1).update(error=str(exc)[:500])
