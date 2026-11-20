"""Debian source-package assessments using the Debian Security Tracker."""
import re
from datetime import timedelta

import requests
from django.db.models import Q
from django.utils import timezone

from vuln_manager.models import DebianTrackerSnapshot, HostSoftwareRelationship

TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
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


def assess_host(item, software, host, snapshot):
    result = {"host": host, "status": "unknown", "label": "Unknown", "reason": "No reliable Debian assessment available", "source_url": "https://security-tracker.debian.org/tracker/", "checked_at": snapshot.fetched_at if snapshot else None}
    release = debian_release(host.operating_system)
    if not release:
        result["reason"] = "Debian release not identified; version not evaluated"
        return result
    relation = HostSoftwareRelationship.objects.filter(host=host, software=software, package_manager="dpkg").first()
    if not relation or not relation.source_package or not relation.source_version:
        result["reason"] = "Debian source package/version missing from agent inventory"
        return result
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


def refresh_tracker():
    """Keep the last valid snapshot; a failed fetch never means not affected."""
    snapshot, _ = DebianTrackerSnapshot.objects.get_or_create(pk=1)
    now = timezone.now()
    claimed = DebianTrackerSnapshot.objects.filter(pk=snapshot.pk).filter(Q(last_attempt__isnull=True) | Q(last_attempt__lt=now-timedelta(hours=24))).update(last_attempt=now)
    if not claimed:
        return
    try:
        with requests.get(TRACKER_URL, timeout=(10, 60), stream=True, allow_redirects=False) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError(f"Unexpected tracker status {response.status_code}")
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if len(content) > MAX_SNAPSHOT_BYTES:
                    raise ValueError("Debian tracker snapshot exceeds size limit")
        import json
        data = json.loads(content)
        if not isinstance(data, dict) or not data:
            raise ValueError("Invalid Debian tracker snapshot")
        DebianTrackerSnapshot.objects.filter(pk=1).update(data=data, fetched_at=timezone.now(), error="")
    except Exception as exc:
        DebianTrackerSnapshot.objects.filter(pk=1).update(error=str(exc)[:500])
