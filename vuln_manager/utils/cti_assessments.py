"""Group CTI assessments consistently across the complete inventory."""
from django.core.paginator import Paginator

from vuln_manager.models import HostSoftwareRelationship, Software
from vuln_manager.utils.debian_cti import assess_host

PRIORITY = {"below_fix": 0, "unknown": 1, "fixed": 2}
LABELS = {"below_fix": "Möglicherweise betroffen", "unknown": "Ungeklärt", "fixed": "Fix-Version erreicht"}
PAGE_SIZE = 25


def _add(group, assessment):
    group["items"].append(assessment)
    status = assessment["status"] if assessment["status"] in PRIORITY else "unknown"
    if PRIORITY[status] < PRIORITY[group["status"]]:
        group["status"] = status


def assessment_groups(request, item, snapshot):
    """Assess each matched host/package pair, then filter and paginate groups.

    Assessments are application logic rather than stored database fields. Both
    grouping modes and their counts therefore use the same complete set before
    filtering or pagination. Queries are batched rather than one per pair.
    """
    relations = {
        (relation.host_id, relation.software_id): relation
        for relation in HostSoftwareRelationship.objects.filter(
            software__cti_matches__item=item, package_manager="dpkg"
        ).iterator(chunk_size=1000)
    }
    hosts, packages = {}, {}
    pairs = Software.hosts.through.objects.filter(
        software__cti_matches__item=item
    ).select_related("host", "software").order_by("host_id", "software_id")
    for pair in pairs.iterator(chunk_size=1000):
        host, software = pair.host, pair.software
        assessment = {"software": software, **assess_host(
            item, software, host, snapshot, relation=relations.get((host.pk, software.pk))
        )}
        host_group = hosts.setdefault(host.pk, {"host": host, "items": [], "status": "fixed"})
        package_group = packages.setdefault(software.pk, {"software": software, "items": [], "status": "fixed"})
        _add(host_group, assessment)
        _add(package_group, assessment)

    counts = {status: sum(group["status"] == status for group in hosts.values()) for status in PRIORITY}
    counts["all"] = len(hosts)
    mode = request.GET.get("group", "host")
    if mode not in ("host", "package"):
        mode = "host"
    status = request.GET.get("assessment_status", "all")
    if status not in ("all", *PRIORITY):
        status = "all"
    query = (request.GET.get("asset_q") or "").strip()[:200]
    sort = request.GET.get("asset_sort", "priority")
    if sort not in ("priority", "name"):
        sort = "priority"
    groups = list(hosts.values() if mode == "host" else packages.values())
    if status != "all":
        groups = [group for group in groups if group["status"] == status]
    if query:
        needle = query.casefold()
        def searchable(group):
            values = []
            for assessment in group["items"]:
                host, software = assessment["host"], assessment["software"]
                values.extend((host.hostname or "", host.ip_address or "", host.operating_system or "", software.name or "", software.version or "", software.vendor or ""))
            return any(needle in value.casefold() for value in values)
        groups = [group for group in groups if searchable(group)]

    def sort_key(group):
        obj = group["host"] if mode == "host" else group["software"]
        name = str(obj).casefold()
        return ((PRIORITY[group["status"]], name, obj.pk) if sort == "priority" else (name, obj.pk))
    groups.sort(key=sort_key)
    for group in groups:
        group["label"] = LABELS[group["status"]]
        group["items"].sort(key=lambda value: (
            PRIORITY.get(value["status"], 1),
            str(value["software"] if mode == "host" else value["host"]).casefold(),
        ))
    return {
        "asset_groups": Paginator(groups, PAGE_SIZE).get_page(request.GET.get("asset_page")),
        "asset_counts": counts, "asset_mode": mode, "asset_status": status,
        "asset_query": query, "asset_sort": sort,
    }
