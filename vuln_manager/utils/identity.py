"""
Asset identity resolution.

Every ingest path (agent, Wazuh, Shodan, Nmap) funnels host creation through
``resolve_host`` instead of ``Host.objects.get_or_create(ip_address=...)``. A raw
IP is an attribute of a server, not its identity: a multi-homed host exposes
several IPs and different sources each observe a different one, which used to
create one asset per IP. The resolver correlates an observation to a single Host
by stable identity first, so one server stays one asset:

    1. machine_id  (strongest — only the agent reports it)
    2. any known IP address (primary or secondary, via HostAddress)
    3. hostname (case-insensitive)
    4. otherwise create a new Host

All observed IPs are registered as ``HostAddress`` rows bound to the resolved
host, so a later alert on any of them resolves correctly.
"""

import ipaddress
import logging

from django.db import transaction
from django.db.models import Q

from vuln_manager.models import Host, HostAddress

logger = logging.getLogger(__name__)


def _clean_ip(value):
    """Return a normalized, routable IP string, or None if it is unusable.

    Loopback and link-local addresses are dropped: they are not stable
    identifiers of a server and would wrongly collapse distinct hosts.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return None
    return ip.compressed


def _candidate_ips(primary, extra):
    """Ordered, de-duplicated list of usable IPs (primary first)."""
    ordered = []
    for raw in [primary, *(extra or [])]:
        cleaned = _clean_ip(raw)
        if cleaned and cleaned not in ordered:
            ordered.append(cleaned)
    return ordered


def _register_address(host, ip, source, trust_reassign):
    """Ensure an HostAddress row for ``ip`` points at ``host``.

    When the IP is already owned by a different host, it is only moved when the
    caller trusts the match (resolved by machine_id, or the host was just
    created) — this handles DHCP/IP reuse without letting a coincidental IP
    collision merge two unrelated servers.
    """
    addr, created = HostAddress.objects.get_or_create(
        ip_address=ip, defaults={"host": host, "source": source}
    )
    if created:
        return
    if addr.host_id != host.id:
        # Never move an IP away from a host that is a *different* identified
        # machine: that IP is shared, not identifying (e.g. the Docker bridges
        # 172.17.0.1 / 172.18.0.1, which are identical on every Docker host).
        owner = addr.host
        both_identified = bool(
            owner.machine_id
            and host.machine_id
            and owner.machine_id != host.machine_id
        )
        if trust_reassign and not both_identified:
            addr.host = host
            addr.source = source
            addr.save(update_fields=["host", "source", "last_seen"])
        return
    # Same host: just bump last_seen (auto_now) and keep the latest source.
    addr.source = source
    addr.save(update_fields=["source", "last_seen"])


@transaction.atomic
def resolve_host(
    *,
    ip_address=None,
    machine_id=None,
    hostname=None,
    ip_addresses=None,
    source="manual",
    defaults=None,
):
    """Resolve an observation to a single Host, creating one if needed.

    Returns ``(host, created)``. ``ip_addresses`` is an optional list of all IPs
    the source knows for the server (the agent reports every local interface);
    each is registered so later alerts on any of them map to this same asset.
    ``defaults`` are applied only when a new Host is created.
    """
    machine_id = (machine_id or "").strip() or None
    hostname = (hostname or "").strip() or None
    candidates = _candidate_ips(ip_address, ip_addresses)

    host = None
    matched_by = None

    if machine_id:
        host = Host.objects.filter(machine_id=machine_id).first()
        if host:
            matched_by = "machine_id"

    # A supplied machine_id is authoritative: when it matches no host, this is a
    # distinct machine, so it must NOT be collapsed into an existing host by a
    # shared IP (Docker bridges are identical across hosts) or a reused hostname
    # that already belongs to a *different* identified machine.
    if host is None and candidates:
        for addr in (
            HostAddress.objects.filter(ip_address__in=candidates)
            .select_related("host")
            .order_by("pk")
        ):
            owner = addr.host
            if (
                machine_id
                and owner.machine_id
                and owner.machine_id != machine_id
            ):
                continue  # IP owned by another known machine → shared, skip it
            host = owner
            matched_by = "ip"
            break

    if host is None and hostname:
        qs = Host.objects.filter(hostname__iexact=hostname)
        if machine_id:
            qs = qs.filter(Q(machine_id__isnull=True) | Q(machine_id=machine_id))
        host = qs.first()
        if host:
            matched_by = "hostname"

    created = False
    if host is None:
        primary_ip = candidates[0] if candidates else _clean_ip(ip_address)
        if not primary_ip:
            # No usable IP and no match: the Host model requires an IP, so we
            # cannot create an asset from this observation alone.
            raise ValueError(
                "resolve_host: cannot create a host without a routable IP"
            )
        create_kwargs = {"ip_address": primary_ip}
        if machine_id:
            create_kwargs["machine_id"] = machine_id
        if hostname:
            create_kwargs["hostname"] = hostname
        if defaults:
            create_kwargs.update(defaults)
        host = Host.objects.create(**create_kwargs)
        created = True

    # Backfill stronger identity onto an existing host when it is still missing.
    update_fields = []
    if machine_id and not host.machine_id:
        host.machine_id = machine_id
        update_fields.append("machine_id")
    if hostname and not host.hostname:
        host.hostname = hostname
        update_fields.append("hostname")
    if update_fields:
        try:
            host.save(update_fields=update_fields)
        except Exception:
            # A machine_id uniqueness clash means another host already owns it;
            # leave the existing identity untouched rather than crashing ingest.
            logger.exception(
                "resolve_host: could not backfill identity for host %s", host.pk
            )
            host.refresh_from_db()

    trust_reassign = created or matched_by == "machine_id"

    # Always make sure the host's primary IP is represented as an address.
    primary = _clean_ip(host.ip_address)
    if primary:
        _register_address(host, primary, source, trust_reassign)
    for ip in candidates:
        _register_address(host, ip, source, trust_reassign)

    return host, created


@transaction.atomic
def merge_hosts(primary, *others):
    """Merge ``others`` into ``primary``, repointing all related data.

    Used to collapse duplicate assets that were created before identity
    resolution (or across sources that could not be correlated automatically).
    Returns the surviving ``primary`` host.
    """
    from vuln_manager.models import (
        HostSoftwareRelationship,
        Port,
        Software,
        Vulnerability,
    )

    survivors_by_criticality = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    for other in others:
        if other.pk == primary.pk:
            continue

        Vulnerability.objects.filter(host=other).update(host=primary)
        Port.objects.filter(host=other).update(host=primary)
        HostAddress.objects.filter(host=other).update(host=primary)

        # HostSoftwareRelationship is unique per (host, software): move rows that
        # do not already exist on the primary, drop the rest.
        existing_sw_ids = set(
            HostSoftwareRelationship.objects.filter(host=primary).values_list(
                "software_id", flat=True
            )
        )
        for rel in HostSoftwareRelationship.objects.filter(host=other):
            if rel.software_id in existing_sw_ids:
                rel.delete()
            else:
                rel.host = primary
                rel.save(update_fields=["host"])
                existing_sw_ids.add(rel.software_id)

        # Software <-> Host M2M: attach each of the other's software to primary.
        for software in Software.objects.filter(hosts=other):
            software.hosts.add(primary)
            software.hosts.remove(other)

        # Capture the attributes we may carry over, then delete the loser BEFORE
        # saving the primary — otherwise backfilling the other's machine_id onto
        # the primary would clash with the (still-present) other's unique value.
        other_machine_id = other.machine_id
        other_hostname = other.hostname
        other_os = other.operating_system
        other_kernel = other.running_kernel
        other_exposed = other.is_exposed
        other_criticality = other.criticality
        other_criticality_source = other.criticality_source
        other_criticality_synced_at = other.criticality_synced_at

        other.delete()

        primary_fields = []
        if not primary.machine_id and other_machine_id:
            primary.machine_id = other_machine_id
            primary_fields.append("machine_id")
        if not primary.hostname and other_hostname:
            primary.hostname = other_hostname
            primary_fields.append("hostname")
        if not primary.operating_system and other_os:
            primary.operating_system = other_os
            primary_fields.append("operating_system")
        if not primary.running_kernel and other_kernel:
            primary.running_kernel = other_kernel
            primary_fields.append("running_kernel")
        if other_exposed and not primary.is_exposed:
            primary.is_exposed = True
            primary_fields.append("is_exposed")
        # A NetBox-owned criticality is authoritative and survives the merge;
        # otherwise keep the higher of the two manual values.
        primary_is_netbox = primary.criticality_source == "netbox"
        other_is_netbox = other_criticality_source == "netbox"
        if other_is_netbox and not primary_is_netbox:
            primary.criticality = other_criticality
            primary.criticality_source = "netbox"
            primary.criticality_synced_at = other_criticality_synced_at
            primary_fields += [
                "criticality",
                "criticality_source",
                "criticality_synced_at",
            ]
        elif not primary_is_netbox and survivors_by_criticality.get(
            other_criticality or "", 0
        ) > survivors_by_criticality.get(primary.criticality or "", 0):
            primary.criticality = other_criticality
            primary_fields.append("criticality")
        if primary_fields:
            primary.save(update_fields=primary_fields)

    return primary
