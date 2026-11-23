from django.http import JsonResponse, HttpResponseNotFound
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.utils import timezone
from django.db import close_old_connections
import logging
from vuln_manager.models import (
    Host,
    HostSoftwareRelationship,
    Extension,
    Software,
)
from vuln_manager.utils.identity import resolve_host
import json
from django.views.decorators.http import require_POST
import threading

logger = logging.getLogger(__name__)


ASYNC_INVENTORY_THRESHOLD = 200


def _sync_inventory_payload(data):
    host_ip = data.get("host_ip")
    hostname = data.get("hostname")
    operating_system = data.get("operating_system") or data.get("os")
    # Optional: agents may report the running kernel (Linux). Older agents that
    # do not send it leave the stored value untouched (backwards compatible).
    running_kernel = data.get("running_kernel") or data.get("kernel")
    # Stable identity + the full set of local IPs. Older agents omit both; the
    # resolver then falls back to IP/hostname matching (backwards compatible).
    machine_id = data.get("machine_id")
    ip_addresses = data.get("ip_addresses") or data.get("local_ips") or []
    software_list = data.get("software", [])

    if not host_ip:
        raise ValueError("host_ip is required")
    if not isinstance(software_list, list) or not all(isinstance(item, dict) for item in software_list):
        raise ValueError("software must be a list of objects")
    sources = data.get("complete_sources")
    started_ms = data.get("snapshot_started_ms")
    allowed_sources = {"dpkg", "rpm", "apk", "pacman"}
    authoritative = (
        data.get("inventory_complete") is True
        and isinstance(sources, list) and bool(sources)
        and all(isinstance(source, str) and source in allowed_sources for source in sources)
        and isinstance(started_ms, int) and not isinstance(started_ms, bool)
        and 0 < started_ms <= int(timezone.now().timestamp() * 1000) + 300000
        and all(isinstance(item.get("name"), str) and item["name"].strip()
                and isinstance(item.get("version"), str) and item["version"].strip()
                and isinstance(item.get("package_manager"), str) and item["package_manager"].strip()
                for item in software_list)
    )

    with transaction.atomic():
        # Resolve by stable identity (machine_id) before IP so a multi-homed
        # server stays ONE asset, and register every reported IP against it.
        host, _ = resolve_host(
            ip_address=host_ip,
            machine_id=machine_id,
            hostname=hostname,
            ip_addresses=ip_addresses,
            source="agent",
        )
        # Serialize per-host inventory reconciliation and ignore replayed or
        # out-of-order complete snapshots. Old agents never confirm absence.
        host = Host.objects.select_for_update().get(pk=host.pk)
        if authoritative and started_ms <= host.last_complete_inventory_ms:
            return host, 0
        # Refresh the host's Last seen even when the reported inventory and
        # metadata are unchanged. auto_now only runs for listed update_fields.
        host.last_agent_contact = timezone.now()
        host_update_fields = ["last_scanned", "last_agent_contact"]
        if authoritative:
            host.last_complete_inventory_ms = started_ms
            host_update_fields.append("last_complete_inventory_ms")
        if hostname and not host.hostname:
            host.hostname = hostname
            host_update_fields.append("hostname")
        if operating_system and host.operating_system != operating_system:
            host.operating_system = operating_system
            host_update_fields.append("operating_system")
        if running_kernel and host.running_kernel != running_kernel:
            host.running_kernel = running_kernel
            host_update_fields.append("running_kernel")
        host.save(update_fields=host_update_fields)

        existing_agent_sw_ids = set(
            HostSoftwareRelationship.objects.filter(host=host, source="agent").values_list(
                "software_id", flat=True
            )
        )

        synced_sw_ids = set()
        added_count = 0
        for sw_item in software_list:
            name = sw_item.get("name")
            version = sw_item.get("version")
            vendor = sw_item.get("vendor")
            port = sw_item.get("port")

            if name:
                sw_obj, software_created = Software.objects.get_or_create(
                    name=name,
                    version=version,
                    vendor=vendor,
                    listening_port=port,
                )

                reintroduced = not software_created and not sw_obj.hosts.exists()
                sw_obj.hosts.add(host)

                relation, created = HostSoftwareRelationship.objects.get_or_create(
                    host=host, software=sw_obj, defaults={"source": "agent"}
                )
                # Old agents omit these fields; do not keep stale package identity
                # when a newer snapshot no longer supplies it.
                if relation.source == "agent":
                    relation.package_manager = str(sw_item.get("package_manager") or "")[:20]
                    relation.source_package = str(sw_item.get("source_package") or "")[:255]
                    relation.source_version = str(sw_item.get("source_version") or "")[:100]
                    relation.missing_snapshots = 0
                    relation.save(update_fields=["package_manager", "source_package", "source_version", "missing_snapshots"])
                if created:
                    from vuln_manager.utils.inventory_lifecycle import record_reappearance
                    record_reappearance(host, sw_obj)
                    if reintroduced:
                        from vuln_manager.signals import schedule_software_enrichment
                        schedule_software_enrichment(sw_obj.pk)

                synced_sw_ids.add(sw_obj.id)
                added_count += 1

        stale_agent_sw_ids = existing_agent_sw_ids - synced_sw_ids
        if authoritative and stale_agent_sw_ids:
            from vuln_manager.utils.inventory_lifecycle import record_absent_installation
            reported = {(item["name"], item["version"], item["package_manager"]) for item in software_list}
            reported_names = {(name, manager) for name, _, manager in reported}
            missing = HostSoftwareRelationship.objects.select_related("software").filter(
                host=host, source="agent", software_id__in=stale_agent_sw_ids,
                package_manager__in=sources,
            )
            for relation in missing:
                # A different vendor/port representation must not count as a
                # disappearance when this same source still reports the exact
                # package and version under another Software row.
                if (relation.software.name, relation.software.version, relation.package_manager) in reported:
                    if relation.missing_snapshots:
                        relation.missing_snapshots = 0
                        relation.save(update_fields=["missing_snapshots"])
                    continue
                relation.missing_snapshots += 1
                if relation.missing_snapshots < 2:
                    relation.save(update_fields=["missing_snapshots"])
                    continue
                software = relation.software
                replacement = (software.name, relation.package_manager) in reported_names
                relation.delete()
                software.hosts.remove(host)
                record_absent_installation(host, software, "version_changed" if replacement else "removed")

    return host, added_count


def _sync_inventory_payload_background(data):
    close_old_connections()
    try:
        _sync_inventory_payload(data)
    except Exception:
        logger.exception("Agent inventory async sync failed")
    finally:
        close_old_connections()


@csrf_exempt
@require_POST
def update_inventory_api(request):
    """
    API endpoint for agents to report software inventory (Strategy A).
    Payload must include 'X-API-Key' header.
    """
    try:
        api_ext, _ = Extension.objects.get_or_create(name_id="agent_api")
        if not api_ext.is_active:
            return HttpResponseNotFound()

        provided_token = request.headers.get("X-API-Key")
        if not provided_token or provided_token != api_ext.api_token:
            return JsonResponse(
                {"status": "error", "message": "unauthorized"}, status=401
            )

        data = json.loads(request.body)
        software_list = data.get("software", [])
        host_ip = data.get("host_ip")
        if not host_ip:
            return JsonResponse(
                {"status": "error", "message": "host_ip is required"}, status=400
            )
        if not isinstance(software_list, list) or not all(isinstance(item, dict) for item in software_list):
            return JsonResponse({"status": "error", "message": "invalid_software"}, status=400)
        if len(software_list) >= ASYNC_INVENTORY_THRESHOLD:
            worker = threading.Thread(
                target=_sync_inventory_payload_background,
                args=(data,),
                daemon=True,
            )
            worker.start()
            return JsonResponse(
                {
                    "status": "accepted",
                    "host": host_ip,
                    "queued": True,
                    "agent_software_received": len(software_list),
                },
                status=202,
            )

        host, added_count = _sync_inventory_payload(data)
        return JsonResponse(
            {
                "status": "success",
                "host": host.ip_address,
                "operating_system": host.operating_system,
                "agent_software_synced": added_count,
            },
            status=200,
        )

    except Exception:
        logger.exception("Agent inventory sync failed")
        return JsonResponse(
            {"status": "error", "message": "internal_error"}, status=500
        )
