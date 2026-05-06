from django.http import JsonResponse, HttpResponseNotFound
from django.views.decorators.csrf import csrf_exempt
from django.db import transaction
from django.db import close_old_connections
import logging
from vuln_manager.models import (
    HostSoftwareRelationship,
    Extension,
    Host,
    Software,
)
import json
from django.views.decorators.http import require_POST
import threading

logger = logging.getLogger(__name__)


ASYNC_INVENTORY_THRESHOLD = 200


def _sync_inventory_payload(data):
    host_ip = data.get("host_ip")
    hostname = data.get("hostname")
    operating_system = data.get("operating_system") or data.get("os")
    software_list = data.get("software", [])

    if not host_ip:
        raise ValueError("host_ip is required")

    with transaction.atomic():
        host, _ = Host.objects.get_or_create(ip_address=host_ip)
        host_update_fields = []
        if hostname and not host.hostname:
            host.hostname = hostname
            host_update_fields.append("hostname")
        if operating_system and host.operating_system != operating_system:
            host.operating_system = operating_system
            host_update_fields.append("operating_system")
        if host_update_fields:
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
                sw_obj, _ = Software.objects.get_or_create(
                    name=name,
                    version=version,
                    vendor=vendor,
                    listening_port=port,
                )

                sw_obj.hosts.add(host)

                HostSoftwareRelationship.objects.get_or_create(
                    host=host, software=sw_obj, source="agent"
                )

                synced_sw_ids.add(sw_obj.id)
                added_count += 1

        stale_agent_sw_ids = existing_agent_sw_ids - synced_sw_ids
        if stale_agent_sw_ids:
            HostSoftwareRelationship.objects.filter(
                host=host, source="agent", software_id__in=stale_agent_sw_ids
            ).delete()

            still_related_sw_ids = set(
                HostSoftwareRelationship.objects.filter(
                    host=host, software_id__in=stale_agent_sw_ids
                ).values_list("software_id", flat=True)
            )
            detach_sw_ids = stale_agent_sw_ids - still_related_sw_ids

            if detach_sw_ids:
                Software.hosts.through.objects.filter(
                    host_id=host.id, software_id__in=detach_sw_ids
                ).delete()

                Software.objects.filter(id__in=detach_sw_ids, hosts__isnull=True).delete()

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
