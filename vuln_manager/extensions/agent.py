from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from vuln_manager.models import HostSoftwareRelationship, Extension, Host, Software
import json
from django.views.decorators.http import require_POST


@csrf_exempt
@require_POST
def update_inventory_api(request):
    """
    API endpoint for agents to report software inventory (Strategy A).
    Payload must include 'X-API-Key' header.
    """
    try:
        api_ext, _ = Extension.objects.get_or_create(name_id="agent_api")
        provided_token = request.headers.get("X-API-Key")
        if not provided_token or provided_token != api_ext.api_token:
            return JsonResponse(
                {"status": "error", "message": "unauthorized"}, status=401
            )

        data = json.loads(request.body)
        host_ip = data.get("host_ip")
        hostname = data.get("hostname")
        software_list = data.get("software", [])

        if not host_ip:
            return JsonResponse(
                {"status": "error", "message": "host_ip is required"}, status=400
            )

        host, _ = Host.objects.get_or_create(ip_address=host_ip)
        if hostname and not host.hostname:
            host.hostname = hostname
            host.save()

        HostSoftwareRelationship.objects.filter(host=host, source="agent").delete()

        added_count = 0
        for sw_item in software_list:
            name = sw_item.get("name")
            version = sw_item.get("version")
            vendor = sw_item.get("vendor")
            port = sw_item.get("port")

            if name:
                sw_obj, _ = Software.objects.get_or_create(
                    name=name, version=version, vendor=vendor, listening_port=port
                )

                HostSoftwareRelationship.objects.get_or_create(
                    host=host, software=sw_obj, source="agent"
                )
                added_count += 1

        return JsonResponse(
            {
                "status": "success",
                "host": host.ip_address,
                "agent_software_synced": added_count,
            },
            status=200,
        )

    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=400)
