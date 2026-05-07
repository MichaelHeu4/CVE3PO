from vuln_manager.models import Extension


def agent_module_context(_request):
    return {
        "agent_module_active": Extension.objects.filter(
            name_id="agent_api", is_active=True
        ).exists()
    }
