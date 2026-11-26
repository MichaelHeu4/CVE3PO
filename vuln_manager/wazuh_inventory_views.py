from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import redirect
from django.http import HttpResponseBadRequest
from django.views.decorators.http import require_POST

from .models import Extension, SystemSettings
from .utils.wazuh_context import validate_api_url


@login_required
@user_passes_test(lambda user: user.is_staff)
@require_POST
def save_wazuh_api_config(request):
    url = (request.POST.get("wazuh_api_url") or "").strip().rstrip("/")
    username = (request.POST.get("wazuh_api_user") or "").strip()
    password = request.POST.get("wazuh_api_password") or ""
    if not url or not username or len(url) > 500 or not validate_api_url(url) or len(username) > 255 or len(password) > 500:
        return HttpResponseBadRequest("Invalid Wazuh API configuration")
    settings, _ = SystemSettings.objects.get_or_create(pk=1)
    if not password and not settings.wazuh_api_password:
        return HttpResponseBadRequest("Wazuh API password is required")
    settings.wazuh_api_url = url
    settings.wazuh_api_user = username
    settings.wazuh_verify_ssl = request.POST.get("wazuh_verify_ssl") == "1"
    fields = ["wazuh_api_url", "wazuh_api_user", "wazuh_verify_ssl"]
    if password:
        settings.wazuh_api_password = password
        fields.append("wazuh_api_password")
    settings.save(update_fields=fields)
    messages.success(request, "Wazuh API settings saved.")
    return redirect("extensions")


@login_required
@user_passes_test(lambda user: user.is_staff)
@require_POST
def sync_wazuh_inventory(request):
    from .utils.wazuh_sync import start_sync
    if not Extension.objects.filter(name_id="wazuh", is_active=True).exists():
        messages.error(request, "Enable the Wazuh module first.")
    elif start_sync():
        messages.success(request, "Wazuh inventory sync started in the background.")
    else:
        messages.warning(request, "A Wazuh inventory sync is already running.")
    return redirect("extensions")
