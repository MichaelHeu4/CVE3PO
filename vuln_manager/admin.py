from django.contrib import admin, messages
from .models import (
    Scan,
    Host,
    HostAddress,
    Port,
    Vulnerability,
    VulnerabilityAuditEvent,
)
from .utils.identity import merge_hosts

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'uploaded_at')


class HostAddressInline(admin.TabularInline):
    model = HostAddress
    extra = 0
    readonly_fields = ("first_seen", "last_seen")


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'hostname', 'machine_id', 'operating_system', 'last_scanned')
    search_fields = ('ip_address', 'hostname', 'machine_id', 'addresses__ip_address')
    inlines = [HostAddressInline]
    actions = ['merge_selected_hosts']

    @admin.action(description="Merge selected hosts into one asset")
    def merge_selected_hosts(self, request, queryset):
        hosts = list(queryset.order_by("pk"))
        if len(hosts) < 2:
            self.message_user(
                request,
                "Select at least two hosts to merge.",
                level=messages.WARNING,
            )
            return
        primary, *others = hosts
        merge_hosts(primary, *others)
        self.message_user(
            request,
            f"Merged {len(others)} host(s) into {primary}.",
            level=messages.SUCCESS,
        )


@admin.register(HostAddress)
class HostAddressAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'host', 'source', 'first_seen', 'last_seen')
    list_filter = ('source',)
    search_fields = ('ip_address', 'host__hostname')

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ('host', 'port_number', 'service_name', 'state')

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'host', 'severity', 'name')
    list_filter = ('severity',)


@admin.register(VulnerabilityAuditEvent)
class VulnerabilityAuditEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "vulnerability", "user", "actor")
    list_filter = ("action",)
