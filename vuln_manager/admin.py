from django.contrib import admin
from .models import Scan, Host, Port, Vulnerability

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'uploaded_at')

@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'hostname', 'last_scanned')

@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ('host', 'port_number', 'service_name', 'state')

@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = ('cve_id', 'host', 'severity', 'name')
    list_filter = ('severity',)
