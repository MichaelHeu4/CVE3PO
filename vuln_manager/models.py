from django.db import models
from django.utils import timezone


import secrets

class Extension(models.Model):
    name_id = models.CharField(max_length=50, unique=True)
    is_active = models.BooleanField(default=False)
    api_token = models.CharField(max_length=100, blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.api_token and self.name_id in {"agent_api", "wazuh"}:
            self.api_token = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.name_id} ({'Active' if self.is_active else 'Inactive'})"


class SystemSettings(models.Model):
    disable_register = models.BooleanField(default=True)
    wrike_folder_id = models.CharField(max_length=100, blank=True, null=True)
    email_report_recipients = models.TextField(blank=True, null=True)
    ai_triage_provider = models.CharField(max_length=20, default="openrouter")
    ai_openrouter_api_key = models.CharField(max_length=255, blank=True, null=True)
    ai_openrouter_model = models.CharField(
        max_length=120, default="deepseek/deepseek-v4-flash"
    )
    ai_azure_endpoint = models.URLField(blank=True, null=True)
    ai_azure_api_key = models.CharField(max_length=255, blank=True, null=True)
    ai_azure_model = models.CharField(max_length=120, blank=True, null=True)

    def __str__(self):
        return f"SystemSettings(disable_register={self.disable_register})"


class Scan(models.Model):
    SCAN_TYPES = (
        ("NMAP", "Nmap Scan"),
        ("NUCLEI", "Nuclei Scan"),
        ("OPENVAS", "OpenVAS Scan"),
        ("SEMGREP", "Semgrep SAST"),
        ("MANUAL", "Manual Entry"),
        ("OSV", "OSV Scan"),
        ("NVD", "NVD Scan"),
        ("WAZUH", "Wazuh Live Feed"),
    )
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPES)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    raw_file = models.FileField(
        upload_to="scans/%Y/%m/%d/", null=True, blank=True)

    def __str__(self):
        return f"{self.get_scan_type_display()} - {self.uploaded_at}"


class Host(models.Model):
    CRITICALITY_CHOICES = (
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
    )
    ip_address = models.GenericIPAddressField(unique=True)
    hostname = models.CharField(max_length=255, blank=True, null=True)
    operating_system = models.CharField(max_length=255, blank=True, null=True)
    last_scanned = models.DateTimeField(auto_now=True)
    criticality = models.CharField(
        max_length=15, null=True, choices=CRITICALITY_CHOICES
    )

    def __str__(self):
        return self.hostname or self.ip_address


class Software(models.Model):
    CRITICALITY_CHOICES = (
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Low", "Low"),
    )
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100, blank=True, null=True)
    vendor = models.CharField(max_length=255, blank=True, null=True)
    listening_port = models.IntegerField(null=True, blank=True)
    criticality = models.CharField(
        max_length=15, null=True, choices=CRITICALITY_CHOICES
    )
    hosts = models.ManyToManyField(Host, related_name="software_inventory")

    class Meta:
        verbose_name_plural = "Software"
        unique_together = ("name", "version", "vendor", "listening_port")

    def __str__(self):
        port_info = f""" (Port {self.listening_port}
                          )""" if self.listening_port else ""
        return f"{self.name} {self.version or ''}{port_info}"


class HostSoftwareRelationship(models.Model):
    SOURCE_CHOICES = (
        ("manual", "Manual Entry"),
        ("agent", "Agent Collection"),
        ("scanner", "Automated Scanner"),
    )
    host = models.ForeignKey(Host, on_delete=models.CASCADE)
    software = models.ForeignKey(Software, on_delete=models.CASCADE)
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default="manual")
    installed_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("host", "software")


class Port(models.Model):
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, related_name="ports")
    scan = models.ForeignKey(
        Scan, on_delete=models.CASCADE, related_name="ports", null=True, blank=True
    )
    port_number = models.IntegerField()
    service_name = models.CharField(max_length=100)
    state = models.CharField(max_length=50)

    def __str__(self):
        return f"{self.host} : {self.port_number}/{self.service_name}"


class Vulnerability(models.Model):
    SEVERITY_CHOICES = (
        ("info", "Info"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    )
    STATUS_CHOICES = (
        ("open", "Open"),
        ("in_progress", "In Progress"),
        ("fixed", "Fixed"),
        ("risk_accepted", "Risk Accepted"),
        ("false_positive", "False Positive"),
    )
    AI_RESULTS = (
        ("Track", "Track"),
        ("Track*", "Track*"),
        ("Attend", "Attend"),
        ("Act", "Act"),
        ("tbd", "tbd")
    )
    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
        null=True,
        blank=True,
    )
    scan = models.ForeignKey(
        Scan, on_delete=models.CASCADE, related_name="vulnerabilities"
    )
    software = models.ForeignKey(
        Software,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="vulnerabilities",
    )
    port = models.ForeignKey(
        Port,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="vulnerabilities",
    )
    cve_id = models.CharField(max_length=50)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="open")
    cvss = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    nuclei_poc = models.TextField(blank=True, null=True)
    supply_chain = models.BooleanField(default=False)

    ai_reason = models.TextField(blank=True, null=True)
    ai_result = models.CharField(max_length=10, choices=AI_RESULTS, default="tbd")
    ai_suggestion = models.TextField(blank=True, null=True)
    ai_proc_time = models.FloatField(default=0.0)
    ai_last_criticality = models.CharField(max_length=20, blank=True, null=True)
    fingerprint = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    detection_count = models.PositiveIntegerField(default=1)
    wrike_task_id = models.CharField(max_length=50, blank=True, null=True)
    wrike_task_url = models.URLField(blank=True, null=True)

    def __str__(self):
        return f"{self.cve_id} - {self.name} ({self.severity})"

    @property
    def most_critical_host(self):
        """
        Gibt das Host-Objekt mit der höchsten Kritikalität zurück.
        Prüft den direkt verknüpften Host sowie alle Hosts der verknüpften Software.
        """
        weight_map = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1
        }
        
        highest_weight = 0
        top_host = None

        # 1. Den direkt verknüpften Host prüfen
        if self.host and self.host.criticality:
            weight = weight_map.get(self.host.criticality, 0)
            if weight > highest_weight:
                highest_weight = weight
                top_host = self.host

        # 2. Die Hosts über die Software prüfen
        if self.software:
            for host in self.software.hosts.all():
                if host.criticality:
                    weight = weight_map.get(host.criticality, 0)
                    if weight > highest_weight:
                        highest_weight = weight
                        top_host = host

        return top_host


class VulnerabilityAuditEvent(models.Model):
    ACTION_CHOICES = (
        ("created", "Created"),
        ("status_changed", "Status Changed"),
        ("updated", "Updated"),
        ("reopened", "Reopened"),
        ("deleted", "Deleted"),
        ("ticket_synced", "Ticket Synced"),
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    user = models.ForeignKey(
        "auth.User", on_delete=models.SET_NULL, null=True, blank=True
    )
    actor = models.CharField(max_length=255, blank=True, null=True)
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        target = self.vulnerability.cve_id if self.vulnerability else "deleted_vulnerability"
        return f"{self.action} - {target}"
