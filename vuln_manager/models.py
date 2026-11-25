from django.db import models
from django.utils import timezone


import secrets

CRITICALITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
}


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
    wazuh_api_url = models.URLField(max_length=500, blank=True, default="")
    wazuh_api_user = models.CharField(max_length=255, blank=True, default="")
    wazuh_api_password = models.CharField(max_length=500, blank=True, default="")
    sla_critical_days = models.PositiveIntegerField(default=7)
    sla_high_days = models.PositiveIntegerField(default=30)
    inventory_retention_days = models.PositiveIntegerField(default=90)
    inventory_cleanup_last_run = models.DateTimeField(null=True, blank=True)
    reminders_enabled = models.BooleanField(default=False)
    escalation_recipients = models.TextField(blank=True)
    escalation_after_days = models.PositiveIntegerField(default=7)
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
    ai_azure_api_version = models.CharField(
        max_length=40, default="2024-05-01-preview"
    )
    ai_cve_system_prompt = models.TextField(blank=True, null=True)
    ai_software_system_prompt = models.TextField(blank=True, null=True)

    # Automated enrichment scheduler (OSV/NVD/threat-intel + optional Shodan).
    auto_enrich_interval_hours = models.PositiveIntegerField(default=24)
    auto_enrich_last_run = models.DateTimeField(blank=True, null=True)
    auto_enrich_last_status = models.CharField(max_length=255, blank=True, null=True)

    # Auto-delete-fixed scheduler: remove vulnerabilities that have been fixed
    # for longer than the retention window. The cleanup runs on a daily cadence.
    auto_delete_fixed_days = models.PositiveIntegerField(default=90)
    auto_delete_fixed_last_run = models.DateTimeField(blank=True, null=True)
    auto_delete_fixed_last_status = models.CharField(
        max_length=255, blank=True, null=True
    )

    # NetBox module: one-way sync of server criticality (NetBox -> CVE3PO).
    # The source is either a custom field on devices/VMs or a tag prefix.
    netbox_url = models.URLField(blank=True, null=True)
    netbox_api_token = models.CharField(max_length=255, blank=True, null=True)
    netbox_verify_ssl = models.BooleanField(default=True)
    netbox_source_type = models.CharField(
        max_length=20,
        default="custom_field",
        choices=(("custom_field", "Custom field"), ("tag", "Tag")),
    )
    # Custom field name (source_type=custom_field) or tag prefix (source_type=tag).
    netbox_source_name = models.CharField(
        max_length=100, default="criticality"
    )
    # Optional "netbox value=Critical" lines/comma list; empty = match the
    # CVE3PO levels case-insensitively.
    netbox_value_mapping = models.TextField(blank=True, null=True)
    netbox_sync_interval_hours = models.PositiveIntegerField(default=6)
    netbox_last_run = models.DateTimeField(blank=True, null=True)
    netbox_last_status = models.CharField(max_length=255, blank=True, null=True)


    def __str__(self):
        return f"SystemSettings(disable_register={self.disable_register})"


class Scan(models.Model):
    SCAN_TYPES = (
        ("NMAP", "Nmap Scan"),
        ("NUCLEI", "Nuclei Scan"),
        ("OPENVAS", "OpenVAS Scan"),
        ("SEMGREP", "Semgrep SAST"),
        ("CYCLONEDX", "CycloneDX SBOM"),
        ("MANUAL", "Manual Entry"),
        ("OSV", "OSV Scan"),
        ("NVD", "NVD Scan"),
        ("WAZUH", "Wazuh Live Feed"),
        ("SHODAN", "Shodan Lookup"),
    )
    scan_type = models.CharField(max_length=10, choices=SCAN_TYPES)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    raw_file = models.FileField(
        upload_to="scans/%Y/%m/%d/", null=True, blank=True)

    class Meta:
        # The dashboard's 14-day trend loop filters on uploaded_at 14x2 times.
        indexes = [models.Index(fields=["uploaded_at"], name="scan_uploaded_idx")]

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
    # Stable, address-independent identity reported by the agent (Linux
    # /etc/machine-id or DMI UUID, Windows MachineGuid). It is the strongest
    # correlation key: a multi-homed server keeps ONE asset even when different
    # sources (agent, Wazuh, Shodan) observe it under different IPs. Optional and
    # unique — NULL for hosts discovered by sources that cannot report it.
    machine_id = models.CharField(
        max_length=255, unique=True, null=True, blank=True
    )
    hostname = models.CharField(max_length=255, blank=True, null=True)
    operating_system = models.CharField(max_length=255, blank=True, null=True)
    # Running kernel release reported by the agent on Linux hosts (e.g.
    # "6.8.0-45-generic"). Optional for backwards compatibility with older agents.
    running_kernel = models.CharField(max_length=255, blank=True, null=True)
    last_agent_contact = models.DateTimeField(blank=True, null=True)
    last_complete_inventory_ms = models.BigIntegerField(default=0)
    last_scanned = models.DateTimeField(auto_now=True)
    is_exposed = models.BooleanField(default=False)
    criticality = models.CharField(
        max_length=15, null=True, choices=CRITICALITY_CHOICES
    )
    # Where the current criticality came from. "netbox" means the NetBox module
    # owns it: manual edits are locked and software propagation is skipped
    # while the module is active.
    criticality_source = models.CharField(
        max_length=20, default="manual",
        choices=(("manual", "Manual"), ("netbox", "NetBox")),
    )
    criticality_synced_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        # The dashboard's cluster counts filter on (criticality, is_exposed).
        indexes = [
            models.Index(
                fields=["criticality", "is_exposed"], name="host_crit_exposed_idx"
            )
        ]

    def __str__(self):
        return self.hostname or self.ip_address


class HostAddress(models.Model):
    """
    An IP address observed for a Host. A server may expose several interfaces
    (and different sources may each see a different one), so addresses are a
    child collection of the Host rather than the Host's identity. The IP is
    globally unique: it belongs to at most one Host at a time, which is what lets
    the resolver map any later observation of that IP back to the same asset.
    """

    SOURCE_CHOICES = (
        ("agent", "Agent"),
        ("wazuh", "Wazuh"),
        ("shodan", "Shodan"),
        ("nmap", "Nmap Scan"),
        ("manual", "Manual Entry"),
    )
    host = models.ForeignKey(
        Host, on_delete=models.CASCADE, related_name="addresses"
    )
    ip_address = models.GenericIPAddressField(unique=True)
    source = models.CharField(
        max_length=20, choices=SOURCE_CHOICES, default="manual"
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.ip_address} ({self.host})"


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

    # AI Triage Fields
    AI_RESULTS = (
        ("Track", "Track"),
        ("Track*", "Track*"),
        ("Attend", "Attend"),
        ("Act", "Act"),
        ("tbd", "tbd")
    )
    ai_reason = models.TextField(blank=True, null=True)
    ai_result_cluster_1 = models.CharField(
        max_length=10, choices=AI_RESULTS, default="tbd"
    )
    ai_result_cluster_2 = models.CharField(
        max_length=10, choices=AI_RESULTS, default="tbd"
    )
    ai_result_cluster_3 = models.CharField(
        max_length=10, choices=AI_RESULTS, default="tbd"
    )
    ai_result_cluster_4 = models.CharField(
        max_length=10, choices=AI_RESULTS, default="tbd"
    )
    ai_triage_time = models.DateTimeField(blank=True, null=True)

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
    package_manager = models.CharField(max_length=20, blank=True)
    source_package = models.CharField(max_length=255, blank=True)
    source_version = models.CharField(max_length=100, blank=True)
    missing_snapshots = models.PositiveSmallIntegerField(default=0)
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
        ("verification", "Verification Pending"),
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
    # Set when the status transitions to "fixed", cleared when it leaves "fixed".
    # Drives the Auto-Delete-Fixed retention module.
    fixed_at = models.DateTimeField(blank=True, null=True)
    inventory_closed_at = models.DateTimeField(blank=True, null=True)
    detection_count = models.PositiveIntegerField(default=1)
    assignee = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_vulnerabilities")
    owner_team = models.CharField(max_length=200, blank=True)
    due_date = models.DateField(null=True, blank=True)
    exception_reason = models.TextField(blank=True)
    exception_expires = models.DateField(null=True, blank=True)
    exception_reviewer = models.ForeignKey("auth.User", null=True, blank=True, on_delete=models.SET_NULL, related_name="reviewed_exceptions")
    remediation_notes = models.TextField(blank=True)
    remediation_reference = models.URLField(blank=True)
    fixed_version = models.CharField(max_length=200, blank=True)
    verification_notes = models.TextField(blank=True)
    wrike_task_id = models.CharField(max_length=50, blank=True, null=True)
    wrike_task_url = models.URLField(blank=True, null=True)

    class Meta:
        # The dashboard filters/aggregates heavily on status, severity and
        # first_seen. Without these indexes every one of its ~40 queries is a
        # full table scan, so page-load time grows linearly with the table and
        # eventually exceeds gunicorn's request timeout.
        indexes = [
            models.Index(fields=["status"], name="vuln_status_idx"),
            models.Index(fields=["severity"], name="vuln_severity_idx"),
            models.Index(fields=["status", "severity"], name="vuln_status_sev_idx"),
            models.Index(
                fields=["severity", "first_seen"], name="vuln_sev_firstseen_idx"
            ),
            # Retention cleanup filters on (status, fixed_at).
            models.Index(fields=["status", "fixed_at"], name="vuln_status_fixedat_idx"),
        ]

    def __str__(self):
        return f"{self.cve_id} - {self.name} ({self.severity})"

    @property
    def most_critical_host(self):
        """
        Gibt das Host-Objekt mit der höchsten Kritikalität zurück.
        Prüft den direkt verknüpften Host sowie alle Hosts der verknüpften Software.
        """
        highest_weight = 0
        top_host = None

        # 1. Den direkt verknüpften Host prüfen
        if self.host and self.host.criticality:
            weight = CRITICALITY_WEIGHTS.get(self.host.criticality, 0)
            if weight > highest_weight:
                highest_weight = weight
                top_host = self.host

        # 2. Die Hosts über die Software prüfen
        if self.software:
            for host in self.software.hosts.all():
                if host.criticality:
                    weight = CRITICALITY_WEIGHTS.get(host.criticality, 0)
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


class InventoryFindingClosure(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="inventory_closures")
    host = models.ForeignKey(Host, null=True, on_delete=models.SET_NULL)
    host_label = models.CharField(max_length=255)
    software_name = models.CharField(max_length=255)
    software_version = models.CharField(max_length=100, blank=True)
    reason = models.CharField(max_length=30, choices=[("removed", "Uninstalled"), ("version_changed", "Version changed")])
    closed_at = models.DateTimeField(default=timezone.now)
    reopened_at = models.DateTimeField(null=True, blank=True)


class CisaKevEntry(models.Model):
    cve_id = models.CharField(max_length=50, unique=True)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "CISA KEV Entry"
        verbose_name_plural = "CISA KEV Entries"

    def __str__(self):
        return self.cve_id


class EpssEntry(models.Model):
    cve_id = models.CharField(max_length=50, unique=True)
    score = models.FloatField()
    percentile = models.FloatField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "EPSS Entry"
        verbose_name_plural = "EPSS Entries"

    def __str__(self):
        return f"{self.cve_id} (Score: {self.score})"


class VulnerabilityObservation(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="observations")
    scan = models.ForeignKey(Scan, on_delete=models.SET_NULL, null=True, blank=True)
    source = models.CharField(max_length=20)
    fingerprint = models.CharField(max_length=64, blank=True, null=True, db_index=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    detection_count = models.PositiveIntegerField(default=1)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["vulnerability", "source"], name="unique_vuln_source")]


class ReminderDelivery(models.Model):
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name="reminder_deliveries")
    date = models.DateField()
    kind = models.CharField(max_length=30)
    recipient = models.EmailField()
    claimed_at = models.DateTimeField(default=timezone.now)
    sent_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["vulnerability", "date", "kind", "recipient"], name="unique_reminder_delivery")]


class FeedRun(models.Model):
    source = models.CharField(max_length=40)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, default="running")
    details = models.TextField(blank=True)


class CTIFeed(models.Model):
    name = models.CharField(max_length=100, unique=True)
    url = models.URLField(unique=True)
    enabled = models.BooleanField(default=True)
    last_attempt = models.DateTimeField(null=True, blank=True)
    last_success = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)


class CTIItem(models.Model):
    source = models.ForeignKey(CTIFeed, on_delete=models.PROTECT, related_name="items")
    external_id = models.CharField(max_length=64, unique=True)
    title = models.CharField(max_length=500)
    summary = models.TextField(blank=True)
    url = models.URLField(max_length=1000)
    published_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(null=True, blank=True)
    received_at = models.DateTimeField(default=timezone.now)
    cves = models.JSONField(default=list, blank=True)
    feed_cves = models.JSONField(default=list, blank=True)
    debian_advisories = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, choices=[("new", "New"), ("reviewed", "Reviewed"), ("dismissed", "Dismissed")], default="new")
    findings = models.ManyToManyField(Vulnerability, blank=True, related_name="cti_items")


class CTIMatch(models.Model):
    item = models.ForeignKey(CTIItem, on_delete=models.CASCADE, related_name="matches")
    software = models.ForeignKey(Software, on_delete=models.CASCADE, related_name="cti_matches")
    reason = models.CharField(max_length=255)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["item", "software"], name="unique_cti_software")]


class WazuhContextSnapshot(models.Model):
    host = models.ForeignKey(Host, on_delete=models.CASCADE, related_name="wazuh_context_snapshots")
    agent_id = models.CharField(max_length=64)
    fetched_at = models.DateTimeField(default=timezone.now)
    fetched_by = models.ForeignKey("auth.User", null=True, on_delete=models.SET_NULL)
    ports = models.JSONField(default=list)
    processes = models.JSONField(default=list)
    software_matches = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["-fetched_at", "-id"]


class WazuhInventorySync(models.Model):
    status = models.CharField(max_length=16, default="running")
    started_at = models.DateTimeField(default=timezone.now)
    heartbeat_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict)

    class Meta:
        ordering = ["-started_at", "-id"]
        constraints = [models.UniqueConstraint(fields=["status"], condition=models.Q(status="running"), name="one_running_wazuh_inventory_sync")]


class DebianTrackerSnapshot(models.Model):
    last_attempt = models.DateTimeField(null=True, blank=True)
    fetched_at = models.DateTimeField(null=True, blank=True)
    error = models.CharField(max_length=500, blank=True)
    data = models.JSONField(default=dict)
    covered_packages = models.JSONField(default=list, blank=True)


class DebianAdvisorySnapshot(models.Model):
    kind = models.CharField(max_length=3, unique=True)
    last_attempt = models.DateTimeField(null=True, blank=True)
    fetched_at = models.DateTimeField(null=True, blank=True)
    error = models.CharField(max_length=500, blank=True)
    data = models.JSONField(default=dict)


class NotificationRule(models.Model):
    EVENTS = [("cti_match", "CTI inventory match"), ("new_finding", "New finding"), ("reopened", "Finding reopened"), ("kev_added", "CVE added to KEV"), ("sla_tomorrow", "SLA due tomorrow")]
    name = models.CharField(max_length=100)
    enabled = models.BooleanField(default=False)
    event_type = models.CharField(max_length=30, choices=EVENTS)
    severity = models.CharField(max_length=10, blank=True, choices=Vulnerability.SEVERITY_CHOICES)
    critical_host = models.BooleanField(default=False)
    exposed_host = models.BooleanField(default=False)
    email = models.EmailField(blank=True)
    webhook_url = models.URLField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)


class NotificationEvent(models.Model):
    key = models.CharField(max_length=255, unique=True)
    event_type = models.CharField(max_length=30, choices=NotificationRule.EVENTS)
    title = models.CharField(max_length=500)
    vulnerability = models.ForeignKey(Vulnerability, null=True, blank=True, on_delete=models.SET_NULL)
    item = models.ForeignKey(CTIItem, null=True, blank=True, on_delete=models.SET_NULL)
    software = models.ForeignKey(Software, null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(default=timezone.now)
    processed_at = models.DateTimeField(null=True, blank=True)


class NotificationDelivery(models.Model):
    event = models.ForeignKey(NotificationEvent, on_delete=models.CASCADE, related_name="deliveries")
    rule = models.ForeignKey(NotificationRule, on_delete=models.CASCADE, related_name="deliveries")
    channel = models.CharField(max_length=10)
    destination = models.CharField(max_length=1000)
    status = models.CharField(max_length=20, default="pending")
    attempts = models.PositiveIntegerField(default=0)
    next_attempt = models.DateTimeField(default=timezone.now)
    claimed_at = models.DateTimeField(null=True, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    error = models.CharField(max_length=500, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["event", "rule", "channel"], name="unique_event_rule_channel")]

class AITriageJob(models.Model):
    """Progress for a host-initiated batch of software triage operations."""
    STATUS_CHOICES = (("running", "Running"), ("completed", "Completed"),
                      ("partial", "Completed with errors"), ("failed", "Failed"),
                      ("interrupted", "Interrupted"))
    kind = models.CharField(max_length=16, choices=(("software", "Host software"), ("findings", "Finding triage")), default="software")
    heartbeat_at = models.DateTimeField(null=True, blank=True)
    dismissed = models.BooleanField(default=False)
    resumed_at = models.DateTimeField(null=True, blank=True)
    software_ids = models.JSONField(null=True, blank=True)
    completed_software_ids = models.JSONField(default=list, blank=True)
    host = models.ForeignKey(Host, null=True, on_delete=models.SET_NULL, related_name="ai_triage_jobs")
    host_label = models.CharField(max_length=255)
    started_by = models.ForeignKey("auth.User", null=True, on_delete=models.SET_NULL)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="running")
    total = models.PositiveIntegerField(default=0)
    processed = models.PositiveIntegerField(default=0)
    succeeded = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)
    current_item = models.CharField(max_length=255, blank=True)
    failed_items = models.JSONField(default=list, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)

    @property
    def progress_percent(self):
        return round(self.processed * 100 / self.total) if self.total else 0
