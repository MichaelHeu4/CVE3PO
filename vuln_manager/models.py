from django.db import models


class Scan(models.Model):
    SCAN_TYPES = (
        ("NMAP", "Nmap Scan"),
        ("NUCLEI", "Nuclei Scan"),
        ("OPENVAS", "OpenVAS Scan"),
        ("SEMGREP", "Semgrep SAST"),
        ("MANUAL", "Manual Entry"),
        ("OSV", "OSV Scan"),
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
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    nuclei_poc = models.TextField(blank=True, null=True)
    supply_chain = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.cve_id} - {self.name} ({self.severity})"
