from django.core.management.base import BaseCommand
from django.db.models.signals import post_save
from django.utils import timezone
from vuln_manager.models import Host, Software, Vulnerability, Scan, SystemSettings, Extension, HostSoftwareRelationship
from vuln_manager.signals import trigger_osv_auto_lookup
from vuln_manager.utils.audit import log_vulnerability_event

class Command(BaseCommand):
    help = 'Generates a clean and realistic set of test data for Hosts, Software, and Vulnerabilities.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Clearing existing vulnerability management data..."))
        
        # 1. Disconnect the OSV auto enrichment signal so we don't query external APIs during generation
        post_save.disconnect(trigger_osv_auto_lookup, sender=Software)

        try:
            # 2. Delete existing entities
            HostSoftwareRelationship.objects.all().delete()
            Vulnerability.objects.all().delete()
            Software.objects.all().delete()
            Host.objects.all().delete()
            Scan.objects.all().delete()
            self.stdout.write(self.style.SUCCESS("Existing data cleared successfully."))

            # 3. Create or update System Settings
            settings_obj, created = SystemSettings.objects.get_or_create(pk=1)
            settings_obj.disable_register = False
            settings_obj.sla_critical_days = 7
            settings_obj.sla_high_days = 30
            settings_obj.save()
            self.stdout.write(self.style.SUCCESS("SystemSettings initialized/updated."))

            # 4. Create and activate Extensions
            extensions = ["ai_triage", "agent_api", "email_reporting", "wrike", "wazuh"]
            for ext_name in extensions:
                ext, _ = Extension.objects.get_or_create(name_id=ext_name)
                ext.is_active = True
                ext.save()
            self.stdout.write(self.style.SUCCESS("All extensions initialized and activated."))

            # 5. Create default Scan objects
            scan_manual = Scan.objects.create(scan_type="MANUAL")
            self.stdout.write(self.style.SUCCESS("Mock scans created."))

            # 6. Create Hosts
            # We want a mix of hosts to populate the 4 clusters:
            # Cluster 1: Open + High (Criticality: Critical/High, is_exposed: True)
            # Cluster 2: Open + Low (Criticality: Medium/Low, is_exposed: True)
            # Cluster 3: Controlled + High (Criticality: Critical/High, is_exposed: False)
            # Cluster 4: Controlled + Low (Criticality: Medium/Low, is_exposed: False)
            hosts_data = [
                # Cluster 1: Open + High
                {"hostname": "web-proxy-prod-01", "ip_address": "10.0.1.10", "operating_system": "Debian 12", "criticality": "Critical", "is_exposed": True},
                {"hostname": "api-gateway-edge", "ip_address": "10.0.1.20", "operating_system": "Alpine Linux", "criticality": "Critical", "is_exposed": True},
                {"hostname": "vpn-gateway-prod", "ip_address": "10.0.1.30", "operating_system": "Ubuntu 22.04 LTS", "criticality": "High", "is_exposed": True},
                {"hostname": "jenkins-build-server", "ip_address": "10.0.1.40", "operating_system": "Ubuntu 22.04 LTS", "criticality": "High", "is_exposed": True},
                
                # Cluster 2: Open + Low
                {"hostname": "mail-relay-public", "ip_address": "10.0.2.10", "operating_system": "Debian 12", "criticality": "Medium", "is_exposed": True},
                {"hostname": "web-mirror-dns", "ip_address": "10.0.2.20", "operating_system": "Ubuntu 20.04 LTS", "criticality": "Medium", "is_exposed": True},
                {"hostname": "dev-sandbox-external", "ip_address": "10.0.2.30", "operating_system": "CentOS Stream 9", "criticality": "Low", "is_exposed": True},
                {"hostname": "demo-blog-frontend", "ip_address": "10.0.2.40", "operating_system": "Debian 11", "criticality": "Low", "is_exposed": True},

                # Cluster 3: Controlled + High
                {"hostname": "db-prod-cluster-01", "ip_address": "10.0.3.10", "operating_system": "Ubuntu 22.04 LTS", "criticality": "Critical", "is_exposed": False},
                {"hostname": "db-prod-cluster-02", "ip_address": "10.0.3.20", "operating_system": "Ubuntu 22.04 LTS", "criticality": "Critical", "is_exposed": False},
                {"hostname": "app-server-internal-01", "ip_address": "10.0.3.30", "operating_system": "Ubuntu 22.04 LTS", "criticality": "High", "is_exposed": False},
                {"hostname": "app-server-internal-02", "ip_address": "10.0.3.40", "operating_system": "Ubuntu 22.04 LTS", "criticality": "High", "is_exposed": False},
                {"hostname": "ad-domain-controller", "ip_address": "10.0.3.50", "operating_system": "Windows Server 2022", "criticality": "Critical", "is_exposed": False},

                # Cluster 4: Controlled + Low
                {"hostname": "nas-backup-local", "ip_address": "10.0.4.10", "operating_system": "FreeBSD", "criticality": "Medium", "is_exposed": False},
                {"hostname": "gitlab-runner-internal-01", "ip_address": "10.0.4.20", "operating_system": "Debian 12", "criticality": "Medium", "is_exposed": False},
                {"hostname": "internal-dns-primary", "ip_address": "10.0.4.30", "operating_system": "Debian 11", "criticality": "Medium", "is_exposed": False},
                {"hostname": "dev-workstation-alice", "ip_address": "192.168.1.50", "operating_system": "Windows 11", "criticality": "Low", "is_exposed": False},
                {"hostname": "dev-workstation-bob", "ip_address": "192.168.1.60", "operating_system": "Windows 11", "criticality": "Low", "is_exposed": False},
                {"hostname": "staging-cache-redis", "ip_address": "10.0.4.40", "operating_system": "Ubuntu 22.04 LTS", "criticality": "Low", "is_exposed": False},
                {"hostname": "printers-subnet-device", "ip_address": "10.0.4.50", "operating_system": "Embedded Linux", "criticality": "Low", "is_exposed": False},
            ]

            hosts = []
            for h in hosts_data:
                host_obj = Host.objects.create(**h)
                hosts.append(host_obj)
            self.stdout.write(self.style.SUCCESS(f"Created {len(hosts)} Host objects."))

            # Helper functions to get hosts by cluster
            def get_cluster_hosts(c_num):
                res = []
                for h in hosts:
                    is_crit = h.criticality in ["Critical", "High"]
                    is_open = h.is_exposed
                    if c_num == 1 and is_crit and is_open:
                        res.append(h)
                    elif c_num == 2 and not is_crit and is_open:
                        res.append(h)
                    elif c_num == 3 and is_crit and not is_open:
                        res.append(h)
                    elif c_num == 4 and not is_crit and not is_open:
                        res.append(h)
                return res

            # 7. Create Software packages
            # --- Software 1: nginx (1.18.0) ---
            # Status: TBD (will be triaged by user)
            # Vulnerabilities: 4 CVEs all forcing "Attend" (Rule 2 trigger: > 3 CVEs => escalates Attend -> Act)
            nginx = Software.objects.create(
                name="nginx",
                version="1.18.0",
                vendor="F5 NGINX",
                listening_port=80,
                criticality="High",
            )
            # Assign to multiple hosts across all clusters
            nginx.hosts.add(*(get_cluster_hosts(1)[:2] + get_cluster_hosts(2)[:2] + get_cluster_hosts(3)[:2] + get_cluster_hosts(4)[:2]))
            
            # Create 4 vulnerabilities for nginx, each with individual AI result "Attend"
            nginx_vulns = [
                {
                    "cve_id": "CVE-2026-40001",
                    "severity": "high",
                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "name": "Nginx HTTP/2 Information Disclosure",
                    "description": "An issue in Nginx HTTP/2 processing allows a remote attacker to read memory contents via specifically crafted requests.",
                    "ai_result": "Attend",
                    "ai_reason": "Vulnerability is remotely exploitable without privileges (AV:N/AC:L/PR:N/UI:N), which defaults to Automated utility. On exposed hosts, it requires attention.",
                    "ai_suggestion": "Apply the security patch or upgrade nginx to version 1.18.1.",
                },
                {
                    "cve_id": "CVE-2026-40002",
                    "severity": "high",
                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "name": "Nginx Request Parsing Denial of Service",
                    "description": "A denial of service vulnerability in Nginx request line parsing allows remote attackers to cause high CPU usage or crash.",
                    "ai_result": "Attend",
                    "ai_reason": "Remotely exploitable without authentication, leading to DoS. Automated utility leads to Attend on key segments.",
                    "ai_suggestion": "Disable HTTP/2 if not strictly required, or update to the latest patched version.",
                },
                {
                    "cve_id": "CVE-2026-40003",
                    "severity": "medium",
                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                    "name": "Nginx mod_zip Path Traversal",
                    "description": "A path traversal vulnerability in Nginx mod_zip extension allows remote attackers to read arbitrary files via directory traversal.",
                    "ai_result": "Attend",
                    "ai_reason": "Low complexity and remote. Requires immediate attention for public systems.",
                    "ai_suggestion": "Disable mod_zip or restrict directory access settings.",
                },
                {
                    "cve_id": "CVE-2026-40004",
                    "severity": "high",
                    "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "name": "Nginx SSL Session Resumption Spoofing",
                    "description": "An issue in SSL session resumption allows an attacker with network access to decrypt or hijack sessions under specific configurations.",
                    "ai_result": "Attend",
                    "ai_reason": "Session hijacking risk on exposed endpoints.",
                    "ai_suggestion": "Configure secure TLS settings and disable session tickets if not needed.",
                }
            ]
            for v_data in nginx_vulns:
                Vulnerability.objects.create(
                    scan=scan_manual,
                    software=nginx,
                    status="open",
                    **v_data
                )
            
            # --- Software 2: openssl (3.0.13) ---
            # Status: TBD (will be triaged by user)
            # Vulnerabilities: 12 CVEs (Rule 1 trigger: > 10 CVEs => escalates Track -> Attend)
            openssl = Software.objects.create(
                name="openssl",
                version="3.0.13",
                vendor="OpenSSL Software Foundation",
                criticality="Critical",
            )
            openssl.hosts.add(*hosts)

            for i in range(1, 13):
                # We want some varying individual results
                ai_res = "Track" if i <= 8 else "Attend"
                sev = "medium" if i <= 8 else "high"
                Vulnerability.objects.create(
                    scan=scan_manual,
                    software=openssl,
                    cve_id=f"CVE-2026-300{i:02d}",
                    severity=sev,
                    status="open",
                    cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" if i <= 8 else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    name=f"OpenSSL Vulnerability Part {i}",
                    description=f"This is mock vulnerability part {i} for OpenSSL 3.0.13. It is used to test software-level triage and the escalation debt rules.",
                    ai_result=ai_res,
                    ai_reason=f"Mock analyst analysis for CVE-2026-300{i:02d}.",
                    ai_suggestion="Upgrade OpenSSL to the latest stable release.",
                )

            # --- Software 3: postgresql (14.2) ---
            # Status: Pre-Triaged (Simulates completed triage)
            postgres = Software.objects.create(
                name="postgresql",
                version="14.2",
                vendor="PostgreSQL Global Development Group",
                listening_port=5432,
                criticality="Critical",
                ai_result_cluster_1="Act",
                ai_result_cluster_2="Act",
                ai_result_cluster_3="Attend",
                ai_result_cluster_4="Track",
                ai_reason="PostgreSQL has a highly critical RCE (CVE-2026-60001) which is Active in public exploits. "
                          "For Cluster 1 and 2 (exponiert), an immediate Act is required to secure the systems. "
                          "Cluster 3 (internal and critical) requires immediate attention to patch. "
                          "Cluster 4 (internal and low criticality) can be tracked during the regular patching cycle.",
                ai_triage_time=timezone.now() - timezone.timedelta(hours=2)
            )
            postgres.hosts.add(*(get_cluster_hosts(1)[:1] + get_cluster_hosts(2)[:1] + get_cluster_hosts(3)[:2] + get_cluster_hosts(4)[:1]))
            
            # Create postgres vulnerability
            Vulnerability.objects.create(
                scan=scan_manual,
                software=postgres,
                cve_id="CVE-2026-60001",
                severity="critical",
                status="open",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                name="PostgreSQL Copy Command Remote Code Execution",
                description="A vulnerability in the COPY FROM PROGRAM command allows authenticated database administrators to execute arbitrary OS commands.",
                ai_result="Act",
                ai_reason="Active exploit found in wild. EPSS score is 0.45, CISA KEV is True. Public exploit POC code is readily available.",
                ai_suggestion="Restrict COPY privileges, upgrade PostgreSQL to 14.3, and enforce network access control lists.",
            )

            # --- Software 4: redis (6.2.6) ---
            # Status: Pre-Triaged (Simulates completed triage)
            redis = Software.objects.create(
                name="redis",
                version="6.2.6",
                vendor="Redis Labs",
                listening_port=6379,
                criticality="High",
                ai_result_cluster_1="Act",
                ai_result_cluster_2="Attend",
                ai_result_cluster_3="Attend",
                ai_result_cluster_4="Track",
                ai_reason="Redis is vulnerable to a major command execution flaw (CVE-2026-70001). "
                          "Exposed critical servers (Cluster 1) require immediate action. "
                          "Exposed low-crit (Cluster 2) and controlled high-crit (Cluster 3) servers need active attention. "
                          "Controlled low-crit (Cluster 4) servers can be tracked.",
                ai_triage_time=timezone.now() - timezone.timedelta(hours=4)
            )
            redis.hosts.add(*(get_cluster_hosts(1)[:1] + get_cluster_hosts(2)[:2] + get_cluster_hosts(3)[:1] + get_cluster_hosts(4)[:3]))

            # Redis Vulnerabilities (2 CVEs)
            Vulnerability.objects.create(
                scan=scan_manual,
                software=redis,
                cve_id="CVE-2026-70001",
                severity="high",
                status="open",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                name="Redis Lua Scripting Remote Code Execution",
                description="A sandbox escape vulnerability in Redis Lua engine allows remote attackers to execute code inside the redis container/host context.",
                ai_result="Act",
                ai_reason="EPSS score is 0.12 (>0.1), CVSS is AV:N/AC:L/PR:N/UI:N, making it synergistic and highly active.",
                ai_suggestion="Ensure Redis is not bound to public interfaces. Enforce AUTH command. Upgrade to Redis 6.2.7+.",
            )
            Vulnerability.objects.create(
                scan=scan_manual,
                software=redis,
                cve_id="CVE-2026-70002",
                severity="medium",
                status="open",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:M",
                name="Redis Client Connection Leak DoS",
                description="An issue in Redis client connection termination causes a resource leak, leading to eventual denial of service.",
                ai_result="Track",
                ai_reason="Requires a large number of open connections to trigger. No active exploits known.",
                ai_suggestion="Monitor open file descriptors on redis nodes and set connection timeouts.",
            )

            # --- Software 5: apache2 (2.4.48) ---
            # Status: TBD (will be triaged by user)
            # Vulnerabilities: 2 CVEs (standard case, no escalation rules triggered)
            apache = Software.objects.create(
                name="apache2",
                version="2.4.48",
                vendor="Apache Software Foundation",
                listening_port=8080,
                criticality="Medium",
            )
            apache.hosts.add(*(get_cluster_hosts(1)[:1] + get_cluster_hosts(2)[:1] + get_cluster_hosts(3)[:1] + get_cluster_hosts(4)[:1]))
            
            # Create apache vulnerabilities
            Vulnerability.objects.create(
                scan=scan_manual,
                software=apache,
                cve_id="CVE-2026-50001",
                severity="critical",
                status="open",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                name="Apache mod_proxy Path Traversal RCE",
                description="A path traversal vulnerability in Apache mod_proxy allows remote unauthenticated attackers to write files and execute arbitrary code.",
                ai_result="tbd",
            )
            Vulnerability.objects.create(
                scan=scan_manual,
                software=apache,
                cve_id="CVE-2026-50002",
                severity="medium",
                status="open",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                name="Apache HTTP/2 Protocol Ping DoS",
                description="An issue in HTTP/2 ping frame handling allows remote attackers to cause high memory load, causing a DoS.",
                ai_result="tbd",
            )

            # --- Software 6: bind9 (9.18.1) ---
            # Status: Pre-Triaged
            # Vulnerabilities: 1 CVE
            bind = Software.objects.create(
                name="bind9",
                version="9.18.1",
                vendor="Internet Systems Consortium",
                listening_port=53,
                criticality="High",
                ai_result_cluster_1="Attend",
                ai_result_cluster_2="Track",
                ai_result_cluster_3="Track",
                ai_result_cluster_4="Track",
                ai_reason="BIND9 has a denial of service vulnerability (CVE-2026-80001). "
                          "Only public exposed critical servers (Cluster 1) require attention. "
                          "For other clusters, the impact and risk are low enough to track.",
                ai_triage_time=timezone.now() - timezone.timedelta(hours=10)
            )
            bind.hosts.add(*(get_cluster_hosts(1)[:1] + get_cluster_hosts(3)[:2]))
            
            Vulnerability.objects.create(
                scan=scan_manual,
                software=bind,
                cve_id="CVE-2026-80001",
                severity="medium",
                status="open",
                cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:M",
                name="BIND9 DNS Query Flood DoS",
                description="A vulnerability in BIND9 query parsing allows an attacker to flood the resolver with malformed requests, causing a crash.",
                ai_result="Track",
                ai_reason="Medium severity DoS, isolated impact.",
                ai_suggestion="Apply rate-limiting on query requests.",
            )

            # --- Software 7: openssh-server (8.9p1) ---
            # Status: TBD (No vulnerabilities!)
            openssh = Software.objects.create(
                name="openssh-server",
                version="8.9p1",
                vendor="OpenSSH",
                listening_port=22,
                criticality="Critical",
            )
            openssh.hosts.add(*hosts[:10])

            # --- Software 8: docker-ce (20.10.12) ---
            # Status: TBD (1 vulnerability, status = open)
            docker = Software.objects.create(
                name="docker-ce",
                version="20.10.12",
                vendor="Docker Inc",
                criticality="High",
            )
            docker.hosts.add(*(get_cluster_hosts(3)[:2] + get_cluster_hosts(4)[:2]))

            Vulnerability.objects.create(
                scan=scan_manual,
                software=docker,
                cve_id="CVE-2026-90001",
                severity="high",
                status="open",
                cvss="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                name="Docker Engine Container Escape",
                description="A flaw in container runtime isolation allows a privileged user inside a container to escape namespaces and execute code on the host.",
                ai_result="tbd",
            )

            self.stdout.write(self.style.SUCCESS(f"Created 8 Software packages with corresponding vulnerabilities and host mappings."))

            # 8. Create some Host-level vulnerabilities (not tied to software)
            for idx, h in enumerate(hosts[:5]):
                Vulnerability.objects.create(
                    scan=scan_manual,
                    host=h,
                    cve_id=f"CVE-2026-100{idx:02d}",
                    severity="high" if idx % 2 == 0 else "medium",
                    status="open",
                    cvss="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    name=f"Host-level vulnerability on {h.hostname}",
                    description=f"A general operating system vulnerability was found on {h.hostname}. Requires local verification.",
                    ai_result="tbd" if idx > 2 else "Attend",
                    ai_reason="Local segment exposure needs attention." if idx <= 2 else "",
                )
            
            self.stdout.write(self.style.SUCCESS("Created 5 Host-specific (software-independent) vulnerabilities."))

            # 9. Create some Audit Events to make the history look authentic
            if postgres.vulnerabilities.exists():
                v = postgres.vulnerabilities.first()
                log_vulnerability_event(
                    vulnerability=v,
                    action="created",
                    actor="system:test_data_generator",
                    details={"source": "test_data_generator", "version": "1.0"}
                )
                log_vulnerability_event(
                    vulnerability=v,
                    action="status_changed",
                    actor="system:test_data_generator",
                    details={"from_status": "open", "to_status": "in_progress", "reason": "Triage investigation"}
                )
            
            self.stdout.write(self.style.SUCCESS("Audit logs populated."))
            self.stdout.write(self.style.SUCCESS("=== Test Data Generation Finished Successfully! ==="))
            self.stdout.write(self.style.WARNING("Note: Ensure the 'ai_triage' extension is configured in the UI or settings if you want to perform real AI Triage."))

        finally:
            # Reconnect signal
            post_save.connect(trigger_osv_auto_lookup, sender=Software)
