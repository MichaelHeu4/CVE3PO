import json
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from vuln_manager.models import Scan, Software, Vulnerability, VulnerabilityAuditEvent
from vuln_manager.parser.osvscanner import parse_osv_json, resolve_osv_metadata
from vuln_manager.utils.enrichment import get_cve_enrichment
from vuln_manager.utils.osv_auto import (
    _extract_nvd_cvss_and_severity, enrich_software_with_feeds,
)
from vuln_manager.utils.vuln_dedup import create_or_update_vulnerability


CVE = "CVE-2026-119618"
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class CveRatingTests(TestCase):
    @patch("vuln_manager.utils.enrichment.requests.get")
    def test_cna_textual_critical_rating_without_cvss(self, get):
        # Apache's CVE JSON can have only this textual metric at publication.
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"containers": {"cna": {
            "metrics": [{"other": {
                "type": "Textual description of severity",
                "content": {"text": "critical"},
            }}],
            "descriptions": [{"lang": "en", "value": "Apache HTTP/2 RCE"}],
        }}}
        self.assertEqual(get_cve_enrichment(CVE), (None, "Apache HTTP/2 RCE", "critical"))
        self.assertEqual(get.call_count, 1)

    @patch("vuln_manager.utils.enrichment.requests.get")
    def test_vector_recalculates_critical(self, get):
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"cvss-vector": VECTOR}
        self.assertEqual(get_cve_enrichment(CVE), (VECTOR, None, "critical"))

    @patch("vuln_manager.utils.osv_auto.query_nvd_by_cve_id")
    @patch("vuln_manager.utils.enrichment.requests.get")
    def test_missing_circl_rating_uses_nvd_score(self, get, nvd):
        get.return_value = Mock(status_code=200)
        get.return_value.json.return_value = {"summary": "Apache HTTP/2 RCE"}
        nvd.return_value = {"metrics": {"cvssMetricV31": [{
            "cvssData": {"baseScore": 9.8, "vectorString": VECTOR},
        }]}}
        self.assertEqual(get_cve_enrichment(CVE), (VECTOR, "Apache HTTP/2 RCE", "critical"))

    @patch("vuln_manager.utils.osv_auto.query_nvd_by_cve_id", return_value=None)
    @patch("vuln_manager.utils.enrichment.requests.get", side_effect=requests.Timeout)
    def test_failed_lookups_return_missing_not_informational(self, get, nvd):
        self.assertEqual(get_cve_enrichment(CVE), (None, None, None))

    def test_nvd_no_rating_differs_from_zero_score(self):
        self.assertEqual(_extract_nvd_cvss_and_severity({}), (None, None))
        self.assertEqual(_extract_nvd_cvss_and_severity({"metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 0}}],
        }}), (None, "info"))

    def test_nvd_skips_incomplete_and_invalid_metrics(self):
        self.assertEqual(_extract_nvd_cvss_and_severity({"metrics": {
            "cvssMetricV40": [{"cvssData": {}}, {"cvssData": {"baseScore": "unknown"}}],
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
        }}), (None, "critical"))

    @patch("vuln_manager.utils.enrichment.get_cve_enrichment", return_value=(VECTOR, None, "critical"))
    def test_osv_missing_rating_is_fetched_once_even_with_summary(self, fetch):
        advisory = {"id": CVE, "summary": "Apache HTTP/2 RCE"}
        cache = {}
        for _ in range(2):
            self.assertEqual(resolve_osv_metadata(advisory, CVE, cache),
                             (VECTOR, "critical", "Apache HTTP/2 RCE"))
        fetch.assert_called_once_with(CVE)

    @patch("vuln_manager.utils.enrichment.get_cve_enrichment")
    def test_osv_existing_rating_needs_no_lookup(self, fetch):
        advisory = {"summary": "Known", "database_specific": {"severity": "HIGH"}}
        self.assertEqual(resolve_osv_metadata(advisory, CVE, {}), (None, "high", "Known"))
        fetch.assert_not_called()

    @patch("vuln_manager.utils.enrichment.get_cve_enrichment", return_value=(None, None, "critical"))
    def test_osv_upload_fetches_missing_rating(self, fetch):
        scan = Scan.objects.create(scan_type="OSV")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "osv.json"
            path.write_text(json.dumps({"vulns": [{"id": CVE, "summary": "Apache RCE"}]}))
            parse_osv_json(path, scan)
        self.assertEqual(Vulnerability.objects.get(cve_id=CVE).severity, "critical")

    @patch("vuln_manager.utils.osv_auto._is_distro_package", return_value=True)
    @patch("vuln_manager.utils.osv_auto._candidate_ecosystems", return_value=["Debian:13"])
    @patch("vuln_manager.utils.osv_auto._query_osv", return_value=[{"id": CVE, "summary": "Apache RCE"}])
    @patch("vuln_manager.utils.enrichment.get_cve_enrichment", return_value=(VECTOR, None, "critical"))
    def test_software_enrichment_repairs_existing_osv_finding(self, fetch, query, ecosystems, distro):
        scan = Scan.objects.create(scan_type="OSV")
        software = Software.objects.create(name="apache2", version="2.4.65-1")
        vuln = create_or_update_vulnerability(
            scan=scan, software=software, cve_id=CVE, severity="info",
            name="OSV: Apache RCE", description="No description provided.", supply_chain=True,
        )
        enrich_software_with_feeds(software.pk)
        vuln.refresh_from_db()
        self.assertEqual(vuln.severity, "critical")
        self.assertEqual(vuln.cvss, VECTOR)
        self.assertEqual(Vulnerability.objects.count(), 1)

    def test_missing_rating_does_not_erase_known_rating_on_reimport(self):
        scan = Scan.objects.create(scan_type="OSV")
        kwargs = dict(scan=scan, cve_id=CVE, name="Apache RCE")
        vuln = create_or_update_vulnerability(**kwargs, severity="critical", cvss=VECTOR)
        create_or_update_vulnerability(**kwargs, severity=None, cvss=None)
        vuln.refresh_from_db()
        self.assertEqual((vuln.severity, vuln.cvss), ("critical", VECTOR))

    @patch("vuln_manager.views.get_cve_enrichment", return_value=(None, None, "critical"))
    def test_manual_enrichment_repairs_severity_without_cvss_and_audits(self, fetch):
        user = User.objects.create_user(username="rating-user")
        self.client.force_login(user)
        vuln = Vulnerability.objects.create(
            scan=Scan.objects.create(scan_type="MANUAL"), cve_id=CVE,
            name="Apache RCE", severity="info",
        )
        response = self.client.post(reverse("enrich_single_vulnerability", args=[vuln.pk]))
        self.assertEqual(response.status_code, 302)
        vuln.refresh_from_db()
        self.assertEqual(vuln.severity, "critical")
        event = VulnerabilityAuditEvent.objects.get(vulnerability=vuln, action="updated")
        self.assertIn("severity", event.details["fields"])

    @patch("vuln_manager.utils.enrichment.get_cve_enrichment", return_value=(VECTOR, None, "critical"))
    @patch("vuln_manager.utils.enrichment.get_epss_score")
    @patch("vuln_manager.utils.enrichment.sync_cisa_kev_to_db")
    def test_scheduled_enrichment_repairs_all_occurrences_with_one_lookup(self, kev, epss, fetch):
        from vuln_manager.utils.scheduler import run_full_enrichment
        scan = Scan.objects.create(scan_type="MANUAL")
        for name in ("Apache one", "Apache two"):
            Vulnerability.objects.create(scan=scan, cve_id=CVE, name=name, severity="info")
        run_full_enrichment()
        self.assertEqual(Vulnerability.objects.filter(severity="critical", cvss=VECTOR).count(), 2)
        fetch.assert_called_once_with(CVE)
