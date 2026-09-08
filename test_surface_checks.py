import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import os
import urllib.error

from passive_asm import automatic_assessment, extract_forms
from surface_checks import inspect_response
from summary_report import cve_risk, historical_risk, port_risk, shodan_html_rows
from sql_to_csv import convert
from env_config import load_local_env
from osint_sources import (_is_privileged, _mask_account, build_cross_validation,
                           collect_public_osint, query_intelx_accounts, unique_values)


class SurfaceExposureTests(unittest.TestCase):
    def test_environment_file_is_reported_without_value(self):
        row = inspect_response(
            "https://example.test/.env", "노출 후보", "200", "text/plain",
            "DB_PASSWORD=do-not-copy-this\nAPP_KEY=also-secret", False, set(),
        )
        self.assertIn("환경설정 파일", row["exposure_findings"])
        self.assertNotIn("do-not-copy-this", repr(row))

    def test_soft_200_without_signature_is_not_reported_as_exposure(self):
        row = inspect_response(
            "https://example.test/debug", "노출 후보", "200", "text/html",
            "ordinary page", False, set(),
        )
        self.assertEqual([], row["exposure_findings"])

    def test_get_password_form_is_preserved(self):
        forms = extract_forms(
            "https://example.test/", '<form method="get" action="/login"><input type="password" name="pw"></form>'
        )
        self.assertEqual(["pw"], forms[0]["password_fields"])
        self.assertEqual("GET", forms[0]["method"])

    def test_port_and_cve_risks_are_concise(self):
        self.assertIn("평문 전송", port_risk(80))
        self.assertIn("접근통제", port_risk(12345))
        self.assertIn("영향 버전", cve_risk("CVE-2025-0001"))

    def test_shodan_rows_merge_shared_ip_fields(self):
        rows = shodan_html_rows({"ip": "203.0.113.7", "ports": [80, 443], "cpes": [], "vulns": ["CVE-2025-0001"]})
        self.assertEqual(2, len(rows))
        self.assertIn('rowspan="2"', rows[0])
        self.assertNotIn("203.0.113.7", rows[1])

    def test_schema_only_sql_has_clear_conversion_error(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "schema.txt"
            source.write_text("wr_id` int(11) NOT NULL, `wr_name` varchar(255) NOT NULL", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema only"):
                convert(source, Path(directory) / "out.csv", "utf-8")

    def test_osint_values_preserve_source_order(self):
        values = ["CVE-2019-6111", "CVE-2023-51385", "CVE-2019-6111", "CVE-2018-15473"]
        self.assertEqual(["CVE-2019-6111", "CVE-2023-51385", "CVE-2018-15473"], unique_values(values, 3))

    def test_passive_indexes_are_cross_validated_by_ip(self):
        data = {
            "shodan_internetdb": [{"provider": "shodan", "ip": "8.8.8.8", "ports": [53, 443]}],
            "censys": [{"provider": "censys", "ip": "8.8.8.8", "ports": [53]}],
        }
        rows = build_cross_validation(data, {"8.8.8.8"})
        self.assertEqual("2개 출처 일치", rows[0]["agreement"])
        self.assertTrue(rows[0]["current_dns_match"])

    def test_credential_intel_helpers_mask_and_flag_admin_accounts(self):
        self.assertEqual("a***@example.test", _mask_account("admin@example.test"))
        self.assertTrue(_is_privileged("admin@example.test"))
        self.assertFalse(_is_privileged("member@example.test"))
        with patch("osint_sources._request", return_value=(
                "email,password\nadmin@example.test,do-not-store\n", "text/csv")):
            result = query_intelx_accounts("example.test", 2, "test-key", "https://intelx.test")
        self.assertEqual(1, result["privileged_count"])
        self.assertNotIn("do-not-store", repr(result))
        self.assertNotIn("admin@example.test", repr(result))

    def test_local_env_loader_does_not_override_existing_values(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / '.env'
            source.write_text('SCANNER_TEST_NEW=loaded\nSCANNER_TEST_SET=file\n', encoding='utf-8')
            with patch.dict(os.environ, {'SCANNER_TEST_SET': 'shell'}, clear=False):
                os.environ.pop('SCANNER_TEST_NEW', None)
                self.assertTrue(load_local_env(source))
                self.assertEqual('loaded', os.environ['SCANNER_TEST_NEW'])
                self.assertEqual('shell', os.environ['SCANNER_TEST_SET'])

    def test_credential_intel_http_error_includes_safe_status_code(self):
        error = urllib.error.HTTPError('https://intelx.test', 403, 'Forbidden', {}, None)
        with patch.dict(os.environ, {'INTELX_API_KEY': 'test-key'}, clear=False), \
             patch('osint_sources.query_shodan_internetdb', return_value=[]), \
             patch('osint_sources.query_urlscan', return_value=[]), \
             patch('osint_sources.query_intelx_accounts', side_effect=error):
            result = collect_public_osint('example.test', {'ipv4': [], 'ipv6': []}, 1, credential_intel=True)
        self.assertEqual('HTTP 403', result['credential_exposure']['notice'])

    def test_historical_risk_is_contextual_but_conservative(self):
        self.assertIn("관리", historical_risk("admin", "/admin.asp"))
        self.assertIn("백업", historical_risk("unknown", "/old/backup.zip"))


if __name__ == "__main__":
    unittest.main()
