import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from passive_asm import automatic_assessment, extract_forms
from surface_checks import inspect_response
from summary_report import cve_risk, historical_risk, port_risk, shodan_html_rows
from sql_to_csv import convert
from osint_sources import unique_values


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

    def test_historical_risk_is_contextual_but_conservative(self):
        self.assertIn("관리", historical_risk("admin", "/admin.asp"))
        self.assertIn("백업", historical_risk("unknown", "/old/backup.zip"))


if __name__ == "__main__":
    unittest.main()
