from __future__ import annotations

import csv
import io
import tempfile
import unittest
from pathlib import Path

from cachaza.html_report import render_html
from cachaza.models import Finding, TargetSpec
from cachaza.reports import _render_csv, build_report_data
from cachaza.workspace import RunWorkspace


class ReportingSecurityTests(unittest.TestCase):
    def _data(self, root: Path) -> dict:
        workspace = RunWorkspace(root)
        workspace.add(
            Finding(
                "nuclei",
                "=cmd|' /C calc'!A0",
                "security_finding",
                "<script>alert(1)</script>",
                True,
                {"name": "<img src=x onerror=alert(1)>", "severity": "high"},
            )
        )
        return build_report_data(
            workspace, TargetSpec(domains=["example.com"]), version="test", failures=[]
        )

    def test_html_has_csp_and_escapes_untrusted_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            document = render_html(self._data(Path(temp)))
        self.assertIn("Content-Security-Policy", document)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertNotIn("<img src=x onerror=alert(1)>", document)

    def test_csv_neutralizes_formula_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            payload = _render_csv(self._data(Path(temp)))
        rows = list(csv.DictReader(io.StringIO(payload)))
        self.assertTrue(rows[0]["source"].startswith("'="))


if __name__ == "__main__":
    unittest.main()

