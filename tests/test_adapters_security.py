from __future__ import annotations

import json
import unittest

from cachaza.adapters import jump403, nuclei, vulnx
from cachaza.models import TargetSpec


class SecurityAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetSpec(domains=["example.com"])

    def test_nuclei_jsonl_becomes_normalized_finding(self) -> None:
        row = {
            "template-id": "exposure-test",
            "matched-at": "https://api.example.com/admin",
            "info": {"name": "Exposure test", "severity": "high", "tags": ["exposure"]},
        }
        findings = nuclei.parse_output(json.dumps(row), self.target)
        self.assertEqual(findings[0].kind, "security_finding")
        self.assertTrue(findings[0].in_scope)
        self.assertEqual(findings[0].metadata["severity"], "high")

    def test_verbose_nuclei_command_reports_progress_without_raw_payloads(self) -> None:
        argv = nuclei.build_argv(
            "nuclei",
            "targets.txt",
            tags="waf",
            severities="info",
            rate_limit=1,
            concurrency=1,
            timeout=10,
            verbose=True,
        )
        self.assertIn("-omit-raw", argv)
        self.assertIn("-no-stdin", argv)
        self.assertEqual(argv[argv.index("-stats-interval") + 1], "30")

    def test_403jump_is_never_presented_as_confirmed(self) -> None:
        findings = jump403.parse_output(
            "SUCCESS 200 https://api.example.com/private\n", self.target
        )
        self.assertEqual(findings[0].metadata["confidence"], "candidate")
        self.assertTrue(findings[0].metadata["requires_manual_validation"])

    def test_vulnx_is_cve_candidate(self) -> None:
        findings = vulnx.parse_output(
            "CVE-2024-12345 possible match", "nginx", in_scope=True
        )
        self.assertEqual(findings[0].kind, "cve_candidate")
        self.assertEqual(findings[0].metadata["confidence"], "candidate")


if __name__ == "__main__":
    unittest.main()
