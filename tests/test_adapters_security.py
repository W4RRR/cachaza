from __future__ import annotations

import unittest

from cachaza.adapters import jump403, vulnx
from cachaza.models import TargetSpec


class SecurityAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetSpec(domains=["example.com"])

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
