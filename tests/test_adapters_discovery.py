from __future__ import annotations

import json
import unittest

from cachaza.adapters import dnsx, gau, smap
from cachaza.models import TargetSpec


class DiscoveryAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetSpec(domains=["example.com"], cidrs=["192.0.2.0/24"])

    def test_dnsx_preserves_scope_boundary(self) -> None:
        row = {
            "host": "api.example.com",
            "a": ["192.0.2.10", "198.51.100.4"],
            "cname": ["edge.other.test"],
        }
        findings = dnsx.parse_output(json.dumps(row), self.target)
        by_value = {item.value: item for item in findings}
        self.assertTrue(by_value["api.example.com"].in_scope)
        self.assertTrue(by_value["192.0.2.10"].in_scope)
        self.assertFalse(by_value["198.51.100.4"].in_scope)
        self.assertFalse(by_value["edge.other.test"].in_scope)

    def test_dnsx_enables_root_specific_wildcard_filtering(self) -> None:
        argv = dnsx.build_argv(
            "dnsx",
            "targets.txt",
            rate_limit=10,
            wildcard_domain="example.com",
        )
        self.assertIn("-wd", argv)
        self.assertEqual(argv[argv.index("-wd") + 1], "example.com")

    def test_gau_marks_sensitive_names_as_candidates(self) -> None:
        findings = gau.parse_output(
            "https://api.example.com/.env?old=1\nhttps://example.com/index.html\n",
            self.target,
        )
        sensitive = next(item for item in findings if ".env" in item.value)
        self.assertTrue(sensitive.in_scope)
        self.assertTrue(sensitive.metadata["sensitive_candidate"])
        self.assertEqual(sensitive.metadata["confidence"], "candidate")
        self.assertEqual(sensitive.metadata["historical_source"], "gau")
        self.assertEqual(sensitive.metadata["host"], "api.example.com")
        self.assertEqual(sensitive.metadata["path"], "/.env")

    def test_smap_normalizes_passive_service(self) -> None:
        self.assertEqual(smap.build_argv("smap"), ["smap", "-iL", "-"])
        findings = smap.parse_output("api.example.com:443 open\n", self.target)
        self.assertEqual(findings[0].kind, "service")
        self.assertTrue(findings[0].in_scope)
        self.assertTrue(findings[0].metadata["passive"])


if __name__ == "__main__":
    unittest.main()
