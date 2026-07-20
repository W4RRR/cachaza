from __future__ import annotations

import unittest

from cachaza.safety import (
    ValidationError,
    active_address_count,
    build_target_spec,
    domain_in_scope,
    extract_domains,
    normalize_asn,
    normalize_cidr,
    normalize_domain,
)


class SafetyTests(unittest.TestCase):
    def test_normalizes_domain_url_and_wildcard(self) -> None:
        self.assertEqual(normalize_domain("HTTPS://WWW.Example.COM/path"), "www.example.com")
        self.assertEqual(normalize_domain("*.api.example.com."), "api.example.com")

    def test_rejects_command_like_domain(self) -> None:
        with self.assertRaises(ValidationError):
            normalize_domain("example.com;id")

    def test_asn_and_cidr_normalization(self) -> None:
        self.assertEqual(normalize_asn("64500"), "AS64500")
        self.assertEqual(normalize_asn("as64500"), "AS64500")
        self.assertEqual(normalize_cidr("192.0.2.4/24"), "192.0.2.0/24")

    def test_scope_respects_exclusion(self) -> None:
        self.assertTrue(domain_in_scope("api.example.com", ["example.com"]))
        self.assertFalse(
            domain_in_scope("dev.api.example.com", ["example.com"], ["api.example.com"])
        )
        self.assertFalse(domain_in_scope("example.net", ["example.com"]))

    def test_extract_domains_from_mixed_output(self) -> None:
        text = '{"url":"https://api.example.com/a"}\n*.WWW.EXAMPLE.COM\nunrelated.test'
        self.assertEqual(
            extract_domains(text, ["example.com"]),
            ["api.example.com", "www.example.com"],
        )

    def test_target_spec_deduplicates(self) -> None:
        target = build_target_spec(
            domains=["example.com", "EXAMPLE.COM"], asns=["AS64500", "64500"]
        )
        self.assertEqual(target.domains, ["example.com"])
        self.assertEqual(target.asns, ["AS64500"])

    def test_active_address_count(self) -> None:
        self.assertEqual(active_address_count(["192.0.2.0/30", "198.51.100.1/32"]), 5)


if __name__ == "__main__":
    unittest.main()
