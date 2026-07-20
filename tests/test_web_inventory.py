from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cachaza.models import Finding
from cachaza.web import (
    deduplicate_http_origins,
    is_api_endpoint,
    normalize_endpoint_url,
    normalize_http_origin,
    select_live_http_origins,
)
from cachaza.workspace import RunWorkspace


class HttpNormalizationTests(unittest.TestCase):
    def test_normalize_http_origin_covers_ports_paths_ipv6_and_credentials(self) -> None:
        cases = {
            "HTTPS://Example.COM:443/login?q=1#fragment": "https://example.com",
            "http://Example.COM:80/path;value?q=1": "http://example.com",
            "https://example.com:8443/swagger": "https://example.com:8443",
            "http://[2001:db8::1]:80/api": "http://[2001:db8::1]",
            "https://[2001:db8::1]:8443/api": "https://[2001:db8::1]:8443",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(normalize_http_origin(source), expected)
        for rejected in (
            "ftp://example.com/file",
            "https:///missing-host",
            "https://user@example.com/",
            "https://user:pass@example.com/",
            "https://example.com:invalid/",
        ):
            with self.subTest(rejected=rejected):
                self.assertIsNone(normalize_http_origin(rejected))

    def test_origin_deduplication_removes_paths_and_default_ports(self) -> None:
        self.assertEqual(
            deduplicate_http_origins(
                [
                    "https://example.com/",
                    "https://example.com/login",
                    "https://example.com/admin",
                    "https://example.com/api/v1?id=1",
                    "https://example.com:443/test",
                ]
            ),
            ["https://example.com"],
        )
        self.assertEqual(
            deduplicate_http_origins(
                ["http://example.com/", "http://example.com:80/test"]
            ),
            ["http://example.com"],
        )

    def test_endpoint_normalization_strips_values_and_fragments(self) -> None:
        self.assertEqual(
            normalize_endpoint_url(
                "https://EXAMPLE.com:443/search?q=secret&page=2&q=again#results"
            ),
            "https://example.com/search?page&q",
        )
        self.assertTrue(is_api_endpoint("https://example.com/api/v1/users"))
        self.assertTrue(is_api_endpoint("https://example.com/graphql"))
        self.assertFalse(is_api_endpoint("https://example.com/about"))


class LiveOriginAndArtifactTests(unittest.TestCase):
    def test_only_confirmed_url_findings_become_waf_origins(self) -> None:
        findings = [
            Finding("ports", "naabu", "service", "example.com:8443", True, {}),
            Finding(
                "gau",
                "gau",
                "url",
                "https://example.com/old",
                True,
                {"historical": True},
            ),
            Finding(
                "http",
                "httpx",
                "url",
                "https://example.com/login",
                True,
                {"status_code": 200},
            ),
            Finding(
                "http",
                "httpx",
                "url",
                "https://example.com:8443/health",
                True,
                {"status_code": 302},
            ),
        ]
        self.assertEqual(
            select_live_http_origins(findings, ["example.com"]),
            ["https://example.com", "https://example.com:8443"],
        )
        self.assertEqual(
            select_live_http_origins(findings[:2], ["example.com"]),
            ["https://example.com"],
        )

    def test_workspace_writes_normalized_endpoint_inventories(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            workspace.add(
                Finding(
                    "gau",
                    "gau",
                    "url",
                    "https://example.com/api/v1/users?token=secret&id=7#row",
                    True,
                    {"endpoint": True, "historical": True},
                )
            )
            workspace.add(
                Finding(
                    "crawl",
                    "katana",
                    "url",
                    "https://example.com/graphql?id=8&token=other",
                    True,
                    {"endpoint": True, "crawler": True, "status_code": 200},
                )
            )
            workspace.add(
                Finding(
                    "crawl",
                    "katana",
                    "url",
                    "https://example.com/graphql?token=different&id=9#other",
                    True,
                    {"endpoint": True, "crawler": True, "status_code": 200},
                )
            )
            workspace.write_artifact_lists()
            endpoints = (workspace.rest / "endpoints.txt").read_text(encoding="utf-8")
            api_endpoints = (workspace.rest / "api-endpoints.txt").read_text(
                encoding="utf-8"
            )
            self.assertIn("https://example.com/api/v1/users?id&token", endpoints)
            self.assertIn("https://example.com/graphql?id&token", endpoints)
            self.assertEqual(endpoints.count("https://example.com/graphql?id&token"), 1)
            self.assertNotIn("secret", endpoints)
            self.assertNotIn("different", endpoints)
            self.assertEqual(api_endpoints, endpoints)
            self.assertTrue((workspace.rest / "urls.txt").is_file())
            self.assertTrue((workspace.rest / "wafs.txt").is_file())


if __name__ == "__main__":
    unittest.main()
