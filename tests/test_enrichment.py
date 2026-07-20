from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cachaza.console import Console
from cachaza.external import CommandResult
from cachaza.models import TargetSpec
from cachaza.pipeline import Pipeline, RunOptions
from cachaza.workspace import RunWorkspace


class EnrichmentTests(unittest.TestCase):
    def test_whois_queries_each_unique_public_ip_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            pipeline = Pipeline(
                TargetSpec(cidrs=["8.8.8.0/24"]),
                workspace,
                RunOptions(stages=[], whois=True),
                Console(silent=True, color=False),
            )
            pipeline._add("asn", "dns", "ip", "8.8.8.8", False, {})
            pipeline._add("asn", "bgp", "ip", "8.8.8.8", False, {})
            pipeline.runner.run = Mock(
                return_value=CommandResult(
                    ["whois", "8.8.8.8"],
                    0,
                    "NetRange: 8.8.8.0 - 8.8.8.255\nNetName: GOOGLE-DNS\nCountry: US\n",
                    "",
                )
            )
            with patch("cachaza.pipeline.find_tool", return_value="whois"):
                details = pipeline.stage_whois()

            pipeline.runner.run.assert_called_once_with(
                ["whois", "8.8.8.8"], timeout=60
            )
            self.assertIn("1/1", details)
            rows = [
                json.loads(line)
                for line in (workspace.rest / "whois-results.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["summary"]["netname"], ["GOOGLE-DNS"])

    def test_wappalyzer_rows_preserve_endpoint_and_resolved_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            pipeline = Pipeline(
                TargetSpec(domains=["example.com"]),
                workspace,
                RunOptions(stages=[], active=True, wappalyzer=True),
                Console(silent=True, color=False),
            )
            count = pipeline._consume_wappalyzer_rows(
                [
                    {
                        "input": "example.com",
                        "url": "https://example.com",
                        "a": ["8.8.8.8"],
                        "tech": ["Cloudflare", "HSTS"],
                        "status_code": 200,
                    }
                ],
                stage="wappalyzer",
            )
            self.assertEqual(count, 2)
            self.assertEqual(workspace.values("ip"), ["8.8.8.8"])
            self.assertEqual(
                workspace.values("technology"),
                ["example.com: Cloudflare", "example.com: HSTS"],
            )


if __name__ == "__main__":
    unittest.main()
