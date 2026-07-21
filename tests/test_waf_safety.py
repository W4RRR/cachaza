from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cachaza.adapters import waf
from cachaza.console import Console
from cachaza.models import Finding, TargetSpec
from cachaza.pipeline import Pipeline, RunOptions
from cachaza.reports import build_key_findings, render_key_findings_console
from cachaza.workspace import RunWorkspace


class WafAdapterSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetSpec(domains=["example.com"])

    def test_nuclei_vendors_are_normalized_and_keep_origin_evidence(self) -> None:
        expected = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "aws-waf": "AWS WAF",
            "f5-big-ip": "F5 BIG-IP",
            "imperva": "Imperva",
        }
        for matcher, vendor in expected.items():
            with self.subTest(matcher=matcher):
                output = json.dumps(
                    {
                        "template-id": "waf-detect",
                        "matcher-name": matcher,
                        "matched-at": "https://api.example.com/login",
                    }
                )
                findings = waf.parse_nuclei(
                    output, "https://api.example.com", self.target
                )
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual((finding.stage, finding.source, finding.kind), (
                    "waf",
                    "nuclei/waf-detect",
                    "waf",
                ))
                self.assertEqual(finding.value, vendor)
                self.assertEqual(finding.metadata["vendor"], vendor)
                self.assertEqual(finding.metadata["target"], "https://api.example.com")
                self.assertEqual(finding.metadata["confidence"], "detected")
                self.assertEqual(finding.metadata["template_id"], "waf-detect")

    def test_nuclei_non_detections_and_other_templates_are_ignored(self) -> None:
        rows = (
            {"template-id": "waf-detect"},
            {"template-id": "waf-detect", "matcher-name": "no waf detected"},
            {"template-id": "cve-2026-test", "matcher-name": "cloudflare"},
        )
        for row in rows:
            self.assertEqual(
                waf.parse_nuclei(json.dumps(row), "https://example.com", self.target),
                [],
            )
        self.assertEqual(waf.parse_nuclei("not-json\n{broken", "https://example.com", self.target), [])
        self.assertEqual(waf.parse_nuclei("", "https://example.com", self.target), [])

    def test_generic_apache_match_requires_manual_validation(self) -> None:
        finding = waf.parse_nuclei(
            json.dumps(
                {"template-id": "waf-detect", "matcher-name": "apachegeneric"}
            ),
            "https://example.com",
            self.target,
        )[0]
        self.assertEqual(finding.value, "Apache Generic")
        self.assertEqual(finding.metadata["confidence"], "candidate")
        self.assertTrue(finding.metadata["requires_manual_validation"])

    def test_waf_findings_from_same_tool_remain_distinct_per_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            for origin in ("https://example.com", "https://api.example.com"):
                finding = waf.parse_nuclei(
                    json.dumps(
                        {"template-id": "waf-detect", "matcher-name": "cloudflare"}
                    ),
                    origin,
                    self.target,
                )[0]
                self.assertTrue(workspace.add(finding))
            self.assertEqual(len(workspace.values("waf")), 1)
            self.assertEqual(len([item for item in workspace.findings if item.kind == "waf"]), 2)
            summary = build_key_findings(workspace.findings)
            self.assertEqual(
                summary["wafs"],
                ["Cloudflare @ https://api.example.com, https://example.com"],
            )

    def test_report_distinguishes_absence_from_unknown_vendor(self) -> None:
        empty = render_key_findings_console(build_key_findings([]), color=False)
        self.assertIn("WAFs (0)\n    No evidence observed", empty)
        unknown = waf._finding(
            "wafw00f", waf.UNKNOWN_WAF, "https://example.com", self.target, "WAF detected"
        )
        summary = build_key_findings([unknown])
        self.assertEqual(
            summary["wafs"],
            [
                "WAF detected (vendor unknown) [candidate; manual validation] "
                "@ https://example.com"
            ],
        )

    def test_generic_waf_candidate_is_labeled_in_key_findings(self) -> None:
        generic = waf.parse_nuclei(
            json.dumps(
                {"template-id": "waf-detect", "matcher-name": "apachegeneric"}
            ),
            "https://example.com",
            self.target,
        )[0]
        rendered = render_key_findings_console(
            build_key_findings([generic]), color=False
        )
        self.assertIn("Apache Generic [candidate; manual validation]", rendered)


class WafPipelineTargetTests(unittest.TestCase):
    def test_stage_waf_runs_one_nuclei_command_per_confirmed_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            pipeline = Pipeline(
                TargetSpec(domains=["example.com"]),
                workspace,
                RunOptions(
                    stages=[],
                    active=True,
                    dry_run=True,
                    waf_tools=["nuclei"],
                ),
                Console(silent=True, color=False),
            )
            for value in (
                "https://example.com/",
                "https://example.com/login",
                "https://example.com/api/v1?id=1",
                "https://example.com:443/admin",
                "https://example.com:8443/health",
            ):
                pipeline._add(
                    "http", "httpx", "url", value, True, {"status_code": 200}
                )
            pipeline._add("ports", "naabu", "service", "example.com:8080", True, {})
            pipeline.stage_waf()
            commands = [item["command"] for item in pipeline.runner.history]
            self.assertEqual(len(commands), 2)
            self.assertTrue(any("-u https://example.com " in command for command in commands))
            self.assertTrue(
                any("-u https://example.com:8443 " in command for command in commands)
            )
            self.assertTrue(all("http/technologies/waf-detect.yaml" in command for command in commands))
            self.assertTrue(all("-tags" not in command and "-severity" not in command for command in commands))
            self.assertTrue(all("/login" not in command and "/api/" not in command for command in commands))
            self.assertTrue(all(":8080" not in command for command in commands))

    def test_isolated_waf_stage_uses_only_root_https_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            pipeline = Pipeline(
                TargetSpec(domains=["example.com"]),
                workspace,
                RunOptions(
                    stages=[], active=True, dry_run=True, waf_tools=["nuclei"]
                ),
                Console(silent=True, color=False),
            )
            pipeline.stage_waf()
            commands = [item["command"] for item in pipeline.runner.history]
            self.assertEqual(len(commands), 1)
            self.assertIn("-u https://example.com ", commands[0])
            self.assertNotIn(":8080", commands[0])
            self.assertNotIn(":8443", commands[0])

    def test_waf_default_tools_exclude_nmap(self) -> None:
        self.assertEqual(RunOptions().waf_tools, ["wafw00f", "nuclei"])


if __name__ == "__main__":
    unittest.main()
