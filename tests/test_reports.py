from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from cachaza.html_report import render_html
from cachaza.models import Finding, TargetSpec
from cachaza.reports import _build_origin_trace, build_report_data
from cachaza.workspace import RunWorkspace


class InteractiveReportTests(unittest.TestCase):
    def _report(self, root: Path) -> dict[str, object]:
        workspace = RunWorkspace(root)
        workspace.add(
            Finding(
                stage="input",
                source="scope",
                kind="domain",
                value="example.com",
                in_scope=True,
                metadata={"root": True},
            )
        )
        workspace.add(
            Finding(
                stage="ct",
                source="certspotter",
                kind="domain",
                value="api.example.com",
                in_scope=True,
                metadata={"root": "example.com", "relationship": "certificate"},
            )
        )
        workspace.add(
            Finding(
                stage="asn",
                source="bgp.he.net",
                kind="asn",
                value="AS64500",
                in_scope=False,
                metadata={"input": "example.com", "holder": "Example Network"},
            )
        )
        workspace.add(
            Finding(
                stage="asn",
                source="arin-rdap",
                kind="organization",
                value="Example Network",
                in_scope=False,
                metadata={"asn": "AS64500", "role": "holder"},
            )
        )
        workspace.add(
            Finding(
                stage="asn",
                source="ripe-stat",
                kind="cidr",
                value="203.0.113.0/24",
                in_scope=False,
                metadata={"asn": "AS64500"},
            )
        )
        workspace.add(
            Finding(
                stage="wappalyzer",
                source="httpx-wappalyzer",
                kind="technology",
                value="example.com: Nginx",
                in_scope=True,
                metadata={
                    "technology": "Nginx",
                    "target": "example.com",
                    "url": "https://example.com",
                    "ips": ["203.0.113.9"],
                },
            )
        )
        workspace.add(
            Finding(
                stage="whois",
                source="whois",
                kind="whois",
                value="203.0.113.9",
                in_scope=False,
                metadata={"summary": {"netname": ["EXAMPLE-NET"]}},
            )
        )
        return build_report_data(
            workspace,
            TargetSpec(domains=["example.com"]),
            version="0.4.0",
            failures=[],
        )

    def test_graph_connects_domain_network_and_holder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            report = self._report(Path(temp))
        graph = report["graph"]
        node_ids = {node["id"] for node in graph["nodes"]}
        self.assertIn("domain:example.com", node_ids)
        self.assertNotIn("domain:True", node_ids)
        self.assertIn("asn:AS64500", node_ids)
        self.assertIn("organization:Example Network", node_ids)
        edges = {
            (edge["source"], edge["target"], edge["relationship"])
            for edge in graph["edges"]
        }
        self.assertIn(
            ("domain:example.com", "domain:api.example.com", "certificate"), edges
        )
        self.assertIn(
            ("asn:AS64500", "organization:Example Network", "holder"), edges
        )
        self.assertIn(("cidr:203.0.113.0/24", "asn:AS64500", "announced by"), edges)
        self.assertIn(
            ("domain:example.com", "technology:example.com: Nginx", "uses technology"),
            edges,
        )
        self.assertIn(
            ("ip:203.0.113.9", "technology:example.com: Nginx", "technology observed at"),
            edges,
        )
        self.assertIn(
            ("ip:203.0.113.9", "whois:203.0.113.9", "WHOIS record"),
            edges,
        )

    def test_origin_trace_marks_validated_direct_path_and_graph_ttp_chain(self) -> None:
        ranking = {
            "status": "completed",
            "mode": "balanced",
            "origin_ip": "203.0.113.45",
            "origin_probability_percent": 88,
            "confidence_band": "high",
            "classification": "high_confidence_origin",
            "direct_requests_performed": 8,
            "candidates_rejected_before_validation": 2,
            "cdn_waf_detected": {
                "provider": "Cloudflare",
                "signals": ["cf-ray", "official range"],
            },
            "primary": [
                {
                    "ip": "203.0.113.45",
                    "validation_status": "high_confidence_origin",
                    "independent_source_families": [
                        "virustotal",
                        "urlscan",
                        "direct_validation",
                    ],
                    "evidence": [
                        {
                            "code": "historical_apex_dns",
                            "description": "Historical apex A record",
                            "score": 30,
                            "source": "virustotal",
                            "source_family": "virustotal",
                        },
                        {
                            "code": "same_certificate",
                            "description": "Same certificate SHA-256",
                            "score": 25,
                            "source": "direct-origin-validation",
                            "source_family": "direct_validation",
                        },
                    ],
                }
            ],
        }
        trace = _build_origin_trace(ranking)
        self.assertEqual(trace["status"], "direct_path_validated")
        self.assertIn("Same certificate SHA-256", trace["validation_signals"])
        self.assertEqual(len(trace["steps"]), 5)

        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            workspace.add(
                Finding("input", "scope", "domain", "example.com", True, {"root": True})
            )
            workspace.add(
                Finding(
                    "origin",
                    "origin-correlation",
                    "origin_candidate",
                    "203.0.113.45",
                    False,
                    {"root": "example.com", "origin_probability_percent": 88},
                )
            )
            workspace.write_json("origin/final-ranking.json", ranking)
            report = build_report_data(
                workspace,
                TargetSpec(domains=["example.com"]),
                version="test",
                failures=[],
            )
        primary = next(
            node for node in report["graph"]["nodes"] if node.get("is_primary_origin")
        )
        self.assertEqual(primary["label"], "203.0.113.45")
        self.assertEqual(
            len(
                [
                    node
                    for node in report["graph"]["nodes"]
                    if node["kind"] == "origin_technique"
                ]
            ),
            5,
        )
        self.assertEqual(
            len([edge for edge in report["graph"]["edges"] if edge.get("origin_path")]),
            6,
        )
        document = render_html(report)
        self.assertIn("DIRECT ORIGIN PATH VALIDATED", document)
        self.assertIn("How Cachaza reached this IP", document)
        self.assertIn('id="origin-chain-title">Origin Exposure Path', document)
        self.assertIn("Validated bypass", document)
        self.assertIn(
            'aria-label="Five-step Origin attribution chain ending at 203.0.113.45"',
            document,
        )
        self.assertEqual(document.count('class="origin-chain-node"'), 5)
        self.assertIn('class="origin-chain-node origin-chain-result critical"', document)
        self.assertIn('href="#origin-step-4"', document)
        self.assertIn("Orange dashed relationships show the Origin attribution chain", document)

        report["presentation"] = {
            "mode": "professional",
            "title": "Professional Recon Report",
            "subject": "example.com",
            "white_label": True,
        }
        professional = render_html(report)
        self.assertIn("Professional Recon Report", professional)
        self.assertIn("Report prepared for <strong>example.com</strong>", professional)
        self.assertIn("How the assessment reached this IP", professional)
        self.assertIn("Origin Exposure Path", professional)
        self.assertIn("How to remediate the Origin exposure", professional)
        self.assertIn("Restrict public ingress to the Origin", professional)
        self.assertNotIn("cachaza", professional.casefold())

    def test_origin_trace_does_not_claim_bypass_for_passive_only_evidence(self) -> None:
        trace = _build_origin_trace(
            {
                "origin_ip": "203.0.113.45",
                "origin_probability_percent": 72,
                "confidence_band": "probable",
                "classification": "probable_origin",
                "direct_requests_performed": 0,
                "primary": [
                    {
                        "ip": "203.0.113.45",
                        "independent_source_families": ["virustotal", "urlscan"],
                        "evidence": [],
                    }
                ],
            }
        )
        self.assertEqual(trace["status"], "passive_correlation_only")
        self.assertNotIn("validated as a directly reachable", trace["summary"])

    def test_origin_trace_does_not_treat_negative_direct_evidence_as_bypass(self) -> None:
        trace = _build_origin_trace(
            {
                "origin_ip": "203.0.113.45",
                "origin_probability_percent": 70,
                "confidence_band": "probable",
                "classification": "probable_origin",
                "direct_requests_performed": 4,
                "primary": [
                    {
                        "ip": "203.0.113.45",
                        "independent_source_families": [
                            "virustotal",
                            "direct_validation",
                        ],
                        "evidence": [
                            {
                                "code": "other_application",
                                "description": "Content corresponds to a different application",
                                "score": -30,
                                "source": "direct-origin-validation",
                                "source_family": "direct_validation",
                            }
                        ],
                    }
                ],
            }
        )
        self.assertEqual(trace["status"], "direct_validation_inconclusive")

    def test_html_contains_expandable_evidence_and_embedded_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            report = self._report(Path(temp))
        document = render_html(report)
        self.assertIn("Interactive relationship explorer", document)
        self.assertIn("Complete evidence explorer", document)
        self.assertIn('id="relationship-graph"', document)
        self.assertIn('id="graph-zoom"', document)
        self.assertIn('id="graph-spacing"', document)
        self.assertIn('id="graph-spacing-value"', document)
        self.assertIn('id="layout-groups"', document)
        self.assertIn('id="graph-search"', document)
        self.assertIn('id="key-findings-section"', document)
        self.assertIn('hoveredNode=node;showTooltip', document)
        self.assertNotIn('hoveredNode=node;renderInspector(node)', document)
        self.assertIn('id="tool-findings-section"', document)
        self.assertIn('if(selectedNode)renderInspector(selectedNode);else emptyInspector()', document)
        self.assertIn('data-kind="asn"', document)
        self.assertIn("finding.metadata", document)
        self.assertIn("function applySpacing()", document)
        self.assertIn('spacingSlider.addEventListener("input",applySpacing)', document)
        self.assertIn("const targets=layoutPositions(currentLayout)", document)
        self.assertIn("main{width:100%;max-width:none;margin:0", document)
        self.assertNotIn("main{max-width:1280px", document)
        match = re.search(
            r'<script type="application/json" id="report-data">(.*?)</script>',
            document,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        embedded = json.loads(match.group(1))
        self.assertEqual(len(embedded["findings"]), 7)
        self.assertGreaterEqual(len(embedded["graph"]["edges"]), 3)

    def test_key_findings_group_wafs_and_subdomains_into_readable_cards(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            workspace.add(
                Finding("input", "scope", "domain", "example.com", True, {"root": True})
            )
            workspace.add(
                Finding(
                    "subdomains",
                    "subfinder",
                    "domain",
                    "api.example.com",
                    True,
                    {"root": "example.com"},
                )
            )
            workspace.add(
                Finding(
                    "dns",
                    "dnsx",
                    "domain",
                    "api.example.com",
                    True,
                    {"resolved": True},
                )
            )
            workspace.add(
                Finding(
                    "http",
                    "httpx",
                    "url",
                    "https://api.example.com",
                    True,
                    {"host": "api.example.com", "status_code": 200},
                )
            )
            workspace.add(
                Finding(
                    "waf",
                    "nuclei-waf-detect",
                    "waf",
                    "Apache Generic",
                    True,
                    {
                        "vendor": "Apache Generic",
                        "target": "https://api.example.com",
                        "confidence": "candidate",
                        "requires_manual_validation": True,
                    },
                )
            )
            report = build_report_data(
                workspace,
                TargetSpec(domains=["example.com"]),
                version="test",
                failures=[],
            )
        document = render_html(report)
        key_section = document.split('id="key-findings-section"', 1)[1].split(
            'id="origin-discovery-section"', 1
        )[0]
        self.assertIn('class="key-findings-layout"', key_section)
        self.assertIn("WAF observations", key_section)
        self.assertIn("Apache Generic", key_section)
        self.assertIn("Candidate · Manual Validation", key_section)
        self.assertIn("HTTP-responsive", key_section)
        self.assertIn("api.example.com", key_section)
        self.assertIn("HTTP 200", key_section)
        self.assertNotIn("<table", key_section)

    def test_report_surfaces_external_source_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = RunWorkspace(root)
            workspace.write_json(
                "ct/source-status.json",
                {
                    "certspotter": {
                        "status": "ok",
                        "retrieved": 2,
                        "added": 1,
                    },
                    "crt.sh": {
                        "status": "error",
                        "retrieved": 0,
                        "added": 0,
                        "error": "example.com: remote_5xx",
                    },
                },
            )
            workspace.write_json(
                "tenant-domains/status.json",
                {
                    "example.com": {
                        "status": "empty",
                        "related_domains": 0,
                        "diagnostic": "No related Microsoft 365 tenant domains were observed.",
                    }
                },
            )
            report = build_report_data(
                workspace,
                TargetSpec(domains=["example.com"]),
                version="test",
                failures=[],
            )
        self.assertEqual(report["source_status"]["certspotter"]["retrieved"], 2)
        self.assertEqual(report["source_status"]["tenant-domains"]["status"], "empty")
        self.assertIn("crt.sh: example.com: remote_5xx", report["issues"])
        document = render_html(report)
        self.assertIn("External source status", document)
        self.assertIn("remote_5xx", document)

    def test_dnsenum_only_candidates_are_omitted_from_summary_and_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            workspace.add(
                Finding("input", "scope", "domain", "example.com", True, {"root": True})
            )
            workspace.add(
                Finding(
                    "dns_enum",
                    "dnsenum",
                    "domain",
                    "noise.example.com",
                    True,
                    {"root": "example.com", "dns_enumeration": True},
                )
            )
            workspace.add(
                Finding(
                    "subdomains",
                    "subfinder",
                    "domain",
                    "api.example.com",
                    True,
                    {"root": "example.com"},
                )
            )
            workspace.add(
                Finding(
                    "dns",
                    "dnsx",
                    "domain",
                    "api.example.com",
                    True,
                    {"resolved": True},
                )
            )
            workspace.add(
                Finding(
                    "http",
                    "httpx",
                    "url",
                    "https://api.example.com",
                    True,
                    {"host": "api.example.com", "status_code": 200},
                )
            )
            report = build_report_data(
                workspace,
                TargetSpec(domains=["example.com"]),
                version="test",
                failures=[],
            )
        self.assertEqual(report["key_findings"]["subdomains"], ["api.example.com"])
        self.assertEqual(report["subdomain_summary"]["dns_only"], [])
        self.assertIn("noise.example.com", report["subdomain_summary"]["omitted"])
        node_ids = {node["id"] for node in report["graph"]["nodes"]}
        self.assertIn("domain:api.example.com", node_ids)
        self.assertNotIn("domain:noise.example.com", node_ids)


if __name__ == "__main__":
    unittest.main()
