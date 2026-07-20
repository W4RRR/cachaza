from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from cachaza.html_report import render_html
from cachaza.models import Finding, TargetSpec
from cachaza.reports import build_report_data
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

    def test_html_contains_expandable_evidence_and_embedded_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            report = self._report(Path(temp))
        document = render_html(report)
        self.assertIn("Interactive relationship explorer", document)
        self.assertIn("Complete evidence explorer", document)
        self.assertIn('id="relationship-graph"', document)
        self.assertIn('id="graph-zoom"', document)
        self.assertIn('id="layout-groups"', document)
        self.assertIn('id="graph-search"', document)
        self.assertIn('id="key-findings-section"', document)
        self.assertIn('renderInspector(node);showTooltip', document)
        self.assertIn('if(selectedNode)renderInspector(selectedNode);else emptyInspector()', document)
        self.assertIn('data-kind="asn"', document)
        self.assertIn("finding.metadata", document)
        match = re.search(
            r'<script type="application/json" id="report-data">(.*?)</script>',
            document,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        embedded = json.loads(match.group(1))
        self.assertEqual(len(embedded["findings"]), 7)
        self.assertGreaterEqual(len(embedded["graph"]["edges"]), 3)


if __name__ == "__main__":
    unittest.main()
