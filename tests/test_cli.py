from __future__ import annotations

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cachaza.cli import main
from cachaza.http import HttpError


class CliTests(unittest.TestCase):
    def test_plan_json(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["plan", "-d", "example.com", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["scope"]["domains"], ["example.com"])
        self.assertTrue(payload["passive_by_default"])
        self.assertTrue(payload["organization_hint_optional"])
        self.assertIn("ARIN RDAP", payload["automatic_discovery"])

    def test_single_active_flag_enables_authorized_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            code = main(
                [
                    "run",
                    "-d",
                    "example.com",
                    "-active",
                    "-dry-run",
                    "-stages",
                    "active",
                    "-active",
                    "-o",
                    str(root),
                    "-silent",
                ]
            )
        self.assertEqual(code, 0)

    def test_dry_run_creates_reproducible_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "--dry-run",
                        "--shodan-mode",
                        "off",
                        "--cloud-providers",
                        "none",
                        "--output",
                        str(root),
                        "--silent",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertTrue((root / "rest" / "findings.jsonl").is_file())
            self.assertTrue((root / "rest" / "shodan-queries.txt").is_file())
            self.assertTrue((root / "report.json").is_file())
            self.assertTrue((root / "report.txt").is_file())
            self.assertFalse((root / "report.html").exists())
            manifest = json.loads((root / "rest" / "manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["dry_run"])
            self.assertTrue(manifest["external_commands"])
            self.assertEqual(
                {path.name for path in root.iterdir()},
                {"report.json", "report.txt", "rest"},
            )

    def test_normalize_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "input.txt"
            source.write_text("https://api.example.com/x\nother.test\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["normalize", "-i", str(source), "-r", "example.com"])
            self.assertEqual(code, 0)
            self.assertEqual(output.getvalue(), "api.example.com\n")

    def test_output_directory_is_not_silently_reused(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            root.mkdir()
            (root / "existing.txt").write_text("keep", encoding="utf-8")
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "--dry-run",
                        "--output",
                        str(root),
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual((root / "existing.txt").read_text(encoding="utf-8"), "keep")
            self.assertIn("is not a Cachaza workspace", errors.getvalue())

    def test_output_option_continues_a_compatible_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            first = main(
                [
                    "run",
                    "-d",
                    "example.com",
                    "-dry-run",
                    "-stages",
                    "asn",
                    "-o",
                    str(root),
                    "-silent",
                ]
            )
            before = (root / "rest" / "findings.jsonl").read_text(encoding="utf-8")
            second = main(
                [
                    "run",
                    "-d",
                    "example.com",
                    "-dry-run",
                    "-stages",
                    "active",
                    "-active",
                    "-o",
                    str(root),
                    "-format",
                    "all",
                    "-silent",
                ]
            )
            after = (root / "rest" / "findings.jsonl").read_text(encoding="utf-8")
            self.assertEqual((first, second), (0, 0))
            self.assertEqual(after, before)
            self.assertTrue((root / "report.html").is_file())

    def test_output_option_rejects_a_different_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            self.assertEqual(
                main(["run", "-d", "example.com", "-dry-run", "-o", str(root), "-silent"]),
                0,
            )
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(["run", "-d", "other.example", "-dry-run", "-o", str(root)])
            self.assertEqual(code, 2)
            self.assertIn("scope does not match the existing -o run", errors.getvalue())

    def test_help_advertises_active_enrichment_combinations(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["-h"])
        self.assertEqual(raised.exception.code, 0)
        help_text = output.getvalue()
        self.assertIn("-active -whois -wappalyzer", help_text)
        self.assertIn("cachaza run -h", help_text)
        self.assertIn("passive  Default passive OSINT", help_text)
        self.assertIn("safe     Passive discovery plus bounded DNS", help_text)
        self.assertIn("full     Safe plus Nuclei", help_text)
        for option in (
            "-active",
            "-whois",
            "-wappalyzer",
            "-s",
            "-harvester",
            "-dns-enum",
            "-w",
            "-format all",
            "-up/-update",
        ):
            self.assertRegex(help_text, rf"(?m)^  {re.escape(option)}\s")

        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            main(["run", "-h"])
        self.assertEqual(raised.exception.code, 0)
        run_help = output.getvalue()
        self.assertIn("Reusing the same -o directory", run_help)
        self.assertIn("-resume", run_help)
        self.assertIn("-profile {passive,safe,full}", run_help)
        self.assertIn("passive  Default passive OSINT", run_help)

    def test_final_output_recommends_opening_html_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "-dry-run",
                        "-stages",
                        "asn",
                        "-format",
                        "html",
                        "-o",
                        str(root),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertIn("Recommended next step: open the HTML report", output.getvalue())
            self.assertIn(str(root / "report.html"), output.getvalue())

    def test_domain_only_discovers_asn_and_holder(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            with (
                patch("cachaza.pipeline.resolve_domain_ips", return_value=["8.8.8.8"]),
                patch(
                    "cachaza.pipeline.bgp_he_domain",
                    return_value=[
                        {
                            "asn": "AS64500",
                            "holder": "Example Network",
                            "ips": ["8.8.8.8"],
                            "prefixes": ["8.8.8.0/24"],
                        }
                    ],
                ),
                patch(
                    "cachaza.pipeline.ripe_network_info",
                    return_value={
                        "ip": "8.8.8.8",
                        "prefix": "8.8.8.0/24",
                        "asns": ["AS64500"],
                    },
                ),
                patch(
                    "cachaza.pipeline.arin_rdap_ip",
                    return_value={
                        "name": "EXAMPLE-NET",
                        "handle": "NET-8-8-8-0-1",
                        "type": "DIRECT ALLOCATION",
                        "country": "US",
                        "start_address": "8.8.8.0",
                        "end_address": "8.8.8.255",
                        "origin_asns": ["AS64500"],
                        "organizations": ["Example Registrant"],
                    },
                ),
                patch(
                    "cachaza.pipeline.ripe_as_overview",
                    return_value={
                        "asn": "AS64500",
                        "holder": "EXAMPLE-NET",
                        "announced": True,
                        "registry": "arin",
                    },
                ),
                patch("cachaza.pipeline.find_tool", return_value=None),
            ):
                code = main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "--stages",
                        "asn",
                        "--format",
                        "all",
                        "--output",
                        str(root),
                        "--silent",
                    ]
                )
            self.assertEqual(code, 0)
            for suffix in ("html", "json", "txt", "pdf", "csv"):
                self.assertTrue((root / f"report.{suffix}").is_file())
            report = json.loads((root / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["scope"]["organizations"], [])
            self.assertEqual(report["network_intelligence"]["asns"][0]["value"], "AS64500")
            holders = {item["value"] for item in report["network_intelligence"]["organizations"]}
            self.assertIn("EXAMPLE-NET", holders)
            self.assertIn("Example Registrant", holders)
            self.assertIn("8.8.8.0/24", (root / "rest" / "candidate-cidrs.txt").read_text())
            csv_header = (root / "report.csv").read_text(encoding="utf-8").splitlines()[0]
            self.assertEqual(
                csv_header,
                "observed_at,stage,source,kind,value,scope,metadata_json",
            )

    def test_rejects_unknown_report_format(self) -> None:
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = main(["run", "-d", "example.com", "--dry-run", "--format", "xml"])
        self.assertEqual(code, 2)
        self.assertIn("html,json,txt,pdf,csv, or all", errors.getvalue())

    def test_wappalyzer_requires_explicit_active_mode(self) -> None:
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = main(["run", "-d", "example.com", "-wappalyzer", "-dry-run"])
        self.assertEqual(code, 2)
        self.assertIn("requires -active", errors.getvalue())

    def test_wappalyzer_uses_httpx_fingerprints_without_duplicate_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            code = main(
                [
                    "run",
                    "-d",
                    "example.com",
                    "-active",
                    "-wappalyzer",
                    "-dry-run",
                    "-stages",
                    "active",
                    "-active-tools",
                    "httpx",
                    "-o",
                    str(root),
                    "-silent",
                ]
            )
            self.assertEqual(code, 0)
            manifest = json.loads(
                (root / "rest" / "manifest.json").read_text(encoding="utf-8")
            )
            commands = [item["command"] for item in manifest["external_commands"]]
            self.assertEqual(len(commands), 1)
            self.assertIn("-tech-detect", commands[0])
            self.assertIn("-ip", commands[0])

    def test_no_color_removes_ansi_from_text_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            colored = Path(temp) / "colored"
            plain = Path(temp) / "plain"
            self.assertEqual(
                main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "-dry-run",
                        "-stages",
                        "asn",
                        "-o",
                        str(colored),
                        "-silent",
                    ]
                ),
                0,
            )
            self.assertEqual(
                main(
                    [
                        "-nc",
                        "run",
                        "-d",
                        "example.com",
                        "-dry-run",
                        "-stages",
                        "asn",
                        "-o",
                        str(plain),
                        "-silent",
                    ]
                ),
                0,
            )
            self.assertIn("\x1b[", (colored / "report.txt").read_text(encoding="utf-8"))
            self.assertNotIn("\x1b[", (plain / "report.txt").read_text(encoding="utf-8"))

    def test_network_limits_above_two_are_rejected(self) -> None:
        for option in ("-jobs", "-rate-limit", "-nuclei-rate-limit", "-nuclei-concurrency"):
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(["run", "-d", "example.com", "-dry-run", option, "3"])
            self.assertEqual(code, 2, option)
            self.assertIn("between 1 and 2", errors.getvalue())

    def test_simple_output_name_is_created_under_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            previous = Path.cwd()
            try:
                os.chdir(temp)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = main(
                        [
                            "run",
                            "-d",
                            "example.com",
                            "-dry-run",
                            "-stages",
                            "asn",
                            "-o",
                            "client-report",
                        ]
                    )
                root = Path(temp) / "output" / "client-report"
                self.assertEqual(code, 0)
                self.assertTrue((root / "report.json").is_file())
                self.assertIn(str(root), output.getvalue())
            finally:
                os.chdir(previous)

    def test_verbose_prints_findings_and_omits_external_silent_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "-dry-run",
                        "-stages",
                        "asn,subdomains",
                        "-v",
                        "-o",
                        str(root),
                        "-shodan-mode",
                        "off",
                        "-cloud-providers",
                        "none",
                    ]
                )
            self.assertEqual(code, 0)
            log = errors.getvalue()
            plain_log = re.sub(r"\x1b\[[0-9;]*m", "", log)
            self.assertIn("[FOUND] domain: example.com", plain_log)
            self.assertIn("Stage: asn", plain_log)
            manifest = json.loads((root / "rest" / "manifest.json").read_text(encoding="utf-8"))
            commands = "\n".join(item["command"] for item in manifest["external_commands"])
            self.assertNotIn("-silent", commands)

    def test_ct_continues_with_certspotter_when_crtsh_is_down(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            errors = io.StringIO()
            with (
                patch(
                    "cachaza.pipeline.certspotter_domains",
                    return_value=["api.example.com"],
                ),
                patch(
                    "cachaza.pipeline.crtsh_domains",
                    side_effect=HttpError("HTTP 502 Bad Gateway"),
                ),
                contextlib.redirect_stderr(errors),
            ):
                code = main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "-stages",
                        "ct",
                        "-o",
                        str(root),
                        "-format",
                        "json",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertIn("Continuing with Cert Spotter results", errors.getvalue())
            findings = (root / "rest" / "findings.jsonl").read_text(encoding="utf-8")
            self.assertIn('"source": "certspotter"', findings)
            self.assertIn('"value": "api.example.com"', findings)

    def test_silent_suppresses_progress_findings_and_report_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "run",
                        "-d",
                        "example.com",
                        "-dry-run",
                        "-stages",
                        "asn",
                        "-v",
                        "-silent",
                        "-o",
                        str(root),
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
