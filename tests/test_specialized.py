from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cachaza.adapters import blackwidow, contacts, dns_enum, harvester, waf
from cachaza.cli import main
from cachaza.console import CACHAZA_WORDMARK, Console
from cachaza.models import Finding, TargetSpec
from cachaza.reports import (
    build_key_findings,
    build_subdomain_summary,
    render_key_findings_console,
)
from cachaza.update import is_newer, perform_update, version_key


class SpecializedAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetSpec(domains=["example.com"])

    def test_waf_adapters_normalize_vendor_and_ignore_negative_output(self) -> None:
        findings = waf.parse_wafw00f(
            "[+] The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF.",
            "https://example.com",
            self.target,
        )
        self.assertEqual(findings[0].kind, "waf")
        self.assertIn("Cloudflare", findings[0].value)
        self.assertEqual(
            waf.parse_wafw00f(
                "[-] No WAF detected by the generic detection",
                "https://example.com",
                self.target,
            ),
            [],
        )
        self.assertEqual(
            waf.parse_wafw00f(
                "The Web Application Firewall Fingerprinting Toolkit\n"
                "~ Sniffing Web Application Firewalls since 2014 ~",
                "https://example.com",
                self.target,
            ),
            [],
        )

    def test_waf_regressions_do_not_promote_test_url_to_vendor(self) -> None:
        line = json.dumps(
            {
                "template-id": "waf-detect",
                "info": {"name": "HTTP WAF Detection"},
                "matcher-name": "cloudflare",
            }
        )
        self.assertEqual(
            waf.parse_nuclei(line, "https://example.com", self.target)[0].value,
            "Cloudflare",
        )
        xml = '<nmaprun><host><ports><port><script id="http-waf-detect" output="IDS/IPS/WAF detected:&#10;https://example.com/?x=&lt;script&gt;"/></port></ports></host></nmaprun>'
        self.assertEqual(
            waf.parse_nmap_xml(xml, "https://example.com", self.target)[0].value,
            waf.UNKNOWN_WAF,
        )

    def test_contact_page_extracts_public_details(self) -> None:
        payload = """
        <html><a href="mailto:hello@example.com">write</a>
        <a href="tel:+1 (929) 600-2911">call</a>
        <script type="application/ld+json">
        {"@type":"PostalAddress","streetAddress":"8550 Argyle Business Loop",
         "addressLocality":"Jacksonville","addressRegion":"FL","postalCode":"32244-8906"}
        </script></html>
        """
        findings = contacts.parse_html(
            "https://example.com/contacto/", payload, "example.com", self.target
        )
        values = {(item.kind, item.value) for item in findings}
        self.assertIn(("email", "hello@example.com"), values)
        self.assertIn(("phone", "+1 (929) 600-2911"), values)
        self.assertIn(
            ("address", "8550 Argyle Business Loop, Jacksonville, FL, 32244-8906"),
            values,
        )
        self.assertNotIn(("phone", "32244-8906"), values)

    def test_blackwidow_normalizes_manual_validation_candidates(self) -> None:
        findings = blackwidow.parse_output(
            "Email found admin@example.com\nhttps://api.example.com/v1/users\nP2 possible XSS candidate",
            "example.com",
            self.target,
        )
        self.assertIn(("email", "admin@example.com"), {(item.kind, item.value) for item in findings})
        self.assertIn("api_endpoint", {item.kind for item in findings})
        candidate = next(item for item in findings if item.kind == "security_finding")
        self.assertTrue(candidate.metadata["requires_manual_validation"])

    def test_harvester_extracts_contacts_and_redacts_secret_values(self) -> None:
        payload = json.dumps(
            {
                "emails": ["ops@example.com"],
                "hosts": ["api.example.com"],
                "interesting_urls": ["https://api.example.com/v1/users"],
                "phone": "+34 600 123 456",
                "address": "Calle Example 1, Madrid",
                "api_key": "super-secret-value",
            }
        )
        findings = harvester.parse_json(payload, "example.com", self.target)
        by_kind = {item.kind: item for item in findings}
        self.assertEqual(by_kind["email"].value, "ops@example.com")
        self.assertEqual(by_kind["domain"].value, "api.example.com")
        self.assertEqual(by_kind["api_endpoint"].value, "https://api.example.com/v1/users")
        self.assertTrue(by_kind["api_key_candidate"].value.startswith("redacted:"))
        self.assertNotIn("super-secret-value", json.dumps([item.to_dict() for item in findings]))

    def test_dns_enum_marks_only_successful_zone_transfer(self) -> None:
        findings = dns_enum.parse_output(
            "api.example.com 192.0.2.10\nZone transfer was successful",
            "dnsenum",
            "example.com",
            self.target,
        )
        self.assertIn("dns_zone_transfer", {item.kind for item in findings})
        failed = dns_enum.parse_output(
            "Zone transfer failed: AXFR refused",
            "dnsenum",
            "example.com",
            self.target,
        )
        self.assertNotIn("dns_zone_transfer", {item.kind for item in failed})

    def test_key_findings_limit_wording_and_zone_warning(self) -> None:
        findings = [
            Finding(
                "subdomains",
                "test",
                "domain",
                f"s{index}.example.com",
                True,
                {"root": "example.com"},
            )
            for index in range(15)
        ]
        findings.append(
            Finding("dns_enum", "dnsenum", "dns_zone_transfer", "example.com", True, {"allowed": True})
        )
        rendered = render_key_findings_console(
            build_key_findings(findings),
            subdomain_summary=build_subdomain_summary(findings),
            color=False,
        )
        self.assertIn("more actionable subdomains in the full report", rendered)
        self.assertIn("ALLOWED: example.com", rendered)

    def test_key_findings_groups_wafs_and_validated_subdomains_on_separate_lines(self) -> None:
        findings = [
            Finding(
                "waf",
                "nuclei",
                "waf",
                "Cloudflare",
                True,
                {"vendor": "Cloudflare", "target": "https://api.example.com"},
            ),
            Finding(
                "dns",
                "dnsx",
                "domain",
                "api.example.com",
                True,
                {"root": "example.com", "resolved": True},
            ),
            Finding(
                "http",
                "httpx",
                "url",
                "https://api.example.com",
                True,
                {"host": "api.example.com", "status_code": 200},
            ),
            Finding(
                "dns_enum",
                "dnsenum",
                "domain",
                "noise.example.com",
                True,
                {"root": "example.com"},
            ),
        ]
        rendered = render_key_findings_console(
            build_key_findings(findings),
            subdomain_summary=build_subdomain_summary(findings),
            color=False,
        )
        self.assertIn("WAFs (1)\n    Cloudflare\n      - https://api.example.com", rendered)
        self.assertIn(
            "Actionable subdomains (1)\n    HTTP-responsive (1)\n"
            "      - api.example.com [HTTP 200]",
            rendered,
        )
        self.assertIn("Unverified / wildcard-like candidates omitted: 1", rendered)
        self.assertNotIn("Cloudflare @ https://api.example.com", rendered)


class SpecializedCliTests(unittest.TestCase):
    def test_blackwidow_depth_maps_to_value_taking_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            code = main(
                [
                    "run", "-d", "example.com", "-stages", "blackwidow",
                    "-blw", "2", "-active", "-dry-run", "-o", str(root), "-silent",
                ]
            )
            self.assertEqual(code, 0)
            manifest = json.loads((root / "rest" / "manifest.json").read_text(encoding="utf-8"))
            self.assertIn(
                "blackwidow -l 2 -v y -s y -u https://example.com/",
                manifest["external_commands"][0]["command"],
            )

    def test_active_bundles_require_explicit_authorization(self) -> None:
        for option in ("-w", "-harvester", "-dns-enum"):
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(["run", "-d", "example.com", option, "-dry-run"])
            self.assertEqual(code, 2)
            self.assertIn("require -active", errors.getvalue())

    def test_dry_run_plans_all_requested_specialized_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            code = main(
                [
                    "run",
                    "-d",
                    "example.com",
                    "-stages",
                    "subdomains",
                    "-s",
                    "-harvester",
                    "-dns-enum",
                    "-w",
                    "-active",
                    "-dry-run",
                    "-o",
                    str(root),
                    "-silent",
                ]
            )
            self.assertEqual(code, 0)
            manifest = json.loads((root / "rest" / "manifest.json").read_text(encoding="utf-8"))
            commands = "\n".join(item["command"] for item in manifest["external_commands"])
            self.assertIn("subfinder -d example.com -all -oJ -cs -rl 1 -t 1", commands)
            self.assertIn("assetfinder --subs-only example.com", commands)
            self.assertIn("theHarvester -d example.com", commands)
            self.assertIn("dnsenum example.com", commands)
            self.assertIn("fierce -dns example.com", commands)
            self.assertIn("wafw00f https://example.com -a", commands)
            self.assertIn("http/technologies/waf-detect.yaml", commands)
            self.assertIn(
                "-rl 1 -bulk-size 1 -c 1 -timeout 20 -retries 0 -no-stdin -omit-raw",
                commands,
            )
            self.assertNotIn("http-waf-detect,http-waf-fingerprint", commands)

    def test_dns_enumeration_runs_before_wildcard_filtered_dns_and_http(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            code = main(
                [
                    "run",
                    "-d",
                    "example.com",
                    "-profile",
                    "safe",
                    "-dns-enum",
                    "-active",
                    "-dry-run",
                    "-o",
                    str(root),
                    "-silent",
                ]
            )
            self.assertEqual(code, 0)
            manifest = json.loads((root / "rest" / "manifest.json").read_text(encoding="utf-8"))
            commands = [item["command"] for item in manifest["external_commands"]]
            dnsenum_index = next(index for index, command in enumerate(commands) if "dnsenum example.com" in command)
            dnsx_index = next(index for index, command in enumerate(commands) if command.startswith("dnsx "))
            httpx_index = next(index for index, command in enumerate(commands) if command.startswith("httpx "))
            self.assertLess(dnsenum_index, dnsx_index)
            self.assertLess(dnsx_index, httpx_index)
            self.assertIn("-wd example.com", commands[dnsx_index])

    def test_help_mentions_update_and_specialized_shortcuts(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            main(["-h"])
        self.assertIn("-up", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            main(["run", "-h"])
        help_text = output.getvalue()
        for option in ("-w", "-harvester", "-dns-enum", "-s", "-blw"):
            self.assertIn(option, help_text)

    def test_up_alias_dispatches_the_verified_updater(self) -> None:
        with patch("cachaza.cli.perform_update", return_value=0) as updater:
            self.assertEqual(main(["-up", "-silent"]), 0)
        updater.assert_called_once()


class UpdateTests(unittest.TestCase):
    def test_semantic_version_comparison(self) -> None:
        self.assertEqual(version_key("v1.2.3"), (1, 2, 3))
        self.assertTrue(is_newer("0.8.1", "0.8.0"))
        self.assertFalse(is_newer("0.8.0", "0.8.0"))

    def test_update_alias_uses_fast_forward_then_reinstalls_and_verifies(self) -> None:
        root = Path("/checkout")
        binaries = {
            "pipx": "/usr/bin/pipx",
            "git": "/usr/bin/git",
            "cachaza": "/home/kali/.local/bin/cachaza",
        }
        with (
            patch("cachaza.update._project_root", return_value=root),
            patch("cachaza.update.shutil.which", side_effect=lambda name: binaries.get(name)),
            patch("cachaza.update.subprocess.run", return_value=Mock(returncode=0)) as run,
        ):
            self.assertEqual(perform_update(Console(silent=True)), 0)

        calls = run.call_args_list
        self.assertEqual(calls[0].args[0], ["/usr/bin/git", "pull", "--ff-only", "origin", "main"])
        self.assertEqual(calls[0].kwargs["cwd"], root)
        self.assertEqual(calls[1].args[0], ["/usr/bin/pipx", "install", "--force", "."])
        self.assertEqual(calls[1].kwargs["cwd"], root)
        self.assertEqual(calls[2].args[0], ["/home/kali/.local/bin/cachaza", "-version"])
        self.assertEqual(calls[3].args[0], ["/home/kali/.local/bin/cachaza", "doctor"])

    def test_banner_contains_project_name_and_attribution(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            Console(color=False).banner("0.8.0")
        banner = output.getvalue()
        self.assertIn(CACHAZA_WORDMARK, banner)
        self.assertLess(banner.index(".-========-."), banner.index("_________"))
        cocktail = banner.splitlines()[:8]
        rim_center = cocktail[0].index(".") + 5.5
        stem_center = cocktail[4].index("||") + 0.5
        base_center = cocktail[6].index("||") + 0.5
        foot_center = (cocktail[7].index("/") + cocktail[7].index("\\")) / 2
        self.assertEqual(rim_center, stem_center)
        self.assertEqual(stem_center, base_center)
        self.assertEqual(base_center, foot_center)
        self.assertIn("github.com/W4RRR/cachaza by W4RRR", banner)
        self.assertIn("v0.8.0", banner)


if __name__ == "__main__":
    unittest.main()
