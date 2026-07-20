from __future__ import annotations

import contextlib
import inspect
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import cachaza.origin as origin_module
from cachaza.adapters.origin import source_family
from cachaza.cli import main
from cachaza.console import Console
from cachaza.external import CommandRunner
from cachaza.models import (
    Finding,
    OriginCandidate,
    OriginConfig,
    OriginEvidence,
    OriginNetwork,
    TargetSpec,
)
from cachaza.origin import (
    FORBIDDEN_REQUEST_HEADERS,
    HttpProbeResult,
    OriginBudget,
    OriginEngine,
    TLSProbeResult,
    detect_cdn,
    direct_http_request,
    probe_jarm,
    probe_tls,
    score_candidate,
    should_auto_validate,
)
from cachaza.workspace import RunWorkspace
from cachaza.reports import build_report_data


def candidate(ip: str = "93.184.216.34", score: int = 60) -> OriginCandidate:
    item = OriginCandidate(ip=ip, classification="origin_candidate")
    item.network = OriginNetwork(is_public=True)
    item.add_evidence(
        OriginEvidence(
            "historical_apex_dns",
            "Historical apex A record",
            score,
            "virustotal",
            "virustotal",
            True,
        )
    )
    item.initial_score = score_candidate(item)
    item.final_score = item.initial_score
    return item


class OneShotServer:
    def __init__(self, response: bytes):
        self.response = response
        self.request = b""
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        connection, _ = self.listener.accept()
        with connection:
            while b"\r\n\r\n" not in self.request:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                self.request += chunk
            connection.sendall(self.response)
        self.listener.close()

    def __enter__(self) -> "OneShotServer":
        self.thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self.thread.join(timeout=2)


class OriginSelectionTests(unittest.TestCase):
    def test_strong_correlated_candidate_is_selected_without_manual_ip(self) -> None:
        item = candidate()
        allowed, reasons = should_auto_validate(item, OriginConfig())
        self.assertTrue(allowed)
        self.assertEqual(reasons, [])

    def test_private_candidate_is_never_selected(self) -> None:
        item = candidate("10.0.0.8")
        item.network = OriginNetwork(is_public=False, is_private=True)
        allowed, reasons = should_auto_validate(item, OriginConfig())
        self.assertFalse(allowed)
        self.assertIn("non_public_address", reasons)

    def test_cdn_candidate_is_never_selected(self) -> None:
        item = candidate()
        item.network = OriginNetwork(provider="Cloudflare", is_known_cdn=True)
        allowed, reasons = should_auto_validate(item, OriginConfig())
        self.assertFalse(allowed)
        self.assertIn("known_cdn_range", reasons)

    def test_low_score_is_not_contactable(self) -> None:
        item = candidate(score=25)
        item.classification = "related_infrastructure"
        allowed, reasons = should_auto_validate(item, OriginConfig())
        self.assertFalse(allowed)
        self.assertIn("score_below_threshold", reasons)

    def test_isolated_favicon_or_mx_evidence_does_not_reach_threshold(self) -> None:
        favicon = OriginCandidate("93.184.216.34")
        favicon.add_evidence(OriginEvidence("same_favicon_sha256", "favicon", 12, "index", "favicon"))
        mx = OriginCandidate("93.184.216.35")
        mx.add_evidence(OriginEvidence("mail_relationship", "MX", 4, "dns", "mail_dns"))
        mx.add_evidence(OriginEvidence("mail_only_penalty", "mail only", -8, "dns", "mail_dns"))
        self.assertLess(score_candidate(favicon), 50)
        self.assertLess(score_candidate(mx), 50)

    def test_budget_enforces_total_and_per_ip_limits_and_resumes(self) -> None:
        config = OriginConfig(maximum_total_requests=3, maximum_requests_per_ip=2, rate_limit_per_second=20)
        with patch("cachaza.origin.time.sleep"):
            budget = OriginBudget(config)
            budget.consume(action="tcp_connect", candidate_ip="93.184.216.34")
            budget.consume(action="https_head", candidate_ip="93.184.216.34")
        with self.assertRaisesRegex(RuntimeError, "budget exhausted"):
            budget.consume(action="https_get", candidate_ip="93.184.216.34")
        resumed = OriginBudget(config, previous=budget.to_dict())
        self.assertEqual(resumed.consumed, 2)
        self.assertEqual(resumed.per_ip["93.184.216.34"], 2)

    def test_uncover_wrappers_do_not_duplicate_upstream_source_independence(self) -> None:
        self.assertEqual(source_family("shodan"), "shodan")
        self.assertEqual(source_family("uncover", {"engine": "shodan"}), "shodan")

    def test_cdn_detection_requires_multiple_signals_unless_cname_or_official_range(self) -> None:
        isolated = {"endpoints": [{"headers": {"server": "cloudflare"}, "cookie_names": [], "addresses": []}]}
        self.assertEqual(detect_cdn(isolated, [])["provider"], "Unknown")
        correlated = {"endpoints": [{"headers": {"server": "cloudflare", "cf-ray": "id"}, "cookie_names": [], "addresses": []}]}
        self.assertEqual(detect_cdn(correlated, [])["provider"], "Cloudflare")
        cname = {"endpoints": [{"cname": "site.map.fastly.net", "headers": {}, "cookie_names": [], "addresses": []}]}
        self.assertEqual(detect_cdn(cname, [])["provider"], "Fastly")


class OriginTransportTests(unittest.TestCase):
    def test_direct_http_uses_target_host_and_only_safe_headers(self) -> None:
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=value; HttpOnly\r\nContent-Length: 2\r\n\r\nok"
        with OneShotServer(response) as server:
            result = direct_http_request(
                "127.0.0.1", "example.com", server.port, scheme="http", method="GET",
                path="/", connect_timeout=2, total_timeout=2, body_limit=100,
            )
        request = server.request.decode("ascii")
        self.assertIn(f"Host: example.com:{server.port}\r\n", request)
        self.assertTrue(request.startswith("GET / HTTP/1.1\r\n"))
        for header in FORBIDDEN_REQUEST_HEADERS:
            self.assertNotIn(header + ":", request.casefold())
        self.assertEqual(result.cookie_names, ["session"])
        self.assertNotIn("value", json.dumps(result.to_dict()))

    def test_head_405_and_get_fallback_are_supported_without_post(self) -> None:
        response = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
        with OneShotServer(response) as server:
            result = direct_http_request(
                "127.0.0.1", "example.com", server.port, scheme="http", method="HEAD",
                path="/", connect_timeout=2, total_timeout=2, body_limit=0,
            )
        self.assertEqual(result.status, 405)
        self.assertTrue(server.request.startswith(b"HEAD / HTTP/1.1"))
        with self.assertRaisesRegex(ValueError, "only HEAD and GET"):
            direct_http_request("127.0.0.1", "example.com", 80, scheme="http", method="POST", path="/", connect_timeout=1, total_timeout=1, body_limit=1)
        with self.assertRaisesRegex(ValueError, "invalid target hostname"):
            direct_http_request("127.0.0.1", "example.com\r\nX-Forwarded-Host: attacker", 80, scheme="http", method="GET", path="/", connect_timeout=1, total_timeout=1, body_limit=1)

    def test_body_limit_and_redirect_location_are_preserved(self) -> None:
        response = b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 10\r\n\r\n0123456789"
        with OneShotServer(response) as server:
            result = direct_http_request(
                "127.0.0.1", "example.com", server.port, scheme="http", method="GET",
                path="/", connect_timeout=2, total_timeout=2, body_limit=5,
            )
        self.assertEqual(result.headers["location"], "/next")
        self.assertEqual(result.body, b"01234")
        self.assertTrue(result.body_truncated)

    def test_tls_probe_passes_exact_hostname_as_sni(self) -> None:
        captured: list[str] = []

        class Raw:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        class Wrapped(Raw):
            def version(self):
                return "TLSv1.3"

            def cipher(self):
                return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

            def getpeercert(self, binary_form=False):
                return b"certificate" if binary_form else {}

        class Context:
            def wrap_socket(self, raw, *, server_hostname):
                captured.append(server_hostname)
                return Wrapped()

        with patch("cachaza.origin.socket.create_connection", return_value=Raw()), patch("cachaza.origin._tls_context", return_value=Context()):
            result = probe_tls("93.184.216.34", 443, "example.com", timeout=1)
        self.assertEqual(captured, ["example.com"])
        self.assertEqual(result.server_hostname, "example.com")
        self.assertEqual(result.handshake, "certificate_trusted")

    def test_jarm_is_single_host_bounded_and_uses_exact_sni(self) -> None:
        fingerprint = "2" * 62
        runner = MagicMock()
        runner.run.return_value = MagicMock(
            skipped=False,
            returncode=0,
            stdout=json.dumps({"jarm_hash": fingerprint}) + "\n",
        )
        value = probe_jarm(
            "93.184.216.34",
            443,
            "example.com",
            runner,
            timeout=12,
            executable="tlsx",
        )
        self.assertEqual(value, fingerprint)
        argv = runner.run.call_args.args[0]
        self.assertEqual(argv[argv.index("-u") + 1], "93.184.216.34:443")
        self.assertEqual(argv[argv.index("-sni") + 1], "example.com")
        self.assertEqual(argv[argv.index("-c") + 1], "1")
        self.assertEqual(argv[argv.index("-retry") + 1], "0")


class OriginEngineTests(unittest.TestCase):
    def _engine(self, root: Path, config: OriginConfig) -> OriginEngine:
        target = TargetSpec(domains=["example.com"])
        workspace = RunWorkspace(root)
        console = Console(silent=True)
        return OriginEngine(
            target,
            workspace,
            config,
            console,
            CommandRunner(console, dry_run=False),
            {},
            timeout=1,
            retries=0,
            add_finding=lambda stage, source, kind, value, in_scope, metadata: workspace.add(
                __import__("cachaza.models", fromlist=["Finding"]).Finding(stage, source, kind, value, in_scope, metadata)
            ),
        )

    def test_candidate_limit_and_stop_score_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = OriginConfig(
                mode="balanced", authorized=True, maximum_candidates=2,
                maximum_total_requests=10, maximum_requests_per_ip=4,
                rate_limit_per_second=20, stop_score=85,
            )
            engine = self._engine(Path(temp), config)
            candidates = [candidate(f"93.184.216.{number}", 60) for number in range(1, 5)]

            def validate(item, root, baseline, budget):
                item.final_score = 90
                item.classification = item.validation_status = "high_confidence_origin"
                return {"ip": item.ip, "validated_at": "2026-01-01T00:00:00+00:00", "classification": item.classification, "final_score": 90, "evidence": []}

            baseline = {"domain": "example.com", "endpoints": [], "cdn_waf": {}}
            with (
                patch("cachaza.origin.capture_public_baseline", return_value=baseline),
                patch("cachaza.origin.dns_inventory", return_value={"records": {}}),
                patch("cachaza.origin.load_cloudflare_networks", return_value=[]),
                patch("cachaza.origin.detect_cdn", return_value={"provider": "Cloudflare", "confidence": 95, "signals": []}),
                patch("cachaza.origin.collect_workspace_observations", return_value=[]),
                patch("cachaza.origin.collect_resolved_names", return_value=[]),
                patch.object(engine, "_build_candidates", return_value=candidates),
                patch.object(engine, "_validate_candidate", side_effect=validate) as validator,
            ):
                engine.run()
            selected = (Path(temp) / "rest" / "origin" / "selected-candidates.jsonl").read_text().splitlines()
            self.assertEqual(len(selected), 2)
            self.assertEqual(validator.call_count, 1)

    def test_mtls_or_acl_result_is_protected_not_aggressively_escalated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = OriginConfig(ports=[443], maximum_total_requests=5, maximum_requests_per_ip=5, rate_limit_per_second=20)
            engine = self._engine(Path(temp), config)
            item = candidate(score=70)
            tls = TLSProbeResult(item.ip, "example.com", 443, handshake="client_certificate_required", server_hostname="example.com")
            response = HttpProbeResult("https", item.ip, "example.com", 443, "/", "GET", status=403)
            dummy_socket = MagicMock()
            dummy_socket.__enter__.return_value = dummy_socket
            with (
                patch("cachaza.origin.time.sleep"),
                patch("cachaza.origin.socket.create_connection", return_value=dummy_socket),
                patch("cachaza.origin.probe_tls", return_value=tls),
                patch("cachaza.origin.direct_http_request", return_value=response),
            ):
                result = engine._validate_candidate(item, "example.com", {"domain": "example.com", "endpoints": []}, OriginBudget(config))
            self.assertEqual(result["classification"], "protected_origin")
            self.assertEqual(result["direct_validation"], "not_directly_verifiable")
            self.assertLessEqual(result["validation_requests"], 5)

    def test_deep_ports_are_only_escalated_when_standard_web_ports_do_not_respond(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = OriginConfig(
                mode="deep",
                deep_ports=[80, 443, 8000, 8080, 8443, 8888],
                maximum_total_requests=10,
                maximum_requests_per_ip=10,
                rate_limit_per_second=20,
            )
            engine = self._engine(Path(temp), config)
            item = candidate(score=70)
            opened: list[int] = []
            dummy_socket = MagicMock()
            dummy_socket.__enter__.return_value = dummy_socket

            def connect(address, timeout):
                opened.append(address[1])
                if address[1] == 443:
                    return dummy_socket
                raise ConnectionRefusedError(10061, "refused")

            response = HttpProbeResult("https", item.ip, "example.com", 443, "/", "GET", status=200, body=b"ok")
            with (
                patch("cachaza.origin.time.sleep"),
                patch("cachaza.origin.socket.create_connection", side_effect=connect),
                patch("cachaza.origin.probe_tls", return_value=TLSProbeResult(item.ip, "example.com", 443, handshake="certificate_trusted")),
                patch("cachaza.origin.direct_http_request", return_value=response),
            ):
                engine._validate_candidate(item, "example.com", {"domain": "example.com", "endpoints": []}, OriginBudget(config))
            self.assertEqual(opened, [80, 443])

    def test_tunnel_without_public_candidate_is_reported_without_inventing_an_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = OriginConfig(mode="passive")
            engine = self._engine(Path(temp), config)
            ranking = engine._ranking(
                "example.com",
                [],
                [],
                OriginBudget(config),
                {"provider": "Cloudflare", "confidence": 95, "signals": []},
            )
            self.assertIsNone(ranking["highest_confidence_candidate"])
            self.assertIn("tunnel", ranking["message"].casefold())

    def test_score_result_classifications_are_explicit(self) -> None:
        self.assertEqual(origin_module._classification_for_score(80), "high_confidence_origin")
        self.assertEqual(origin_module._classification_for_score(65), "probable_origin")
        self.assertEqual(origin_module._classification_for_score(50), "possible_origin")
        self.assertEqual(origin_module._classification_for_score(49), "related_infrastructure")

    def test_strong_unreachable_candidate_remains_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = OriginConfig(ports=[443], maximum_total_requests=2, maximum_requests_per_ip=2, rate_limit_per_second=20)
            engine = self._engine(Path(temp), config)
            item = candidate(score=70)
            with patch("cachaza.origin.time.sleep"), patch("cachaza.origin.socket.create_connection", side_effect=socket.timeout("blocked")):
                result = engine._validate_candidate(item, "example.com", {"domain": "example.com", "endpoints": []}, OriginBudget(config))
            self.assertEqual(result["classification"], "inconclusive")
            self.assertEqual(result["direct_validation"], "not_directly_verifiable")

    def test_different_application_is_not_matching(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = OriginConfig(ports=[80], maximum_total_requests=4, maximum_requests_per_ip=4, rate_limit_per_second=20)
            engine = self._engine(Path(temp), config)
            item = candidate(score=55)
            response = HttpProbeResult("http", item.ip, "example.com", 80, "/", "GET", status=200, body=b"parked unrelated tenant " * 40)
            dummy_socket = MagicMock()
            dummy_socket.__enter__.return_value = dummy_socket
            baseline_body = b"production storefront inventory account " * 40
            baseline = {
                "domain": "example.com",
                "endpoints": [{
                    "hostname": "example.com",
                    "url": "http://example.com/",
                    "normalized_body_sha256": "not-the-same",
                    "_normalized_body": origin_module.normalize_html(baseline_body),
                    "title": "Expected",
                    "headers": {},
                    "cookie_names": [],
                    "resources": {},
                }],
            }
            with (
                patch("cachaza.origin.time.sleep"),
                patch("cachaza.origin.socket.create_connection", return_value=dummy_socket),
                patch("cachaza.origin.direct_http_request", return_value=response),
            ):
                result = engine._validate_candidate(item, "example.com", baseline, OriginBudget(config))
            self.assertEqual(result["classification"], "not_matching")

    def test_origin_source_contains_no_scanners_shell_or_evasion_requests(self) -> None:
        source = inspect.getsource(OriginEngine).casefold()
        self.assertNotIn("nuclei", source)
        self.assertNotIn("arjun", source)
        self.assertNotIn("shell=true", source)
        request_source = inspect.getsource(direct_http_request).casefold()
        for header in FORBIDDEN_REQUEST_HEADERS:
            self.assertNotIn(f'"{header}":', request_source)

    def test_origin_correlation_is_present_in_relationship_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = RunWorkspace(Path(temp))
            workspace.add(Finding("input", "scope", "domain", "example.com", True, {"root": True}))
            workspace.add(Finding("origin", "origin-correlation", "origin_candidate", "93.184.216.34", False, {"root": "example.com", "ip": "93.184.216.34", "score": 92, "relationship": "Origin correlation"}))
            report = build_report_data(workspace, TargetSpec(domains=["example.com"]), version="test", failures=[])
        edges = {(item["source"], item["target"], item["relationship"]) for item in report["graph"]["edges"]}
        self.assertIn(("domain:example.com", "origin_candidate:93.184.216.34", "Origin correlation"), edges)
        self.assertIn(("ip:93.184.216.34", "origin_candidate:93.184.216.34", "registered or observed as"), edges)


class OriginCliTests(unittest.TestCase):
    def test_balanced_active_origin_requires_explicit_authorization(self) -> None:
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = main(["run", "-d", "example.com", "-active", "-origin-auto", "-dry-run", "-silent"])
        self.assertEqual(code, 2)
        self.assertIn("Automatic origin validation requires explicit authorization", errors.getvalue())

    def test_passive_origin_needs_no_active_gate_or_manual_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            code = main(["run", "-d", "example.com", "-origin-auto", "-origin-mode", "passive", "-dry-run", "-stages", "origin", "-o", str(root), "-silent"])
            self.assertEqual(code, 0)
            ranking = json.loads((root / "rest" / "origin" / "final-ranking.json").read_text())
            self.assertEqual(ranking["mode"], "passive")
            self.assertEqual(ranking["direct_requests_performed"], 0)
            self.assertTrue((root / "rest" / "origin" / "all-candidates.jsonl").is_file())

    def test_deep_defaults_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            code = main(["run", "-d", "example.com", "-active", "-authorized", "-origin-auto", "-origin-mode", "deep", "-dry-run", "-stages", "origin", "-o", str(root), "-silent"])
            self.assertEqual(code, 0)
            budget = json.loads((root / "rest" / "origin" / "request-budget.json").read_text())
            self.assertEqual(budget["maximum_candidates"], 20)
            self.assertEqual(budget["maximum_total_requests"], 100)
            self.assertEqual(budget["maximum_requests_per_ip"], 10)
            self.assertEqual(budget["maximum_concurrency"], 2)

    def test_help_has_automatic_origin_options_and_no_manual_approval_flags(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit):
            main(["-h"])
        text = output.getvalue()
        self.assertIn("-origin-auto", text)
        self.assertIn("-origin-mode", text)
        self.assertNotIn("approve-origin-ip", text)
        self.assertNotIn("approve-origin-candidates-file", text)


if __name__ == "__main__":
    unittest.main()
