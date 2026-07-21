from __future__ import annotations

import contextlib
import unittest
import urllib.error
from unittest.mock import patch

from cachaza.http import GLOBAL_REQUEST_LIMITER, HttpError, request_bytes
from cachaza.sources import (
    censys_query,
    censys_search,
    certspotter_domains,
    extract_censys_indicators,
    intelx_auth_info,
    intelx_capability_paths,
    intelx_phonebook,
    normalize_urlscan,
    normalize_intelx_host,
    parse_arin_rdap,
    parse_bgp_he_dns_html,
    ripe_as_overview,
    ripe_network_info,
)


class SourceTests(unittest.TestCase):
    def test_intelx_phonebook_uses_key_header_and_normalizes_selectors(self) -> None:
        responses = [
            {"id": "search-id"},
            {"selectors": [{"selectorvalue": "Admin@Example.com"}, {"selectorvalue": "www.example.com"}]},
        ]
        with patch("cachaza.sources.request_json", side_effect=responses) as request:
            result = intelx_phonebook(
                "example.com",
                api_key="secret",
                host="https://free.intelx.io/",
                timeout=20,
                retries=1,
            )
        self.assertEqual(result["values"], ["Admin@Example.com", "www.example.com"])
        self.assertEqual(result["target"], 0)
        self.assertEqual(request.call_args_list[0].args[0], "https://free.intelx.io/phonebook/search")
        self.assertEqual(request.call_args_list[0].kwargs["headers"]["x-key"], "secret")
        self.assertEqual(request.call_args_list[0].kwargs["json_body"]["target"], 0)
        self.assertEqual(request.call_args_list[1].kwargs["params"]["id"], "search-id")

    def test_intelx_auth_info_uses_account_specific_host(self) -> None:
        capabilities = {"paths": {"/phonebook/search": {"credit": 25}}}
        with patch("cachaza.sources.request_json", return_value=capabilities) as request:
            result = intelx_auth_info(
                api_key="secret",
                host="free.intelx.io",
                timeout=20,
                retries=1,
            )
        self.assertEqual(result, capabilities)
        self.assertEqual(request.call_args.args[0], "https://free.intelx.io/authenticate/info")
        self.assertEqual(request.call_args.kwargs["headers"]["x-key"], "secret")

    def test_intelx_host_normalization_preserves_assigned_tier(self) -> None:
        self.assertEqual(normalize_intelx_host("free.intelx.io/"), "https://free.intelx.io")
        self.assertEqual(
            normalize_intelx_host("https://2.intelx.io/"), "https://2.intelx.io"
        )

    def test_intelx_capability_paths_accepts_dict_and_list_shapes(self) -> None:
        self.assertEqual(
            intelx_capability_paths({"paths": {"/phonebook/search": {"credit": 25}}}),
            {"/phonebook/search"},
        )
        self.assertEqual(
            intelx_capability_paths(
                {"paths": [{"path": "phonebook/search"}, "/authenticate/info"]}
            ),
            {"/phonebook/search", "/authenticate/info"},
        )

    def test_censys_rejects_legacy_id_secret_pair_before_request(self) -> None:
        with (
            patch("cachaza.sources.request_json") as request,
            self.assertRaises(HttpError) as caught,
        ):
            censys_search(
                "example.com",
                api_key="legacy-id:legacy-secret",
                timeout=20,
                retries=1,
            )
        self.assertEqual(caught.exception.status_code, 401)
        self.assertIn("Personal Access Token", str(caught.exception))
        request.assert_not_called()

    def test_censys_query_and_scope_extraction(self) -> None:
        self.assertIn("web.hostname=~", censys_query("example.com"))
        payload = {
            "result": {
                "hits": [
                    {"web": {"hostname": "api.example.com"}, "ip": "192.0.2.10"},
                    {"cert": {"names": ["example.com", "example.com.evil.test"]}},
                ]
            }
        }
        result = extract_censys_indicators(payload, "example.com")
        self.assertEqual(result["domains"], ["api.example.com", "example.com"])
        self.assertEqual(result["ips"], ["192.0.2.10"])

    def test_urlscan_search_normalization_does_not_expand_domain_scope(self) -> None:
        payload = {
            "results": [
                {
                    "page": {
                        "domain": "api.example.com",
                        "url": "https://api.example.com/",
                        "ip": "192.0.2.10",
                    }
                },
                {"page": {"domain": "example.com.evil.test", "url": "https://example.com.evil.test/"}},
            ]
        }
        result = normalize_urlscan(payload, "example.com")
        self.assertEqual(result["domains"], ["api.example.com", "example.com"])
        self.assertIn("https://api.example.com/", result["urls"])
        self.assertNotIn("example.com.evil.test", result["domains"])

    def test_certspotter_paginates_and_filters_scope(self) -> None:
        pages = [
            [
                {
                    "id": "10",
                    "dns_names": ["api.example.com", "*.dev.example.com", "outside.test"],
                }
            ],
            [],
        ]
        with patch("cachaza.sources.request_json", side_effect=pages) as mocked:
            values = certspotter_domains("example.com", timeout=1, retries=0)
        self.assertEqual(values, ["api.example.com", "dev.example.com"])
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(mocked.call_args_list[1].kwargs["params"]["after"], "10")

    def test_http_errors_do_not_leak_query_secrets(self) -> None:
        with (
            patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")),
            patch.object(GLOBAL_REQUEST_LIMITER, "slot", return_value=contextlib.nullcontext()),
        ):
            with self.assertRaises(HttpError) as caught:
                request_bytes(
                    "https://api.example.test/search",
                    params={"key": "super-secret", "query": "example.com"},
                    retries=0,
                )
        self.assertNotIn("super-secret", str(caught.exception))
        self.assertNotIn("example.com", str(caught.exception))

    def test_http_401_is_not_retried_and_is_structured(self) -> None:
        error = urllib.error.HTTPError(
            "https://api.example.test/search", 401, "Unauthorized", {}, None
        )
        with (
            patch("urllib.request.urlopen", side_effect=error) as opened,
            patch.object(GLOBAL_REQUEST_LIMITER, "slot", return_value=contextlib.nullcontext()),
            self.assertRaises(HttpError) as caught,
        ):
            request_bytes("https://api.example.test/search", retries=4)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(caught.exception.status_code, 401)
        self.assertFalse(caught.exception.transient)

    def test_parses_bgp_he_dns_rows(self) -> None:
        html = """
        <table><tr><td><a href="/ip/203.0.113.10">203.0.113.10</a></td>
        <td><a href="/AS64500">AS64500</a></td>
        <td><a href="/net/203.0.113.0/24">203.0.113.0/24</a></td>
        <td>Example Network, Inc.</td></tr></table>
        """
        self.assertEqual(
            parse_bgp_he_dns_html(html),
            [
                {
                    "asn": "AS64500",
                    "holder": "Example Network, Inc.",
                    "ips": ["203.0.113.10"],
                    "prefixes": ["203.0.113.0/24"],
                }
            ],
        )

    def test_parses_ripestat_network_and_asn_overview(self) -> None:
        with patch(
            "cachaza.sources.request_json",
            side_effect=[
                {"data": {"prefix": "203.0.113.0/24", "asns": [64500]}},
                {
                    "data": {
                        "resource": "64500",
                        "holder": "EXAMPLE-NET",
                        "announced": True,
                        "block": {"name": "TEST"},
                    }
                },
            ],
        ):
            network = ripe_network_info("203.0.113.10", timeout=1, retries=0)
            overview = ripe_as_overview("AS64500", timeout=1, retries=0)
        self.assertEqual(network["asns"], ["AS64500"])
        self.assertEqual(network["prefix"], "203.0.113.0/24")
        self.assertEqual(overview["holder"], "EXAMPLE-NET")
        self.assertTrue(overview["announced"])

    def test_parses_arin_rdap_registrant_without_personal_contacts(self) -> None:
        payload = {
            "handle": "NET-203-0-113-0-1",
            "name": "EXAMPLE-NET",
            "type": "DIRECT ALLOCATION",
            "startAddress": "203.0.113.0",
            "endAddress": "203.0.113.255",
            "arin_originas0_originautnums": [64500],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["fn", {}, "text", "Example Registrant"],
                            ["email", {}, "text", "ignored@example.test"],
                        ],
                    ],
                }
            ],
        }
        parsed = parse_arin_rdap(payload, "203.0.113.10")
        self.assertEqual(parsed["origin_asns"], ["AS64500"])
        self.assertEqual(parsed["organizations"], ["Example Registrant"])
        self.assertNotIn("ignored@example.test", str(parsed))


if __name__ == "__main__":
    unittest.main()
