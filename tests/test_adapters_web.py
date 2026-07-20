from __future__ import annotations

import json
import unittest

from cachaza.adapters import cariddi, csp_stalker, favicorn, jsmap, katana
from cachaza.models import TargetSpec


class WebAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = TargetSpec(domains=["example.com"])

    def test_katana_and_cariddi_keep_url_scope(self) -> None:
        katana_row = {
            "request": {"endpoint": "https://api.example.com/api/v1/users", "method": "GET"},
            "response": {"status_code": 200},
        }
        katana_findings = katana.parse_output(json.dumps(katana_row), self.target)
        self.assertTrue(katana_findings[0].in_scope)
        self.assertTrue(katana_findings[0].metadata["endpoint"])
        self.assertTrue(katana_findings[0].metadata["http_live"])
        self.assertEqual(katana_findings[0].metadata["method"], "GET")
        self.assertEqual(katana_findings[0].metadata["status_code"], 200)
        cariddi_findings = cariddi.parse_output(
            "endpoint https://outside.test/x secret token\n", self.target
        )
        self.assertFalse(cariddi_findings[0].in_scope)
        self.assertNotIn("secret_candidate", cariddi_findings[0].metadata)
        argv = cariddi.build_argv("cariddi", timeout=20)
        self.assertIn("-e", argv)
        self.assertIn("-plain", argv)
        self.assertNotIn("-s", argv)
        self.assertEqual(argv[argv.index("-c") + 1], "1")

    def test_jsmap_policy_and_favicon_are_normalized(self) -> None:
        js_findings = jsmap.parse_output(
            json.dumps({"endpoint": "https://api.example.com/v1", "hint": "api_key"}),
            self.target,
        )
        self.assertTrue(js_findings[0].metadata["endpoint"])
        self.assertNotIn("secret_candidate", js_findings[0].metadata)
        policy = csp_stalker.parse_output(
            "CSP unsafe-inline at https://example.com", self.target, "https://example.com"
        )
        self.assertEqual(policy[0].kind, "policy_finding")
        fingerprints = favicorn.parse_output(
            "https://example.com 0123456789abcdef0123456789abcdef", self.target
        )
        self.assertEqual(fingerprints[0].kind, "fingerprint")
        self.assertTrue(fingerprints[0].in_scope)


if __name__ == "__main__":
    unittest.main()
