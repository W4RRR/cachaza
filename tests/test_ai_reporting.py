from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from cachaza.ai_reporting import AIReportConfig, build_report_digest, generate_ai_assistance
from cachaza.http import HttpError


class AIReportingTests(unittest.TestCase):
    def _data(self) -> dict:
        return {
            "tool": "cachaza",
            "version": "test",
            "generated_at": "2026-08-27T00:00:00Z",
            "scope": {"domains": ["example.com"]},
            "counts": {"domain": 2, "origin_candidate": 1},
            "issues": [],
            "network_intelligence": {
                "asns": [],
                "organizations": [],
                "prefixes": [],
                "resolved_ips": [],
            },
            "key_findings": {"subdomains": ["api.example.com"]},
            "findings": [
                {
                    "kind": "security_finding",
                    "value": "DO NOT SEND raw-secret-material",
                    "metadata": {"token": "raw-secret-material"},
                }
            ],
            "origin_discovery": {
                "origin_ip": "203.0.113.45",
                "origin_probability_percent": 88,
                "confidence_band": "high",
                "classification": "high_confidence_origin",
                "direct_requests_performed": 8,
                "cdn_waf_detected": {"provider": "Cloudflare"},
            },
            "origin_trace": {
                "status": "direct_path_validated",
                "source_families": ["virustotal", "direct_validation"],
                "validation_signals": ["Same certificate"],
                "steps": [],
            },
            "origin_remediation": {
                "actions": [
                    {
                        "priority": "P0",
                        "phase": "Contain",
                        "title": "Restrict ingress",
                        "action": "Allow only the edge path.",
                        "verification": "Direct external requests fail.",
                    }
                ]
            },
            "presentation": {
                "mode": "professional",
                "subject": "example.com",
            },
        }

    def test_digest_excludes_raw_findings(self) -> None:
        digest = build_report_digest(self._data())
        serialized = json.dumps(digest)
        self.assertNotIn("raw-secret-material", serialized)
        self.assertNotIn("findings", digest)
        self.assertEqual(digest["report_subject"], "example.com")
        self.assertTrue(digest["professional_white_label"])
        self.assertEqual(digest["origin_remediation"][0]["priority"], "P0")

    def test_openrouter_generates_validated_structured_narrative(self) -> None:
        narrative = {
            "headline": "Direct origin exposure requires remediation",
            "executive_summary": "A concise summary.",
            "origin_assessment": "The direct path was validated.",
            "business_impact": "Edge controls may be circumvented.",
            "recommended_actions": ["Restrict ingress", "Rotate exposed services", "Retest"],
            "limitations": "Heuristic attribution is not ownership proof.",
        }
        response = {
            "model": "openai/test-model",
            "choices": [{"message": {"content": json.dumps(narrative)}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 80, "total_tokens": 180},
        }
        with patch("cachaza.ai_reporting.request_json", return_value=response) as request:
            result = generate_ai_assistance(
                self._data(), AIReportConfig(api_key="secret", model="openai/test-model")
            )
        self.assertEqual(result["status"], "generated")
        self.assertEqual(result["structured_output_mode"], "json_schema")
        self.assertEqual(result["narrative"]["recommended_actions"][0], "Restrict ingress")
        kwargs = request.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer secret")
        serialized_payload = json.dumps(kwargs["json_body"])
        self.assertNotIn("raw-secret-material", serialized_payload)
        self.assertTrue(
            kwargs["json_body"]["provider"]["require_parameters"]
        )
        self.assertEqual(kwargs["json_body"]["plugins"], [{"id": "response-healing"}])
        self.assertIn("origin_remediation", serialized_payload)
        self.assertIn("do not name the underlying collection product", serialized_payload)

    def test_invalid_openrouter_response_is_rejected(self) -> None:
        with patch(
            "cachaza.ai_reporting.request_json",
            return_value={"choices": [{"message": {"content": "not json"}}]},
        ):
            with self.assertRaises(HttpError):
                generate_ai_assistance(self._data(), AIReportConfig(api_key="secret"))


if __name__ == "__main__":
    unittest.main()
