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
            "executive_summary": ["Summary one.", "Summary two.", "Summary three."],
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
        self.assertEqual(result["narrative"]["executive_summary"][0], "Summary one.")
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
        self.assertIn("including headings and recommended_actions", serialized_payload)

    def test_legacy_string_summary_is_normalized_into_bullets(self) -> None:
        narrative = {
            "headline": "Assessment",
            "executive_summary": "First point. Second point. Third point.",
            "origin_assessment": "Assessment.",
            "business_impact": "Impact.",
            "recommended_actions": ["One", "Two", "Three"],
            "limitations": "Limitations.",
        }
        response = {"choices": [{"message": {"content": json.dumps(narrative)}}]}
        with patch("cachaza.ai_reporting.request_json", return_value=response):
            result = generate_ai_assistance(self._data(), AIReportConfig(api_key="secret"))
        self.assertEqual(
            result["narrative"]["executive_summary"],
            ["First point.", "Second point.", "Third point."],
        )

    def test_invalid_openrouter_response_is_rejected(self) -> None:
        with patch(
            "cachaza.ai_reporting.request_json",
            return_value={"choices": [{"message": {"content": "not json"}}]},
        ) as request:
            with self.assertRaises(HttpError) as caught:
                generate_ai_assistance(self._data(), AIReportConfig(api_key="secret"))
        self.assertEqual(request.call_count, 2)
        self.assertIn("after one semantic repair attempt", str(caught.exception))
        self.assertIn('"content_type": "str"', str(caught.exception))
        self.assertNotIn("not json", str(caught.exception))

    def test_markdown_wrapped_spanish_aliases_are_normalized(self) -> None:
        narrative = {
            "Título": "Exposición del origen",
            "Resumen ejecutivo": ["Uno.", "Dos.", "Tres."],
            "Evaluación del origen": "La ruta fue validada.",
            "Impacto empresarial": "Aumenta el riesgo perimetral.",
            "Acciones recomendadas": ["Contener", "Autenticar", "Revalidar"],
            "Limitaciones": "La atribución no prueba propiedad.",
        }
        response = {
            "model": "test/model",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": "```json\n" + json.dumps(narrative, ensure_ascii=False) + "\n```"
                    },
                }
            ],
        }
        with patch("cachaza.ai_reporting.request_json", return_value=response) as request:
            result = generate_ai_assistance(
                self._data(), AIReportConfig(api_key="secret", language="es")
            )
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result["narrative"]["headline"], "Exposición del origen")
        self.assertEqual(result["narrative"]["recommended_actions"][0], "Contener")
        self.assertEqual(result["response_diagnostic"]["finish_reason"], "stop")

    def test_segmented_message_content_is_joined_before_decoding(self) -> None:
        narrative = {
            "headline": "Assessment",
            "executive_summary": ["One.", "Two.", "Three."],
            "origin_assessment": "Assessment.",
            "business_impact": "Impact.",
            "recommended_actions": ["Contain", "Authenticate", "Retest"],
            "limitations": "Limitations.",
        }
        encoded = json.dumps(narrative)
        response = {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "text", "text": encoded[:40]},
                            {"type": "text", "text": encoded[40:]},
                        ]
                    }
                }
            ]
        }
        with patch("cachaza.ai_reporting.request_json", return_value=response):
            result = generate_ai_assistance(self._data(), AIReportConfig(api_key="secret"))
        self.assertEqual(result["narrative"]["headline"], "Assessment")
        self.assertEqual(result["response_diagnostic"]["content_type"], "list")

    def test_mixed_text_before_json_is_safely_extracted(self) -> None:
        narrative = {
            "headline": "Assessment",
            "executive_summary": ["One.", "Two.", "Three."],
            "origin_assessment": "Assessment.",
            "business_impact": "Impact.",
            "recommended_actions": ["Contain", "Authenticate", "Retest"],
            "limitations": "Limitations.",
        }
        response = {
            "choices": [
                {
                    "message": {
                        "content": "Structured result follows:\n" + json.dumps(narrative)
                    }
                }
            ]
        }
        with patch("cachaza.ai_reporting.request_json", return_value=response) as request:
            result = generate_ai_assistance(self._data(), AIReportConfig(api_key="secret"))
        self.assertEqual(request.call_count, 1)
        self.assertEqual(result["narrative"]["headline"], "Assessment")

    def test_invalid_first_narrative_gets_one_semantic_repair_attempt(self) -> None:
        repaired = {
            "headline": "Assessment",
            "executive_summary": ["One.", "Two.", "Three."],
            "origin_assessment": "Assessment.",
            "business_impact": "Impact.",
            "recommended_actions": ["Contain", "Authenticate", "Retest"],
            "limitations": "Limitations.",
        }
        responses = [
            {
                "choices": [{"message": {"content": "{}"}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110},
            },
            {
                "choices": [{"message": {"content": json.dumps(repaired)}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 30, "total_tokens": 150},
            },
        ]
        with patch("cachaza.ai_reporting.request_json", side_effect=responses) as request:
            result = generate_ai_assistance(self._data(), AIReportConfig(api_key="secret"))
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["structured_output_mode"], "json_object_semantic_repair")
        self.assertEqual(
            result["usage"],
            {"prompt_tokens": 220, "completion_tokens": 40, "total_tokens": 260},
        )
        repair_payload = request.call_args_list[1].kwargs["json_body"]
        self.assertEqual(repair_payload["temperature"], 0)
        self.assertEqual(repair_payload["response_format"], {"type": "json_object"})
        self.assertNotIn("provider", repair_payload)

    def test_openrouter_404_after_fallback_has_actionable_model_diagnostic(self) -> None:
        with patch(
            "cachaza.ai_reporting.request_json",
            side_effect=[
                HttpError("strict route unavailable", status_code=404),
                HttpError("fallback route unavailable", status_code=404),
            ],
        ):
            with self.assertRaises(HttpError) as caught:
                generate_ai_assistance(
                    self._data(),
                    AIReportConfig(api_key="secret", model="~openai/gpt-latest"),
                )
        self.assertEqual(caught.exception.status_code, 404)
        self.assertIn("~openai/gpt-latest", str(caught.exception))
        self.assertIn("no leading backslash", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
