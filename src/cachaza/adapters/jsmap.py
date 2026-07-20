"""JSMap Inspector endpoint-inventory adapter."""

from __future__ import annotations

from urllib.parse import urljoin

from ..models import Finding, TargetSpec
from ..web import is_api_endpoint
from .common import extract_urls, json_records, url_in_scope, walk_strings


def build_argv(binary: str, input_file: str, output_file: str) -> list[str]:
    return [binary, "-l", input_file, "-o", output_file]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for row in json_records(text):
        flattened = " ".join(walk_strings(row))
        candidates = set(extract_urls(flattened))
        base_url = str(row.get("javascript_url") or "")
        references = row.get("references") if isinstance(row.get("references"), list) else []
        for reference in references:
            candidate = urljoin(base_url, str(reference).strip())
            if candidate.startswith(("http://", "https://")):
                candidates.add(candidate)
        for value in sorted(candidates):
            findings.append(
                Finding(
                    "js",
                    "jsmap-inspector",
                    "url",
                    value,
                    url_in_scope(value, target),
                    {
                        "javascript_analysis": True,
                        "endpoint": is_api_endpoint(value),
                        "related_javascript": value.lower().split("?", 1)[0].endswith(".js"),
                        "confidence": "observed",
                    },
                )
            )
    return findings
