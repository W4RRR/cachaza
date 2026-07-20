"""403jump output adapter."""

from __future__ import annotations

import re

from ..models import Finding, TargetSpec
from .common import clean_text, extract_urls, url_in_scope


SUCCESS = re.compile(r"\b(?:200|204|301|302)\b|success|bypass", re.IGNORECASE)


def build_argv(binary: str, input_file: str) -> list[str]:
    return [binary, "-f", input_file]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        cleaned = clean_text(line, 4_000)
        if not cleaned or not SUCCESS.search(cleaned):
            continue
        urls = extract_urls(cleaned)
        value = urls[0] if urls else cleaned
        findings.append(
            Finding(
                "bypass",
                "403jump",
                "security_finding",
                f"possible-403-bypass@{value}",
                url_in_scope(value, target) if urls else False,
                {
                    "target": value,
                    "category": "access-control",
                    "severity": "medium",
                    "confidence": "candidate",
                    "raw_summary": cleaned,
                    "requires_manual_validation": True,
                },
            )
        )
    return findings

