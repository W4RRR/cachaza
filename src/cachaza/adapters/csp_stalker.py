"""CSP Stalker text output adapter."""

from __future__ import annotations

import re

from ..models import Finding, TargetSpec
from .common import clean_text, extract_urls, url_in_scope


POLICY_HINT = re.compile(r"content-security-policy|\bcsp\b|unsafe-inline|unsafe-eval|wildcard", re.I)


def build_argv(binary: str, url: str) -> list[str]:
    # Upstream CSP-Stalker writes to ./results and has no -o/--output option.
    return [binary, "-u", url]


def parse_output(text: str, target: TargetSpec, fallback_url: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        cleaned = clean_text(line, 4_000)
        if not POLICY_HINT.search(cleaned):
            continue
        urls = extract_urls(cleaned)
        url = urls[0] if urls else fallback_url
        findings.append(
            Finding(
                "policies",
                "csp-stalker",
                "policy_finding",
                f"csp@{url}:{cleaned[:160]}",
                url_in_scope(url, target),
                {
                    "target": url,
                    "policy": "content-security-policy",
                    "summary": cleaned,
                    "confidence": "candidate",
                    "requires_manual_validation": True,
                },
            )
        )
    return findings
