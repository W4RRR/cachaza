"""Cariddi endpoint/secret candidate adapter."""

from __future__ import annotations

import re

from ..models import Finding, TargetSpec
from .common import clean_text, extract_urls, url_in_scope


SECRET_HINT = re.compile(r"secret|token|api[-_ ]?key|password|credential", re.IGNORECASE)


def build_argv(binary: str) -> list[str]:
    return [binary, "-e", "-s", "-plain"]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        cleaned = clean_text(line, 4_000)
        for value in extract_urls(cleaned):
            secret = bool(SECRET_HINT.search(cleaned))
            findings.append(
                Finding(
                    "crawl",
                    "cariddi",
                    "url",
                    value,
                    url_in_scope(value, target),
                    {
                        "endpoint": True,
                        "secret_candidate": secret,
                        "confidence": "candidate" if secret else "observed",
                        "raw_summary": cleaned if secret else None,
                    },
                )
            )
    return findings

