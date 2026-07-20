"""Favicorn fingerprint output adapter."""

from __future__ import annotations

import re

from ..models import Finding, TargetSpec
from .common import clean_text, extract_urls, url_in_scope


HASH = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|-?[0-9]{4,})\b")


def build_argv(binary: str, input_file: str) -> list[str]:
    return [binary, "-f", input_file]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        cleaned = clean_text(line, 2_000)
        urls, hashes = extract_urls(cleaned), HASH.findall(cleaned)
        if not hashes:
            continue
        url = urls[0] if urls else ""
        for value in hashes:
            findings.append(
                Finding(
                    "policies",
                    "favicorn",
                    "fingerprint",
                    value.lower(),
                    url_in_scope(url, target) if url else False,
                    {"url": url or None, "fingerprint_type": "favicon"},
                )
            )
    return findings

