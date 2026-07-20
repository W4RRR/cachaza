"""Cariddi endpoint-only discovery adapter."""

from __future__ import annotations

from ..models import Finding, TargetSpec
from ..web import is_api_endpoint
from .common import clean_text, extract_urls, url_in_scope


def build_argv(binary: str, *, timeout: int) -> list[str]:
    return [
        binary,
        "-e",
        "-plain",
        "-c",
        "1",
        "-d",
        "1",
        "-t",
        str(timeout),
        "-md",
        "3",
    ]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        cleaned = clean_text(line, 4_000)
        for value in extract_urls(cleaned):
            findings.append(
                Finding(
                    "crawl",
                    "cariddi",
                    "url",
                    value,
                    url_in_scope(value, target),
                    {
                        "endpoint": is_api_endpoint(value),
                        "endpoint_discovery": True,
                        "crawler": True,
                        "confidence": "observed",
                    },
                )
            )
    return findings
