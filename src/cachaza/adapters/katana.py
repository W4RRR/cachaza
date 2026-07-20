"""Katana JSONL crawler adapter."""

from __future__ import annotations

from ..models import Finding, TargetSpec
from .common import json_records, url_in_scope


def build_argv(
    binary: str, input_file: str, *, rate_limit: int, timeout: int
) -> list[str]:
    return [
        binary,
        "-list",
        input_file,
        "-depth",
        "3",
        "-js-crawl",
        "-known-files",
        "robotstxt,sitemapxml",
        "-field-scope",
        "fqdn",
        "-crawl-duration",
        "2m",
        "-concurrency",
        "2",
        "-parallelism",
        "2",
        "-rate-limit",
        str(min(rate_limit, 2)),
        "-timeout",
        str(timeout),
        "-jsonl",
        "-silent",
    ]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for row in json_records(text):
        request = row.get("request") if isinstance(row.get("request"), dict) else {}
        value = str(request.get("endpoint") or request.get("url") or row.get("url") or "").strip()
        if not value.startswith(("http://", "https://")):
            continue
        findings.append(
            Finding(
                "crawl",
                "katana",
                "url",
                value,
                url_in_scope(value, target),
                {
                    "method": request.get("method"),
                    "status_code": row.get("response", {}).get("status_code")
                    if isinstance(row.get("response"), dict)
                    else None,
                    "crawler": True,
                },
            )
        )
    return findings
