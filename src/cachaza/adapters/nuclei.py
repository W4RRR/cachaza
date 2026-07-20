"""Nuclei JSONL command and result adapter."""

from __future__ import annotations

from typing import Any

from ..models import Finding, TargetSpec
from .common import clean_text, json_records, string_values, url_in_scope


SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}


def build_argv(
    binary: str,
    input_file: str,
    *,
    tags: str,
    severities: str,
    rate_limit: int,
    concurrency: int,
    timeout: int,
    verbose: bool,
) -> list[str]:
    argv = [
        binary,
        "-l",
        input_file,
        "-tags",
        tags,
        "-severity",
        severities,
        "-jsonl",
        "-rl",
        str(min(rate_limit, 2)),
        "-bulk-size",
        str(min(concurrency, 2)),
        "-c",
        str(min(concurrency, 2)),
        "-hbs",
        "2",
        "-headc",
        "2",
        "-jsc",
        "2",
        "-pc",
        "2",
        "-prc",
        "2",
        "-tlc",
        "2",
        "-timeout",
        str(timeout),
        "-retries",
        "0",
        "-max-host-error",
        "5",
        "-no-stdin",
        "-omit-raw",
        "-no-color",
    ]
    if verbose:
        argv.extend(["-stats", "-stats-interval", "30"])
    else:
        argv.append("-silent")
    return argv


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for row in json_records(text):
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        template_id = clean_text(row.get("template-id") or row.get("template_id"), 300)
        matched = clean_text(
            row.get("matched-at") or row.get("matched_at") or row.get("host") or row.get("url"),
            3_000,
        )
        if not matched:
            continue
        severity = clean_text(info.get("severity") or row.get("severity") or "unknown", 20).lower()
        if severity not in SEVERITIES:
            severity = "unknown"
        name = clean_text(info.get("name") or template_id or "Nuclei finding", 500)
        tags = string_values(info.get("tags"))
        findings.append(
            Finding(
                "nuclei",
                "nuclei",
                "security_finding",
                f"{template_id or name}@{matched}",
                url_in_scope(matched, target),
                {
                    "target": matched,
                    "template_id": template_id,
                    "name": name,
                    "severity": severity,
                    "tags": tags,
                    "matcher_name": row.get("matcher-name") or row.get("matcher_name"),
                    "type": row.get("type"),
                    "extracted_results": row.get("extracted-results") or row.get("extracted_results"),
                    "confidence": "confirmed_observation",
                    "requires_manual_validation": True,
                },
            )
        )
    return findings
