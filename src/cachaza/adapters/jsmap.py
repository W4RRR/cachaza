"""JSMap Inspector JSON adapter."""

from __future__ import annotations

import re

from ..models import Finding, TargetSpec
from .common import extract_urls, json_records, url_in_scope, walk_strings


SECRET_HINT = re.compile(r"secret|token|api[-_ ]?key|password|credential", re.IGNORECASE)


def build_argv(binary: str, input_file: str, output_file: str) -> list[str]:
    return [binary, "-l", input_file, "-o", output_file]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for row in json_records(text):
        flattened = " ".join(walk_strings(row))
        secret = bool(SECRET_HINT.search(flattened))
        for value in extract_urls(flattened):
            findings.append(
                Finding(
                    "js",
                    "jsmap-inspector",
                    "url",
                    value,
                    url_in_scope(value, target),
                    {
                        "javascript_analysis": True,
                        "secret_candidate": secret,
                        "confidence": "candidate" if secret else "observed",
                        "requires_manual_validation": secret,
                    },
                )
            )
    return findings

