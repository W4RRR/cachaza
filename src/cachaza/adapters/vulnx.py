"""Vulnx CVE-correlation adapter."""

from __future__ import annotations

import re

from ..models import Finding
from .common import clean_text


CVE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,}\b", re.IGNORECASE)


def build_argv(binary: str, technology: str) -> list[str]:
    return [binary, "search", technology, "--limit", "20", "--json", "--silent"]


def parse_output(text: str, technology: str, *, in_scope: bool) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        cleaned = clean_text(line, 2_000)
        for match in CVE.finditer(cleaned):
            value = match.group(0).upper()
            findings.append(
                Finding(
                    "cve",
                    "vulnx",
                    "cve_candidate",
                    f"{technology}:{value}",
                    in_scope,
                    {
                        "technology": technology,
                        "cve": value,
                        "confidence": "candidate",
                        "raw_summary": cleaned,
                        "requires_manual_validation": True,
                    },
                )
            )
    return findings
