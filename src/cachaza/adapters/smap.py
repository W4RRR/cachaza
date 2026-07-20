"""Smap/Shodan passive service adapter."""

from __future__ import annotations

import re

from ..models import Finding, TargetSpec
from .common import clean_text, host_in_scope


SERVICE = re.compile(r"(?P<host>[A-Za-z0-9_.:-]+):(?P<port>[0-9]{1,5})")


def build_argv(binary: str) -> list[str]:
    # Smap does not consume target lines from stdin unless Nmap-compatible
    # input-list mode is selected explicitly. A dash makes that list stdin.
    return [binary, "-iL", "-"]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = SERVICE.search(clean_text(line))
        if not match:
            continue
        port = int(match.group("port"))
        if not 1 <= port <= 65535:
            continue
        value = f"{match.group('host')}:{port}"
        if value in seen:
            continue
        seen.add(value)
        findings.append(
            Finding(
                "ports",
                "smap/shodan",
                "service",
                value,
                host_in_scope(match.group("host"), target),
                {"port": port, "passive": True},
            )
        )
    return findings
