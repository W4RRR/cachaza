"""dnsx JSONL adapter."""

from __future__ import annotations

import ipaddress
from typing import Any

from ..models import Finding, TargetSpec
from ..safety import domain_in_scope, ip_in_scope
from .common import json_records, string_values


def build_argv(binary: str, input_file: str, *, rate_limit: int) -> list[str]:
    return [
        binary,
        "-l",
        input_file,
        "-json",
        "-resp",
        "-silent",
        "-rl",
        str(min(rate_limit, 2)),
        "-t",
        "2",
    ]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for row in json_records(text):
        host = str(row.get("host") or row.get("input") or "").lower().rstrip(".")
        host_scope = domain_in_scope(host, target.domains, target.exclude_domains)
        if host:
            findings.append(
                Finding("dns", "dnsx", "domain", host, host_scope, {"resolved": True})
            )
        for key, record_type in (("a", "A"), ("aaaa", "AAAA")):
            for raw in string_values(row.get(key)):
                try:
                    value = str(ipaddress.ip_address(raw))
                except ValueError:
                    continue
                scoped = ip_in_scope(value, target.cidrs, target.exclude_cidrs)
                findings.append(
                    Finding(
                        "dns",
                        "dnsx",
                        "ip",
                        value,
                        scoped,
                        {
                            "host": host,
                            "record_type": record_type,
                            "candidate_only": not scoped,
                        },
                    )
                )
        for raw in string_values(row.get("cname")):
            cname = raw.lower().rstrip(".")
            scoped = domain_in_scope(cname, target.domains, target.exclude_domains)
            findings.append(
                Finding(
                    "dns",
                    "dnsx",
                    "domain",
                    cname,
                    scoped,
                    {"host": host, "record_type": "CNAME", "requires_scope_approval": not scoped},
                )
            )
    return findings
