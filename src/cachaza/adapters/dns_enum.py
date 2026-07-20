"""Normalize dnsenum and Fierce discovery output."""

from __future__ import annotations

import ipaddress
import re

from ..models import Finding, TargetSpec
from ..safety import domain_in_scope, extract_domains, ip_in_scope
from .common import clean_text


IP_TOKEN = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
TRANSFER_SUCCESS = re.compile(
    r"zone transfer (?:was )?(?:successful|succeeded|allowed)|"
    r"axfr (?:query )?(?:succeeded|successful|allowed)|"
    r"(?:successful|complete) zone transfer|zone transfer completed",
    re.IGNORECASE,
)
TRANSFER_FAILURE = re.compile(r"failed|failure|refused|denied|not allowed|no zone transfer", re.IGNORECASE)


def parse_output(text: str, tool: str, root: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    cleaned = clean_text(text, 2_000_000)
    for domain in extract_domains(cleaned, target.domains):
        findings.append(
            Finding(
                "dns_enum",
                tool,
                "domain",
                domain,
                domain_in_scope(domain, target.domains, target.exclude_domains),
                {"root": root, "dns_enumeration": True},
            )
        )
    for token in IP_TOKEN.findall(cleaned):
        try:
            address = str(ipaddress.ip_address(token))
        except ValueError:
            continue
        scoped = ip_in_scope(address, target.cidrs, target.exclude_cidrs)
        findings.append(
            Finding(
                "dns_enum",
                tool,
                "ip",
                address,
                scoped,
                {"root": root, "candidate_only": not scoped},
            )
        )
    transfer_lines = [
        line
        for line in text.splitlines()
        if TRANSFER_SUCCESS.search(line) and not TRANSFER_FAILURE.search(line)
    ]
    if transfer_lines:
        evidence = clean_text(transfer_lines[0], 500) or "Zone transfer accepted"
        findings.append(
            Finding(
                "dns_enum",
                tool,
                "dns_zone_transfer",
                root,
                True,
                {
                    "root": root,
                    "allowed": True,
                    "risk": "high",
                    "evidence": evidence,
                    "requires_manual_validation": True,
                },
            )
        )
    return findings
