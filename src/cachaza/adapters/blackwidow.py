"""Normalize BlackWidow crawler artifacts and Inject-X candidate output."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from ..models import Finding, TargetSpec
from ..safety import domain_in_scope, extract_domains
from .common import HTTP_URL, url_in_scope
from .harvester import EMAIL, PHONE


INJECT = re.compile(r"(?:P[23]|SQLi|XSS|traversal|open redirect)", re.I)
API_HINT = re.compile(r"/(?:api|v\d+|graphql|swagger|openapi)(?:/|\b)", re.I)


def parse_output(text: str, root: str, target: TargetSpec, *, artifact: str = "stdout") -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, in_scope: bool, **metadata: object) -> None:
        value = value.strip().rstrip(".,;)")
        key = (kind, value.casefold())
        if not value or key in seen:
            return
        seen.add(key)
        findings.append(
            Finding(
                "blackwidow",
                "blackwidow",
                kind,
                value,
                in_scope,
                {"root": root, "artifact": artifact, **metadata},
            )
        )

    for email in EMAIL.findall(text):
        add("email", email.lower(), domain_in_scope(email.rsplit("@", 1)[-1], target.domains, target.exclude_domains))
    artifact_lower = artifact.casefold()
    for match in HTTP_URL.finditer(text):
        url = match.group(0).rstrip("\"'.,;)")
        kind = "api_endpoint" if API_HINT.search(urlsplit(url).path) else "url"
        add(
            kind,
            url,
            url_in_scope(url, target),
            discovered_by_crawl=True,
            form="form" in artifact_lower,
            dynamic="dynamic" in artifact_lower or "?" in url,
        )
    for line in text.splitlines():
        clean = line.strip()
        if INJECT.search(clean) and len(clean) <= 2_000:
            add(
                "security_finding",
                clean,
                True,
                confidence="candidate",
                requires_manual_validation=True,
                active_fuzzing=True,
            )
        if "phone" in artifact.casefold() or "phone" in clean.casefold():
            for match in PHONE.finditer(clean):
                value = match.group(0).strip()
                if 8 <= sum(character.isdigit() for character in value) <= 16:
                    add("phone", value, True)
    for domain in extract_domains(text, target.domains):
        if domain != root:
            add("domain", domain, domain_in_scope(domain, target.domains, target.exclude_domains))
    return findings


def parse_tree(path: Path, root: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    if not path.is_dir():
        return findings
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file() or candidate.stat().st_size > 20_000_000:
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(parse_output(text, root, target, artifact=str(candidate.relative_to(path))))
    unique: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.kind, finding.value.casefold()), finding)
    return sorted(unique.values(), key=lambda item: (item.kind, item.value.casefold()))
