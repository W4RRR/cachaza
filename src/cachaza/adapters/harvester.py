"""Normalize theHarvester JSON into contact and attack-surface findings."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..models import Finding, TargetSpec
from ..safety import domain_in_scope, extract_domains, ip_in_scope
from .common import HTTP_URL, clean_text, url_in_scope


EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])", re.IGNORECASE)
PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?!\w)")
PHONE_KEYS = ("phone", "telephone", "mobile", "tel")
ADDRESS_KEYS = ("address", "street", "location", "postal")
SECRET_KEYS = ("api_key", "apikey", "access_token", "secret", "credential")
API_HINT = re.compile(r"/(?:api|v\d+|graphql|swagger|openapi)(?:/|\b)", re.IGNORECASE)


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        yield path, str(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, path + (str(key).lower(),))
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child, path)


def _looks_like_phone(value: str, path_text: str) -> bool:
    digits = sum(character.isdigit() for character in value)
    return 7 <= digits <= 18 and (any(key in path_text for key in PHONE_KEYS) or value.strip().startswith("+"))


def _add(
    findings: list[Finding],
    seen: set[tuple[str, str]],
    kind: str,
    value: str,
    root: str,
    path: tuple[str, ...],
    in_scope: bool,
    **metadata: Any,
) -> None:
    clean = clean_text(value, 3_000)
    key = (kind, clean.casefold())
    if not clean or key in seen:
        return
    seen.add(key)
    findings.append(
        Finding(
            "harvester",
            "theHarvester",
            kind,
            clean,
            in_scope,
            {"root": root, "source_field": ".".join(path), **metadata},
        )
    )


def parse_json(text: str, root: str, target: TargetSpec) -> list[Finding]:
    """Extract deduplicated contacts, hosts, endpoints, and redacted key candidates."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for path, raw in _walk(payload):
        value = clean_text(raw, 8_000)
        path_text = ".".join(path)
        if not value:
            continue

        for email in EMAIL.findall(value):
            email_domain = email.rsplit("@", 1)[-1]
            _add(
                findings,
                seen,
                "email",
                email.lower(),
                root,
                path,
                domain_in_scope(email_domain, target.domains, target.exclude_domains),
            )

        if any(key in path_text for key in SECRET_KEYS) and len(value) >= 8:
            fingerprint = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
            _add(
                findings,
                seen,
                "api_key_candidate",
                f"redacted:{fingerprint}",
                root,
                path,
                True,
                redacted=True,
                confidence="candidate",
                requires_manual_validation=True,
            )

        for match in HTTP_URL.finditer(value):
            url = match.group(0).rstrip(".,;)")
            kind = "api_endpoint" if API_HINT.search(urlsplit(url).path) or "api" in path_text else "url"
            _add(findings, seen, kind, url, root, path, url_in_scope(url, target))

        if _looks_like_phone(value, path_text):
            match = PHONE.search(value)
            if match:
                _add(findings, seen, "phone", match.group(0), root, path, False, contextual=True)

        if any(key in path_text for key in ADDRESS_KEYS):
            try:
                ipaddress.ip_address(value.strip("[]"))
                is_ip_address = True
            except ValueError:
                is_ip_address = False
            if (
                5 <= len(value) <= 500
                and not is_ip_address
                and not value.startswith(("http://", "https://"))
            ):
                _add(findings, seen, "address", value, root, path, False, contextual=True)

        if any(key in path_text for key in ("host", "domain", "subdomain")):
            for domain in extract_domains(value, target.domains):
                _add(
                    findings,
                    seen,
                    "domain",
                    domain,
                    root,
                    path,
                    domain_in_scope(domain, target.domains, target.exclude_domains),
                )

        if any(key in path_text for key in ("ip", "address")):
            for token in re.findall(r"[0-9A-Fa-f:.]{3,}", value):
                try:
                    address = str(ipaddress.ip_address(token.strip(".,;[]()")))
                except ValueError:
                    continue
                _add(
                    findings,
                    seen,
                    "ip",
                    address,
                    root,
                    path,
                    ip_in_scope(address, target.cidrs, target.exclude_cidrs),
                    candidate_only=not ip_in_scope(address, target.cidrs, target.exclude_cidrs),
                )
    return findings
