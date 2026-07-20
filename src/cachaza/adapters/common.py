"""Defensive parsing helpers shared by external adapters."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterable
from urllib.parse import urlsplit

from ..models import TargetSpec
from ..safety import domain_in_scope, ip_in_scope


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HTTP_URL = re.compile(r"https?://[^\s\]\[<>'\"]+", re.IGNORECASE)


def clean_text(value: Any, limit: int = 8_000) -> str:
    if value is None:
        return ""
    text = ANSI.sub("", str(value)).replace("\x00", "").replace("\r", " ")
    return " ".join(text.split())[:limit]


def json_records(text: str) -> list[dict[str, Any]]:
    if not text.strip():
        return []
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def extract_urls(text: str) -> list[str]:
    return sorted({match.group(0).rstrip(".,;)") for match in HTTP_URL.finditer(text)})


def host_in_scope(host: str, target: TargetSpec) -> bool:
    value = host.strip().strip("[]").rstrip(".")
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return domain_in_scope(value, target.domains, target.exclude_domains)
    return ip_in_scope(value, target.cidrs, target.exclude_cidrs)


def url_in_scope(url: str, target: TargetSpec) -> bool:
    host = urlsplit(url).hostname or ""
    return host_in_scope(host, target)


def string_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [clean_text(item, 1_000) for item in value if clean_text(item, 1_000)]
    if value is None:
        return []
    text = clean_text(value, 1_000)
    return [text] if text else []


def walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_strings(child)

