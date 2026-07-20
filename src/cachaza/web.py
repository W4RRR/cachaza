"""Canonical HTTP origins and endpoint inventory helpers."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit


API_PATH = re.compile(
    r"/(?:api|v\d+|graphql|swagger|openapi|rest)(?:/|$)",
    re.IGNORECASE,
)


def _canonical_host(hostname: str) -> str | None:
    host = hostname.casefold().rstrip(".")
    if not host:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return f"[{address}]" if address.version == 6 else str(address)


def _http_parts(url: str) -> tuple[str, str, int | None, Any] | None:
    try:
        parsed = urlsplit(str(url).strip())
        port = parsed.port
    except (TypeError, ValueError):
        return None
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    host = _canonical_host(parsed.hostname)
    if not host:
        return None
    if port == (80 if scheme == "http" else 443):
        port = None
    return scheme, host, port, parsed


def normalize_http_origin(url: str) -> str | None:
    """Return ``scheme://host[:port]`` for a credential-free HTTP(S) URL."""
    parts = _http_parts(url)
    if not parts:
        return None
    scheme, host, port, _ = parts
    authority = f"{host}:{port}" if port is not None else host
    return f"{scheme}://{authority}"


def normalize_endpoint_url(url: str) -> str | None:
    """Normalize one endpoint without retaining query-string values."""
    parts = _http_parts(url)
    if not parts:
        return None
    scheme, host, port, parsed = parts
    authority = f"{host}:{port}" if port is not None else host
    path = parsed.path or "/"
    parameter_names = sorted(
        {
            name
            for name, _ in parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=False,
            )
            if name
        },
        key=str.casefold,
    )
    query = "&".join(quote(name, safe="-._~[]") for name in parameter_names)
    return urlunsplit((scheme, authority, path, query, ""))


def is_api_endpoint(url: str) -> bool:
    normalized = normalize_endpoint_url(url)
    return bool(normalized and API_PATH.search(urlsplit(normalized).path))


def deduplicate_http_origins(urls: Iterable[str]) -> list[str]:
    return sorted(
        {origin for value in urls if (origin := normalize_http_origin(value))},
        key=str.casefold,
    )


def select_live_http_origins(
    findings: Iterable[Any],
    fallback_domains: Iterable[str] = (),
) -> list[str]:
    """Select confirmed live origins, falling back only to root-domain HTTPS."""
    confirmed: set[str] = set()
    for finding in findings:
        if getattr(finding, "kind", None) != "url" or not getattr(
            finding, "in_scope", False
        ):
            continue
        metadata = getattr(finding, "metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        source = str(getattr(finding, "source", "")).casefold()
        status = metadata.get("status_code")
        status_text = str(status) if status is not None else ""
        confirmed_by_httpx = source == "httpx" and status is not None
        confirmed_by_crawler = bool(metadata.get("crawler")) and status_text.startswith(
            ("2", "3")
        )
        confirmed_by_response = metadata.get("http_live") is True
        if not (confirmed_by_httpx or confirmed_by_crawler or confirmed_by_response):
            continue
        origin = normalize_http_origin(str(getattr(finding, "value", "")))
        if origin:
            confirmed.add(origin)
    if confirmed:
        return sorted(confirmed, key=str.casefold)
    fallbacks = {
        origin
        for domain in fallback_domains
        if (origin := normalize_http_origin(f"https://{domain}"))
    }
    return sorted(fallbacks, key=str.casefold)
