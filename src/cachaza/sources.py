"""Passive intelligence sources and cloud range classification."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from .http import HttpError, request_bytes, request_json
from .safety import domain_in_scope, extract_domains, normalize_asn, normalize_cidr
from .signatures import Signature


RIPE_ANNOUNCED_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"
RIPE_NETWORK_INFO = "https://stat.ripe.net/data/network-info/data.json"
RIPE_AS_OVERVIEW = "https://stat.ripe.net/data/as-overview/data.json"
BGP_HE_DNS = "https://bgp.he.net/dns/{domain}"
ARIN_RDAP_IP = "https://rdap.arin.net/registry/ip/{ip}"
SHODAN_COUNT = "https://api.shodan.io/shodan/host/count"
SHODAN_SEARCH = "https://api.shodan.io/shodan/host/search"
CRT_SH = "https://crt.sh/"
CERTSPOTTER_ISSUANCES = "https://api.certspotter.com/v1/issuances"
IPRANGES_BASE = "https://raw.githubusercontent.com/lord-alfred/ipranges/main"
CENSYS_SEARCH = "https://api.platform.censys.io/v3/global/search/query"
URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"
INTELX_DEFAULT_HOST = "https://2.intelx.io"

CLOUD_PROVIDERS = {
    "amazon": "amazon",
    "cloudflare": "cloudflare",
    "digitalocean": "digitalocean",
    "github": "github",
    "google": "google",
    "linode": "linode",
    "microsoft": "microsoft",
    "oracle": "oracle",
    "vultr": "vultr",
}


def normalize_intelx_host(host: str) -> str:
    """Normalize the account-specific IntelX API URL without guessing its tier."""
    base = host.strip().rstrip("/") or INTELX_DEFAULT_HOST
    if "://" not in base:
        base = "https://" + base
    return base


def intelx_auth_info(
    *,
    api_key: str,
    host: str = INTELX_DEFAULT_HOST,
    timeout: int,
    retries: int,
) -> dict[str, Any]:
    """Validate an IntelX key/host pair and return its advertised capabilities."""
    if not api_key:
        raise HttpError("INTELX_API_KEY is not configured")
    base = normalize_intelx_host(host)
    payload = request_json(
        f"{base}/authenticate/info",
        headers={"x-key": api_key, "Accept": "application/json"},
        timeout=timeout,
        retries=retries,
    )
    if not isinstance(payload, dict):
        raise HttpError("IntelX authentication endpoint returned an invalid response")
    return payload


def intelx_capability_paths(payload: dict[str, Any]) -> set[str]:
    """Return normalized API paths from current and legacy capability shapes."""
    raw_paths = payload.get("paths", {})
    candidates: list[Any] = []
    if isinstance(raw_paths, dict):
        candidates.extend(raw_paths)
        candidates.extend(raw_paths.values())
    elif isinstance(raw_paths, list):
        candidates.extend(raw_paths)
    elif isinstance(raw_paths, str):
        candidates.append(raw_paths)

    paths: set[str] = set()
    for candidate in candidates:
        if isinstance(candidate, dict):
            candidate = candidate.get("path") or candidate.get("name") or candidate.get("url")
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        value = candidate.strip()
        if "://" in value:
            value = "/" + value.split("://", 1)[1].split("/", 1)[-1]
        if not value.startswith("/"):
            value = "/" + value
        paths.add(value.rstrip("/"))
    return paths


def intelx_phonebook(
    domain: str,
    *,
    api_key: str,
    host: str = INTELX_DEFAULT_HOST,
    timeout: int,
    retries: int,
    target: int = 0,
) -> dict[str, Any]:
    """Run an IntelX Phonebook lookup and return raw selectors plus normalized values."""
    if not api_key:
        raise HttpError("INTELX_API_KEY is not configured")
    if target not in {0, 1, 2, 3}:
        raise ValueError("IntelX Phonebook target must be 0, 1, 2, or 3")
    base = normalize_intelx_host(host)
    headers = {"x-key": api_key, "Accept": "application/json"}
    search = request_json(
        f"{base}/phonebook/search",
        headers=headers,
        method="POST",
        json_body={
            "term": domain,
            "maxresults": 1000,
            "media": 0,
            "target": target,
            "terminate": [],
        },
        timeout=timeout,
        retries=retries,
    )
    search_id = search.get("id") if isinstance(search, dict) else None
    if not search_id:
        raise HttpError("IntelX did not return a Phonebook search id")
    selectors: list[dict[str, Any]] = []
    result: Any = {}
    for poll in range(6):
        result = request_json(
            f"{base}/phonebook/search/result",
            headers=headers,
            params={"id": str(search_id), "limit": 1000, "offset": -1},
            timeout=timeout,
            retries=retries,
        )
        if not isinstance(result, dict):
            break
        current = result.get("selectors", [])
        if isinstance(current, list):
            selectors.extend(row for row in current if isinstance(row, dict))
        status = result.get("status")
        if status in {1, 2}:
            break
        if status == 3:
            if poll < 5:
                time.sleep(1)
            continue
        if status != 0:
            break
    result_payload = dict(result) if isinstance(result, dict) else {"raw": result}
    result_payload["selectors"] = selectors
    values = sorted(
        {
            str(row.get("selectorvalue") or row.get("value") or "").strip()
            for row in selectors
            if isinstance(row, dict) and str(row.get("selectorvalue") or row.get("value") or "").strip()
        },
        key=str.casefold,
    )
    return {"search": search, "result": result_payload, "values": values, "target": target}


def resolve_domain_ips(domain: str) -> list[str]:
    """Resolve A/AAAA records with the local resolver and return normalized addresses."""
    values: set[str] = set()
    for result in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
        sockaddr = result[4]
        if not sockaddr:
            continue
        try:
            values.add(str(ipaddress.ip_address(sockaddr[0])))
        except ValueError:
            continue
    return sorted(values, key=lambda value: (ipaddress.ip_address(value).version, value))


def ripe_network_info(ip: str, *, timeout: int, retries: int) -> dict[str, Any]:
    address = str(ipaddress.ip_address(ip))
    payload = request_json(
        RIPE_NETWORK_INFO,
        params={"resource": address},
        timeout=timeout,
        retries=retries,
    )
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    prefix = data.get("prefix") if isinstance(data, dict) else None
    normalized_prefix: str | None = None
    if isinstance(prefix, str):
        try:
            normalized_prefix = normalize_cidr(prefix)
        except ValueError:
            pass
    asns: list[str] = []
    raw_asns = data.get("asns", []) if isinstance(data, dict) else []
    for raw_asn in raw_asns if isinstance(raw_asns, list) else []:
        try:
            asns.append(normalize_asn(str(raw_asn)))
        except ValueError:
            continue
    return {"ip": address, "prefix": normalized_prefix, "asns": sorted(set(asns))}


def ripe_as_overview(asn: str, *, timeout: int, retries: int) -> dict[str, Any]:
    normalized = normalize_asn(asn)
    payload = request_json(
        RIPE_AS_OVERVIEW,
        params={"resource": normalized},
        timeout=timeout,
        retries=retries,
    )
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    return {
        "asn": normalized,
        "holder": str(data.get("holder") or "").strip(),
        "announced": bool(data.get("announced")),
        "registry": str(data.get("block", {}).get("name") or "").strip()
        if isinstance(data.get("block"), dict)
        else "",
        "resource": str(data.get("resource") or normalized).strip(),
    }


class _BgpHeDnsParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[dict[str, Any]]] = []
        self._row: list[dict[str, Any]] | None = None
        self._cell: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "tr":
            self._row = []
        elif tag == "td" and self._row is not None:
            self._cell = {"text": [], "hrefs": []}
        elif tag == "a" and self._cell is not None:
            href = dict(attrs).get("href")
            if href:
                self._cell["hrefs"].append(href)

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell["text"].append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "td" and self._row is not None and self._cell is not None:
            self._cell["text"] = " ".join("".join(self._cell["text"]).split())
            self._row.append(self._cell)
            self._cell = None
        elif tag == "tr" and self._row is not None:
            if self._row:
                self.rows.append(self._row)
            self._row = None
            self._cell = None


def parse_bgp_he_dns_html(payload: str) -> list[dict[str, Any]]:
    """Parse the public BGP Toolkit DNS table without relying on private APIs."""
    parser = _BgpHeDnsParser()
    parser.feed(payload)
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...], tuple[str, ...]]] = set()
    for cells in parser.rows:
        hrefs = [href for cell in cells for href in cell["hrefs"]]
        raw_asns = [href[3:].split("?", 1)[0] for href in hrefs if href.upper().startswith("/AS")]
        asns: list[str] = []
        for raw_asn in raw_asns:
            try:
                asns.append(normalize_asn(raw_asn))
            except ValueError:
                continue
        ips: list[str] = []
        for href in hrefs:
            if not href.startswith("/ip/"):
                continue
            try:
                ips.append(str(ipaddress.ip_address(unquote(href[4:]).split("?", 1)[0])))
            except ValueError:
                continue
        prefixes: list[str] = []
        for href in hrefs:
            if not href.startswith("/net/"):
                continue
            try:
                prefixes.append(normalize_cidr(unquote(href[5:]).split("?", 1)[0]))
            except ValueError:
                continue
        if not asns:
            continue
        holder = str(cells[-1]["text"]).strip() if len(cells) >= 4 else ""
        for asn in sorted(set(asns)):
            key = (asn, holder, tuple(sorted(set(ips))), tuple(sorted(set(prefixes))))
            if key in seen:
                continue
            seen.add(key)
            records.append(
                {
                    "asn": asn,
                    "holder": holder,
                    "ips": sorted(set(ips)),
                    "prefixes": sorted(set(prefixes)),
                }
            )
    return records


def bgp_he_domain(domain: str, *, timeout: int, retries: int) -> list[dict[str, Any]]:
    payload = request_bytes(
        BGP_HE_DNS.format(domain=quote(domain, safe=".")),
        timeout=timeout,
        retries=retries,
    ).decode("utf-8", "replace")
    return parse_bgp_he_dns_html(payload)


def _rdap_entity_names(entities: Any) -> list[str]:
    names: set[str] = set()
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict) or "registrant" not in entity.get("roles", []):
            continue
        vcard = entity.get("vcardArray", [])
        properties = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        for prop in properties if isinstance(properties, list) else []:
            if not isinstance(prop, list) or len(prop) < 4 or prop[0] not in {"fn", "org"}:
                continue
            raw = prop[3]
            values = raw if isinstance(raw, list) else [raw]
            for value in values:
                if isinstance(value, str) and value.strip():
                    names.add(value.strip())
    return sorted(names)


def parse_arin_rdap(payload: dict[str, Any], ip: str) -> dict[str, Any]:
    origin_asns: list[str] = []
    for raw_asn in payload.get("arin_originas0_originautnums", []):
        try:
            origin_asns.append(normalize_asn(str(raw_asn)))
        except ValueError:
            continue
    return {
        "ip": str(ipaddress.ip_address(ip)),
        "handle": str(payload.get("handle") or "").strip(),
        "name": str(payload.get("name") or "").strip(),
        "type": str(payload.get("type") or "").strip(),
        "country": str(payload.get("country") or "").strip(),
        "start_address": str(payload.get("startAddress") or "").strip(),
        "end_address": str(payload.get("endAddress") or "").strip(),
        "origin_asns": sorted(set(origin_asns)),
        "organizations": _rdap_entity_names(payload.get("entities")),
    }


def arin_rdap_ip(ip: str, *, timeout: int, retries: int) -> dict[str, Any]:
    address = str(ipaddress.ip_address(ip))
    payload = request_json(
        ARIN_RDAP_IP.format(ip=quote(address, safe=":")),
        timeout=timeout,
        retries=retries,
    )
    if not isinstance(payload, dict):
        return parse_arin_rdap({}, address)
    return parse_arin_rdap(payload, address)


def ripe_prefixes(asn: str, *, timeout: int, retries: int) -> list[str]:
    normalized = normalize_asn(asn)
    payload = request_json(
        RIPE_ANNOUNCED_PREFIXES,
        params={"resource": normalized},
        timeout=timeout,
        retries=retries,
    )
    prefixes = payload.get("data", {}).get("prefixes", []) if isinstance(payload, dict) else []
    results: list[str] = []
    for item in prefixes:
        value = item.get("prefix") if isinstance(item, dict) else None
        if not value:
            continue
        try:
            results.append(normalize_cidr(value))
        except ValueError:
            continue
    return sorted(set(results))


def crtsh_domains(domain: str, *, timeout: int, retries: int) -> list[str]:
    payload = request_json(
        CRT_SH,
        params={"q": f"%.{domain}", "output": "json"},
        timeout=timeout,
        retries=retries,
    )
    if not isinstance(payload, list):
        return []
    names: set[str] = set()
    for row in payload:
        if not isinstance(row, dict):
            continue
        for key in ("name_value", "common_name"):
            value = row.get(key)
            if not isinstance(value, str):
                continue
            for name in extract_domains(value, [domain]):
                if domain_in_scope(name, [domain]):
                    names.add(name)
    return sorted(names)


def certspotter_domains(
    domain: str, *, timeout: int, retries: int, max_pages: int = 5
) -> list[str]:
    """Return CT names from SSLMate Cert Spotter, with bounded pagination."""
    names: set[str] = set()
    after: str | None = None
    headers: dict[str, str] = {}
    api_key = os.getenv("CERTSPOTTER_API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    for _ in range(max(1, max_pages)):
        params: dict[str, str | int] = {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
        if after:
            params["after"] = after
        payload = request_json(
            CERTSPOTTER_ISSUANCES,
            params=params,
            headers=headers,
            timeout=timeout,
            retries=retries,
        )
        if not isinstance(payload, list) or not payload:
            break
        next_after: str | None = None
        for row in payload:
            if not isinstance(row, dict):
                continue
            raw_names = row.get("dns_names", [])
            if isinstance(raw_names, list):
                for raw in raw_names:
                    if isinstance(raw, str):
                        names.update(extract_domains(raw, [domain]))
            if row.get("id") is not None:
                next_after = str(row["id"])
        if not next_after or next_after == after:
            break
        after = next_after
    return sorted(names)


def censys_query(domain: str) -> str:
    escaped = re.escape(domain.lower().rstrip("."))
    suffix = rf"^([^.]+\.)*{escaped}$"
    return (
        f"(web.hostname=~`{suffix}` or host.dns.names=~`{suffix}` "
        f"or cert.names=~`{suffix}`)"
    )


def _walk_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)


def extract_censys_indicators(payload: Any, domain: str) -> dict[str, list[str]]:
    root = domain.lower().rstrip(".")
    names: set[str] = {root}
    addresses: set[str] = set()
    pattern = re.compile(
        rf"(?i)(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)*{re.escape(root)}\.?"
    )
    for raw in _walk_strings(payload):
        candidate = raw.strip().rstrip(".")
        try:
            addresses.add(str(ipaddress.ip_address(candidate)))
            continue
        except ValueError:
            pass
        for match in pattern.finditer(raw):
            value = match.group(0).rstrip(".").lower()
            try:
                extracted = extract_domains(value, [root])
            except ValueError:
                extracted = []
            names.update(item for item in extracted if domain_in_scope(item, [root]))
    return {
        "domains": sorted(names),
        "ips": sorted(
            addresses,
            key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item)),
        ),
    }


def censys_search(
    domain: str,
    *,
    api_key: str,
    organization_id: str = "",
    timeout: int,
    retries: int,
    page_size: int = 100,
) -> dict[str, Any]:
    if not api_key:
        raise HttpError("CENSYS_API_KEY is not configured")
    if ":" in api_key:
        raise HttpError(
            "CENSYS_API_KEY looks like a legacy API ID/secret pair; "
            "the Platform API requires a Personal Access Token",
            status_code=401,
        )
    params: dict[str, str | int] | None = None
    if organization_id:
        params = {"organization_id": organization_id}
    payload = request_json(
        CENSYS_SEARCH,
        params=params,
        headers={"Authorization": f"Bearer {api_key}"},
        method="POST",
        json_body={"query": censys_query(domain), "page_size": min(max(page_size, 1), 100)},
        timeout=timeout,
        retries=retries,
    )
    indicators = extract_censys_indicators(payload, domain)
    return {"payload": payload, **indicators}


def normalize_urlscan(payload: Any, domain: str) -> dict[str, list[str]]:
    root = domain.lower().rstrip(".")
    names: set[str] = {root}
    addresses: set[str] = set()
    urls: set[str] = set()
    results = payload.get("results", []) if isinstance(payload, dict) else []
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        for section in (result.get("page", {}), result.get("task", {})):
            if not isinstance(section, dict):
                continue
            host = str(section.get("domain") or "").lower().strip().rstrip(".")
            if host and domain_in_scope(host, [root]):
                names.add(host)
            url = str(section.get("url") or "").strip()
            if url.startswith(("http://", "https://")):
                urls.add(url)
            raw_ip = str(section.get("ip") or "").strip()
            try:
                if raw_ip:
                    addresses.add(str(ipaddress.ip_address(raw_ip)))
            except ValueError:
                pass
        lists = result.get("lists", {})
        if isinstance(lists, dict):
            for raw in lists.get("ips", []) if isinstance(lists.get("ips"), list) else []:
                try:
                    addresses.add(str(ipaddress.ip_address(str(raw))))
                except ValueError:
                    continue
    return {
        "domains": sorted(names),
        "urls": sorted(urls),
        "ips": sorted(
            addresses,
            key=lambda item: (ipaddress.ip_address(item).version, ipaddress.ip_address(item)),
        ),
    }


def urlscan_search(
    domain: str,
    *,
    api_key: str,
    timeout: int,
    retries: int,
    size: int = 500,
) -> dict[str, Any]:
    if not api_key:
        raise HttpError("URLSCAN_API_KEY is not configured")
    query = (
        f"(page.domain:{domain} OR page.domain:*.{domain} "
        f"OR task.domain:{domain} OR task.domain:*.{domain})"
    )
    payload = request_json(
        URLSCAN_SEARCH,
        params={"q": query, "size": min(max(size, 1), 10_000)},
        headers={"API-Key": api_key},
        timeout=timeout,
        retries=retries,
    )
    return {"payload": payload, **normalize_urlscan(payload, domain)}


def shodan_request(
    signature: Signature,
    *,
    mode: str,
    pages: int,
    timeout: int,
    retries: int,
    api_key: str | None = None,
) -> dict[str, Any]:
    key = api_key or os.getenv("SHODAN_API_KEY")
    if not key:
        raise HttpError("SHODAN_API_KEY is not configured")
    common = {"key": key, "query": signature.query}
    if mode == "count":
        payload = request_json(SHODAN_COUNT, params=common, timeout=timeout, retries=retries)
        return {
            "id": signature.identifier,
            "name": signature.name,
            "query": signature.query,
            "total": int(payload.get("total", 0)) if isinstance(payload, dict) else 0,
            "matches": [],
        }
    matches: list[dict[str, Any]] = []
    total = 0
    for page in range(1, max(1, pages) + 1):
        params = dict(common, page=page, minify="true")
        payload = request_json(SHODAN_SEARCH, params=params, timeout=timeout, retries=retries)
        if not isinstance(payload, dict):
            break
        total = int(payload.get("total", total) or 0)
        current = payload.get("matches", [])
        if not isinstance(current, list) or not current:
            break
        matches.extend(item for item in current if isinstance(item, dict))
        if len(current) < 100:
            break
    return {
        "id": signature.identifier,
        "name": signature.name,
        "query": signature.query,
        "total": total,
        "matches": matches,
    }


def _fetch_cloud_family(provider: str, family: int, *, timeout: int, retries: int) -> list[str]:
    folder = CLOUD_PROVIDERS[provider]
    url = f"{IPRANGES_BASE}/{quote(folder)}/ipv{family}_merged.txt"
    payload = request_bytes(url, timeout=timeout, retries=retries).decode("utf-8", "replace")
    ranges: list[str] = []
    for line in payload.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version == family:
            ranges.append(str(network))
    return sorted(set(ranges))


def fetch_cloud_ranges(
    providers: list[str], *, timeout: int, retries: int, jobs: int
) -> tuple[dict[str, list[ipaddress._BaseNetwork]], dict[str, str]]:
    normalized = []
    for provider in providers:
        key = provider.strip().lower()
        if key and key not in normalized:
            if key not in CLOUD_PROVIDERS:
                raise ValueError(f"unsupported cloud provider: {provider}")
            normalized.append(key)

    ranges: dict[str, list[ipaddress._BaseNetwork]] = {item: [] for item in normalized}
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(jobs, 2))) as executor:
        futures = {
            executor.submit(
                _fetch_cloud_family, provider, family, timeout=timeout, retries=retries
            ): (provider, family)
            for provider in normalized
            for family in (4, 6)
        }
        for future in as_completed(futures):
            provider, family = futures[future]
            try:
                values = future.result()
                ranges[provider].extend(ipaddress.ip_network(item) for item in values)
            except (HttpError, OSError, ValueError) as exc:
                errors[f"{provider}/ipv{family}"] = str(exc)
    return ranges, errors


def classify_cloud_value(
    value: str, ranges: dict[str, list[ipaddress._BaseNetwork]]
) -> list[str]:
    try:
        candidate = ipaddress.ip_network(value, strict=False)
    except ValueError:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return []
        candidate = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
    providers: list[str] = []
    for provider, networks in ranges.items():
        for network in networks:
            if candidate.version == network.version and candidate.overlaps(network):
                providers.append(provider)
                break
    return providers


def manual_osint_markdown(domains: list[str], asns: list[str], organizations: list[str]) -> str:
    lines = [
        "# Corporate OSINT handoff",
        "",
        "These checks require human review, a paid account, or an interface without a stable API.",
        "Cachaza does not collect personal data for phishing or social engineering.",
        "",
        "## Domains",
        "",
    ]
    if domains:
        for domain in domains:
            lines.extend(
                [
                    f"### {domain}",
                    "",
                    f"- BGP/DNS: https://bgp.he.net/dns/{domain}",
                    f"- Microsoft 365 tenant: run `tenant-domains.sh -d {domain} -s` if installed.",
                    f"- ARIN RDAP search: https://search.arin.net/rdap/?query={domain}",
                    "- Review asndnschecker.org manually and at a low request rate.",
                    "",
                ]
            )
    else:
        lines.append("- No domains were provided.\n")

    lines.extend(["## ASN", ""])
    if asns:
        for asn in asns:
            lines.extend(
                [
                    f"- {asn}: https://bgp.he.net/{asn}",
                    f"- {asn} (ARIN/RDAP): https://search.arin.net/rdap/?query={asn}",
                ]
            )
    else:
        lines.append("- No ASNs were provided.")

    lines.extend(["", "## Corporate intelligence", ""])
    if organizations:
        for org in organizations:
            encoded = quote(org)
            lines.extend(
                [
                    f"- {org}: cross-check parent company, subsidiaries, and acquisitions in Tracxn and PitchBook.",
                    f"- Encoded general search: https://www.google.com/search?q={encoded}",
                ]
            )
    else:
        lines.append("- No organizations were provided.")
    lines.extend(
        [
            "",
            "## Methodology sources",
            "",
            "- https://github.com/projectdiscovery/asnmap",
            "- https://github.com/TheArqsz/tenant-domains",
            "- https://github.com/lord-alfred/ipranges",
            "- https://github.com/g0ldencybersec/Caduceus",
            "- https://github.com/g0ldencybersec/gungnir",
            "- https://github.com/projectdiscovery/subfinder",
            "- https://github.com/blacklanternsecurity/bbot",
            "- https://github.com/tomnomnom/assetfinder",
            "",
        ]
    )
    return "\n".join(lines)


def parse_json_lines(text: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            results.append(value)
    return results


def load_fingerprint_file(path: str | None) -> list[str]:
    if not path:
        return []
    return Path(path).expanduser().read_text(encoding="utf-8", errors="replace").splitlines()
