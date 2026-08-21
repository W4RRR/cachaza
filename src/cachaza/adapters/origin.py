"""Bounded passive adapters used by automatic Origin candidate discovery."""

from __future__ import annotations

import base64
import ipaddress
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..external import CommandRunner, find_tool
from ..http import HttpError, request_json
from ..models import Finding
from ..safety import domain_in_scope
from ..sources import censys_search


SOURCE_FAMILIES = {
    "crt.sh": "certificate_transparency",
    "certspotter": "certificate_transparency",
    "subfinder": "subdomain_enumeration",
    "assetfinder": "subdomain_enumeration",
    "bbot": "subdomain_enumeration",
    "urlscan": "urlscan",
    "censys": "censys",
    "censys-platform": "censys",
    "shodan": "shodan",
    "uncover": "infrastructure_search",
    "virustotal": "virustotal",
    "securitytrails": "securitytrails",
    "otx": "otx",
    "viewdns": "viewdns",
    "fofa": "fofa",
    "dns": "current_dns",
    "dnsx": "current_dns",
    "scope": "operator_scope",
}


@dataclass(slots=True)
class CandidateObservation:
    ip: str
    source: str
    source_family: str
    hostname: str = ""
    relationship: str = "related"
    historical: bool = False
    first_seen: str | None = None
    last_seen: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def source_family(source: str, metadata: dict[str, Any] | None = None) -> str:
    clean = source.casefold()
    if clean == "uncover" and metadata:
        engine = str(metadata.get("engine") or "").casefold()
        if engine in {"shodan", "censys"}:
            return engine
    for key, family in SOURCE_FAMILIES.items():
        if key in clean:
            return family
    return clean.replace(" ", "_") or "unknown"


def resolve_host(name: str) -> list[str]:
    """Resolve A/AAAA records without shell execution."""
    values: set[str] = set()
    try:
        rows = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return []
    for row in rows:
        raw = str(row[4][0]).split("%", 1)[0]
        try:
            values.add(str(ipaddress.ip_address(raw)))
        except ValueError:
            continue
    return sorted(values, key=lambda value: (ipaddress.ip_address(value).version, value))


def collect_workspace_observations(
    findings: Iterable[Finding], roots: list[str]
) -> list[CandidateObservation]:
    """Convert existing provider evidence into origin observations.

    It intentionally does not treat two wrappers over the same upstream source
    as independent: ``source_family`` performs that normalization.
    """
    observations: list[CandidateObservation] = []
    services_by_ip: dict[str, list[Finding]] = {}
    fingerprints_by_ip: dict[str, list[Finding]] = {}
    cloud_by_ip: dict[str, list[str]] = {}
    asns_by_ip: dict[str, list[str]] = {}
    organizations_by_ip: dict[str, list[str]] = {}
    for finding in findings:
        if finding.kind == "service":
            host = finding.value.rsplit(":", 1)[0].strip("[]")
            services_by_ip.setdefault(host, []).append(finding)
        elif finding.kind == "fingerprint":
            host = str(finding.metadata.get("ip") or "")
            if host:
                fingerprints_by_ip.setdefault(host, []).append(finding)
        elif finding.kind == "cloud_asset":
            try:
                host = str(ipaddress.ip_address(finding.value))
            except ValueError:
                continue
            providers = finding.metadata.get("providers", [])
            if isinstance(providers, str):
                providers = [providers]
            if isinstance(providers, list):
                cloud_by_ip.setdefault(host, []).extend(str(item) for item in providers)
        elif finding.kind in {"asn", "organization", "network_registration"}:
            raw_ip = str(finding.metadata.get("ip") or "")
            try:
                host = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue
            if finding.kind == "asn":
                asns_by_ip.setdefault(host, []).append(finding.value)
            else:
                organizations_by_ip.setdefault(host, []).append(finding.value)

    for finding in findings:
        if finding.kind != "ip":
            continue
        try:
            ip = str(ipaddress.ip_address(finding.value))
        except ValueError:
            continue
        metadata = dict(finding.metadata)
        root = str(metadata.get("root") or metadata.get("host") or "")
        if root and not domain_in_scope(root, roots):
            root = ""
        relationship = "provider_search"
        if finding.source == "urlscan":
            relationship = "urlscan_main_document"
        elif metadata.get("historical"):
            relationship = "historical_dns"
        elif finding.source in {"dns", "dnsx"}:
            relationship = "current_dns"
        elif finding.source == "scope":
            relationship = "operator_scope"
        if services_by_ip.get(ip):
            metadata["web_services"] = sorted(item.value for item in services_by_ip[ip])
        if fingerprints_by_ip.get(ip):
            metadata["certificate_fingerprints"] = sorted(
                item.value for item in fingerprints_by_ip[ip]
            )
        if cloud_by_ip.get(ip):
            metadata["cloud_providers"] = sorted(set(cloud_by_ip[ip]))
        if asns_by_ip.get(ip):
            metadata["asns"] = sorted(set(asns_by_ip[ip]))
        if organizations_by_ip.get(ip):
            metadata["organizations"] = sorted(set(organizations_by_ip[ip]))
        observations.append(
            CandidateObservation(
                ip=ip,
                source=finding.source,
                source_family=source_family(finding.source, metadata),
                hostname=root,
                relationship=relationship,
                historical=bool(metadata.get("historical")),
                first_seen=str(metadata.get("first_seen") or "") or None,
                last_seen=str(metadata.get("last_seen") or "") or None,
                metadata=metadata,
            )
        )
    return observations


def collect_resolved_names(names: Iterable[str], roots: list[str]) -> list[CandidateObservation]:
    observations: list[CandidateObservation] = []
    for name in sorted(set(names)):
        if not domain_in_scope(name, roots):
            continue
        for ip in resolve_host(name):
            observations.append(
                CandidateObservation(
                    ip=ip,
                    hostname=name,
                    source="dns",
                    source_family="current_dns",
                    relationship="current_dns",
                )
            )
    return observations


def virustotal_resolutions(
    domain: str,
    *,
    api_key: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
    payload = request_json(
        url,
        timeout=timeout,
        retries=retries,
        params={"limit": min(maximum, 40)},
        headers={"x-apikey": api_key},
    )
    rows = list(payload.get("data", [])) if isinstance(payload, dict) and isinstance(payload.get("data"), list) else []
    next_url = payload.get("links", {}).get("next") if isinstance(payload, dict) and isinstance(payload.get("links"), dict) else None
    pages = 1
    while next_url and len(rows) < maximum and pages < 3:
        page = request_json(
            str(next_url), timeout=timeout, retries=retries, headers={"x-apikey": api_key}
        )
        if not isinstance(page, dict):
            break
        page_rows = page.get("data", [])
        if not isinstance(page_rows, list) or not page_rows:
            break
        rows.extend(page_rows)
        links = page.get("links", {})
        next_url = links.get("next") if isinstance(links, dict) else None
        pages += 1
    observations: list[CandidateObservation] = []
    for row in rows[:maximum] if isinstance(rows, list) else []:
        attributes = row.get("attributes", {}) if isinstance(row, dict) else {}
        raw_ip = str(attributes.get("ip_address") or row.get("id") or "")
        try:
            ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            continue
        observations.append(
            CandidateObservation(
                ip=ip,
                hostname=domain,
                source="virustotal",
                source_family="virustotal",
                relationship="historical_dns",
                historical=True,
                first_seen=str(attributes.get("first_seen") or "") or None,
                last_seen=str(attributes.get("date") or attributes.get("last_seen") or "") or None,
                metadata={"record_type": "A/AAAA", "historical": True},
            )
        )
    combined = dict(payload) if isinstance(payload, dict) else {}
    combined["data"] = rows[:maximum]
    combined["pages_collected"] = pages
    return observations, combined


def securitytrails_resolutions(
    domain: str,
    *,
    api_key: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    observations: list[CandidateObservation] = []
    payloads: dict[str, Any] = {}
    for record_type in ("a", "aaaa"):
        payload = request_json(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/{record_type}",
            timeout=timeout,
            retries=retries,
            headers={"APIKEY": api_key},
        )
        payloads[record_type] = payload
        rows = payload.get("records", []) if isinstance(payload, dict) else []
        for row in rows if isinstance(rows, list) else []:
            values = row.get("values", []) if isinstance(row, dict) else []
            for value in values if isinstance(values, list) else []:
                raw_ip = value.get("ip") if isinstance(value, dict) else value
                try:
                    ip = str(ipaddress.ip_address(str(raw_ip)))
                except ValueError:
                    continue
                observations.append(
                    CandidateObservation(
                        ip=ip,
                        hostname=domain,
                        source="securitytrails",
                        source_family="securitytrails",
                        relationship="historical_dns",
                        historical=True,
                        first_seen=str(row.get("first_seen") or "") or None,
                        last_seen=str(row.get("last_seen") or "") or None,
                        metadata={"record_type": record_type.upper(), "historical": True},
                    )
                )
                if len(observations) >= maximum:
                    return observations, payloads
    return observations, payloads


def urlscan_observations(
    domain: str,
    *,
    api_key: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    """Collect existing urlscan results without submitting a new scan."""
    query = (
        f"(page.domain:{domain} OR page.domain:*.{domain} "
        f"OR task.domain:{domain} OR task.domain:*.{domain})"
    )
    headers = {"API-Key": api_key} if api_key else {}
    payload = request_json(
        "https://urlscan.io/api/v1/search/",
        timeout=timeout,
        retries=retries,
        params={"q": query, "size": min(maximum, 10_000)},
        headers=headers,
    )
    observations: list[CandidateObservation] = []
    rows = payload.get("results", []) if isinstance(payload, dict) else []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        page = row.get("page", {})
        task = row.get("task", {})
        if not isinstance(page, dict) or not isinstance(task, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(str(page.get("ip") or "")))
        except ValueError:
            continue
        hostname = str(page.get("domain") or domain).casefold().rstrip(".")
        if not domain_in_scope(hostname, [domain]):
            hostname = domain
        asn = str(page.get("asn") or "")
        if asn and not asn.upper().startswith("AS"):
            asn = "AS" + asn
        observations.append(
            CandidateObservation(
                ip=ip,
                hostname=hostname,
                source="urlscan",
                source_family="urlscan",
                relationship="urlscan_main_document",
                historical=True,
                last_seen=str(task.get("time") or "") or None,
                metadata={
                    "historical": True,
                    "asns": [asn] if asn else [],
                    "organizations": [str(page.get("asnname"))] if page.get("asnname") else [],
                    "url": str(task.get("url") or page.get("url") or ""),
                },
            )
        )
        if len(observations) >= maximum:
            break
    return observations, payload if isinstance(payload, dict) else {}


def censys_observations(
    domain: str,
    *,
    api_key: str,
    organization_id: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    """Collect Censys Platform certificate/name correlations."""
    result = censys_search(
        domain,
        api_key=api_key,
        organization_id=organization_id,
        timeout=timeout,
        retries=retries,
        page_size=min(maximum, 100),
    )
    observations = [
        CandidateObservation(
            ip=ip,
            hostname=domain,
            source="censys-platform",
            source_family="censys",
            relationship="provider_search",
            metadata={"certificate_search": True},
        )
        for ip in result.get("ips", [])[:maximum]
    ]
    return observations, result.get("payload", {})


def shodan_observations(
    domain: str,
    *,
    api_key: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    """Search indexed Shodan banners; this never requests an active Shodan scan."""
    query = f'ssl:"{domain}"'
    payload = request_json(
        "https://api.shodan.io/shodan/host/search",
        timeout=timeout,
        retries=retries,
        params={"key": api_key, "query": query, "page": 1, "minify": "false"},
    )
    observations: list[CandidateObservation] = []
    rows = payload.get("matches", []) if isinstance(payload, dict) else []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(str(row.get("ip_str") or "")))
        except ValueError:
            continue
        hostnames = row.get("hostnames") or row.get("domains") or []
        hostname = str(hostnames[0]) if isinstance(hostnames, list) and hostnames else domain
        metadata: dict[str, Any] = {"certificate_search": True}
        if row.get("asn"):
            metadata["asns"] = [str(row["asn"])]
        if row.get("org"):
            metadata["organizations"] = [str(row["org"])]
        if isinstance(row.get("port"), int):
            metadata["ports"] = [row["port"]]
        observations.append(
            CandidateObservation(
                ip=ip,
                hostname=hostname,
                source="shodan",
                source_family="shodan",
                relationship="provider_search",
                last_seen=str(row.get("timestamp") or "") or None,
                metadata=metadata,
            )
        )
        if len(observations) >= maximum:
            break
    return observations, payload if isinstance(payload, dict) else {}


def otx_observations(
    domain: str,
    *,
    api_key: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    """Collect AlienVault OTX passive DNS and archived URL observations."""
    base = f"https://otx.alienvault.com/api/v1/indicator/hostname/{domain}"
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    payloads: dict[str, Any] = {}
    errors: list[str] = []
    observations: list[CandidateObservation] = []
    try:
        passive = request_json(
            f"{base}/passive_dns", timeout=timeout, retries=retries, headers=headers
        )
        payloads["passive_dns"] = passive
        rows = passive.get("passive_dns", []) if isinstance(passive, dict) else []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            try:
                ip = str(ipaddress.ip_address(str(row.get("address") or "")))
            except ValueError:
                continue
            observations.append(
                CandidateObservation(
                    ip=ip,
                    hostname=str(row.get("hostname") or domain),
                    source="otx",
                    source_family="otx",
                    relationship="historical_dns",
                    historical=True,
                    first_seen=str(row.get("first") or "") or None,
                    last_seen=str(row.get("last") or "") or None,
                    metadata={"historical": True, "asns": [str(row["asn"])] if row.get("asn") else []},
                )
            )
    except HttpError as exc:
        errors.append(f"passive_dns: {exc}")
    try:
        archived = request_json(
            f"{base}/url_list",
            timeout=timeout,
            retries=retries,
            params={"limit": min(maximum, 100), "page": 1},
            headers=headers,
        )
        payloads["url_list"] = archived
        rows = archived.get("url_list", []) if isinstance(archived, dict) else []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            result = row.get("result", {})
            worker = result.get("urlworker", {}) if isinstance(result, dict) else {}
            try:
                ip = str(ipaddress.ip_address(str(worker.get("ip") or "")))
            except (AttributeError, ValueError):
                continue
            observations.append(
                CandidateObservation(
                    ip=ip,
                    hostname=str(row.get("hostname") or domain),
                    source="otx",
                    source_family="otx",
                    relationship="urlscan_main_document",
                    historical=True,
                    last_seen=str(row.get("date") or "") or None,
                    metadata={"historical": True, "url": str(row.get("url") or "")},
                )
            )
    except HttpError as exc:
        errors.append(f"url_list: {exc}")
    payloads["errors"] = errors
    return observations[:maximum], payloads


def viewdns_resolutions(
    domain: str,
    *,
    api_key: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    payload = request_json(
        "https://api.viewdns.info/iphistory/",
        timeout=timeout,
        retries=retries,
        params={"domain": domain, "apikey": api_key, "output": "json"},
    )
    response = payload.get("response", {}) if isinstance(payload, dict) else {}
    rows = response.get("records", []) if isinstance(response, dict) else []
    observations: list[CandidateObservation] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(str(row.get("ip") or "")))
        except ValueError:
            continue
        observations.append(
            CandidateObservation(
                ip=ip,
                hostname=domain,
                source="viewdns",
                source_family="viewdns",
                relationship="historical_dns",
                historical=True,
                last_seen=str(row.get("lastseen") or "") or None,
                metadata={
                    "historical": True,
                    "organizations": [str(row["owner"])] if row.get("owner") else [],
                    "country": str(row.get("location") or ""),
                },
            )
        )
        if len(observations) >= maximum:
            break
    return observations, payload if isinstance(payload, dict) else {}


def fofa_observations(
    domain: str,
    *,
    email: str,
    api_key: str,
    maximum: int,
    timeout: int,
    retries: int,
) -> tuple[list[CandidateObservation], dict[str, Any]]:
    query = f'domain="{domain}"'
    fields = "ip,port,host,domain,title,cert,asn,org,lastupdatetime"
    payload = request_json(
        "https://fofa.info/api/v1/search/all",
        timeout=timeout,
        retries=retries,
        params={
            "email": email,
            "key": api_key,
            "qbase64": base64.b64encode(query.encode()).decode(),
            "fields": fields,
            "size": min(maximum, 100),
        },
    )
    if isinstance(payload, dict) and payload.get("error"):
        raise HttpError(str(payload.get("errmsg") or "FOFA returned an error"))
    observations: list[CandidateObservation] = []
    rows = payload.get("results", []) if isinstance(payload, dict) else []
    field_names = fields.split(",")
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, list):
            continue
        values = dict(zip(field_names, row))
        try:
            ip = str(ipaddress.ip_address(str(values.get("ip") or "")))
        except ValueError:
            continue
        metadata: dict[str, Any] = {"certificate_search": bool(values.get("cert"))}
        if values.get("asn"):
            metadata["asns"] = [str(values["asn"])]
        if values.get("org"):
            metadata["organizations"] = [str(values["org"])]
        if str(values.get("port") or "").isdigit():
            metadata["ports"] = [int(values["port"])]
        observations.append(
            CandidateObservation(
                ip=ip,
                hostname=str(values.get("domain") or domain),
                source="fofa",
                source_family="fofa",
                relationship="provider_search",
                last_seen=str(values.get("lastupdatetime") or "") or None,
                metadata=metadata,
            )
        )
        if len(observations) >= maximum:
            break
    return observations, payload if isinstance(payload, dict) else {}


def run_dns_permutations(
    names: Iterable[str],
    roots: list[str],
    *,
    maximum: int,
    runner: CommandRunner,
    raw_directory: Path,
) -> list[CandidateObservation]:
    """Use AlterX plus PureDNS/DNSx when installed, always with hard caps.

    No wildcard expansion, network range, or ASN enumeration is performed.
    Missing optional tools simply produce no observations.
    """
    alterx = find_tool("alterx")
    resolver = find_tool("puredns") or find_tool("dnsx")
    if not alterx or not resolver or maximum < 1:
        return []
    raw_directory.mkdir(parents=True, exist_ok=True)
    seeds = raw_directory / "permutation-seeds.txt"
    seeds.write_text("\n".join(sorted(set(names))) + "\n", encoding="utf-8")
    altered = runner.run([alterx, "-l", str(seeds), "-limit", str(maximum), "-silent"], timeout=300)
    if altered.skipped or altered.returncode != 0:
        return []
    generated = [
        line.strip().lower().rstrip(".")
        for line in altered.stdout.splitlines()
        if line.strip()
    ][:maximum]
    candidates_file = raw_directory / "permutations.txt"
    candidates_file.write_text("\n".join(generated) + ("\n" if generated else ""), encoding="utf-8")
    if not generated:
        return []
    resolver_label = Path(resolver).name.casefold()
    resolved_text = ""
    if resolver_label.startswith("puredns"):
        pure = runner.run([resolver, "resolve", str(candidates_file), "-q"], timeout=600)
        if pure.skipped:
            return []
        dnsx = find_tool("dnsx")
        if pure.returncode == 0:
            valid_names = [line.strip().rstrip(".") for line in pure.stdout.splitlines() if line.strip()][:maximum]
            valid_file = raw_directory / "puredns-valid.txt"
            valid_file.write_text("\n".join(valid_names) + ("\n" if valid_names else ""), encoding="utf-8")
            if dnsx and valid_names:
                resolved = runner.run([dnsx, "-l", str(valid_file), "-a", "-aaaa", "-resp", "-silent"], timeout=600)
                if resolved.skipped or resolved.returncode != 0:
                    return []
                resolved_text = resolved.stdout
                resolver_label = "puredns+dnsx"
            else:
                resolved_text = "\n".join(
                    f"{name} {ip}" for name in valid_names for ip in resolve_host(name)
                )
                resolver_label = "puredns+socket"
        elif dnsx:
            resolved = runner.run([dnsx, "-l", str(candidates_file), "-a", "-aaaa", "-resp", "-silent"], timeout=600)
            if resolved.skipped or resolved.returncode != 0:
                return []
            resolved_text = resolved.stdout
            resolver_label = "dnsx"
        else:
            return []
    else:
        resolved = runner.run([resolver, "-l", str(candidates_file), "-a", "-aaaa", "-resp", "-silent"], timeout=600)
        if resolved.skipped or resolved.returncode != 0:
            return []
        resolved_text = resolved.stdout
        resolver_label = "dnsx"
    raw_directory.joinpath("permutation-resolutions.txt").write_text(
        resolved_text, encoding="utf-8"
    )
    observations: list[CandidateObservation] = []
    address_frequency: dict[str, int] = {}
    parsed_rows: list[tuple[str, str]] = []
    for line in resolved_text.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        hostname = parts[0].rstrip(".").lower()
        if not domain_in_scope(hostname, roots):
            continue
        for token in parts[1:]:
            token = token.strip("[],")
            try:
                ip = str(ipaddress.ip_address(token))
            except ValueError:
                continue
            parsed_rows.append((hostname, ip))
            address_frequency[ip] = address_frequency.get(ip, 0) + 1
    for hostname, ip in parsed_rows:
        # A single address returned for many unrelated generated labels is
        # treated as wildcard DNS and excluded before candidate creation.
        if address_frequency[ip] > 10:
            continue
        observations.append(
            CandidateObservation(
                ip=ip,
                hostname=hostname,
                source=f"alterx+{resolver_label}",
                source_family="dns_permutation",
                relationship="permuted_hostname",
            )
        )
        if len(observations) >= maximum:
            return observations
    return observations


__all__ = [
    "CandidateObservation",
    "HttpError",
    "collect_resolved_names",
    "collect_workspace_observations",
    "censys_observations",
    "fofa_observations",
    "otx_observations",
    "resolve_host",
    "run_dns_permutations",
    "securitytrails_resolutions",
    "shodan_observations",
    "source_family",
    "urlscan_observations",
    "viewdns_resolutions",
    "virustotal_resolutions",
]
