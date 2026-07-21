"""Self-contained run report exporters."""

from __future__ import annotations

import csv
import ipaddress
import io
import json
import re
from html import escape as html_escape
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from xml.sax.saxutils import escape as xml_escape

from .html_report import render_html
from .models import Finding, TargetSpec, utc_now
from .workspace import RunWorkspace


REPORT_FORMATS = ("html", "json", "txt", "pdf", "csv")


KEY_FINDING_LABELS = (
    ("wafs", "WAFs"),
    ("subdomains", "Actionable subdomains"),
    ("api_key_candidates", "API key/secret candidates"),
    ("api_endpoints", "API endpoints"),
    ("emails", "Emails"),
    ("phones", "Phones"),
    ("addresses", "Addresses"),
    ("zone_transfer_allowed", "Zone transfer allowed"),
)


NOISY_DNS_ENUM_SOURCES = frozenset({"dnsenum", "fierce"})
LIVE_HTTP_STATUS_CODES = frozenset({401, 403})
PDF_EVIDENCE_LIMIT = 100


def _is_waf_banner_false_positive(item: dict[str, Any]) -> bool:
    if item.get("kind") != "waf" or item.get("source") != "wafw00f":
        return False
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    evidence = str(metadata.get("evidence") or "").casefold()
    return evidence.strip() in {
        "the web application firewall fingerprinting toolkit",
        "~ sniffing web application firewalls since 2014 ~",
    }


def build_subdomain_summary(
    findings: list[Finding] | list[dict[str, Any]],
) -> dict[str, Any]:
    """Separate validated subdomains from unverified enumeration candidates.

    DNS brute-force output is deliberately not promoted on its own. When active
    DNS/HTTP evidence exists, only names that resolved through dnsx or produced
    a meaningful HTTP response remain actionable. Passive-only reports retain
    non-bruteforce discoveries so they do not become artificially empty.
    """
    normalized = [raw.to_dict() if isinstance(raw, Finding) else raw for raw in findings]
    roots = {
        str(item.get("value") or "").casefold().rstrip(".")
        for item in normalized
        if item.get("stage") == "input" and item.get("kind") == "domain"
    }
    roots.update(
        str(item.get("metadata", {}).get("root") or "").casefold().rstrip(".")
        for item in normalized
        if isinstance(item.get("metadata"), dict)
        and item.get("metadata", {}).get("root")
    )
    roots.discard("")
    evidence: dict[str, dict[str, Any]] = {}

    def is_subdomain(host: str) -> bool:
        return any(host.endswith("." + root) for root in roots)

    def record(host: str) -> dict[str, Any] | None:
        clean = host.casefold().rstrip(".")
        if not clean or not is_subdomain(clean):
            return None
        return evidence.setdefault(
            clean,
            {
                "host": clean,
                "sources": set(),
                "dns_resolved": False,
                "http_statuses": set(),
                "http_urls": set(),
                "wildcard_suspect": False,
            },
        )

    for item in normalized:
        if _is_waf_banner_false_positive(item):
            continue
        kind = str(item.get("kind") or "")
        source = str(item.get("source") or "")
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if kind == "domain":
            entry = record(str(item.get("value") or ""))
            if entry is None:
                continue
            if source:
                entry["sources"].add(source)
            if source == "dnsx" and metadata.get("resolved") is True:
                entry["dns_resolved"] = True
            if metadata.get("wildcard_suspect") is True:
                entry["wildcard_suspect"] = True
        elif kind == "url":
            value = str(item.get("value") or "")
            host = str(metadata.get("host") or urlsplit(value).hostname or "")
            entry = record(host)
            if entry is None:
                continue
            if source:
                entry["sources"].add(source)
            status = metadata.get("status_code")
            try:
                code = int(status)
            except (TypeError, ValueError):
                code = 0
            if code:
                entry["http_statuses"].add(code)
                entry["http_urls"].add(value)

    def live_status(code: int) -> bool:
        return 200 <= code < 400 or code in LIVE_HTTP_STATUS_CODES

    has_active_validation = any(
        entry["dns_resolved"] or entry["http_statuses"] for entry in evidence.values()
    )
    live_http: list[dict[str, Any]] = []
    dns_only: list[str] = []
    passive_only: list[str] = []
    omitted: list[str] = []
    for host, entry in sorted(evidence.items()):
        statuses = sorted(entry["http_statuses"])
        is_live = any(live_status(code) for code in statuses)
        passive_sources = entry["sources"] - NOISY_DNS_ENUM_SOURCES - {"dnsx", "httpx"}
        if entry["wildcard_suspect"]:
            omitted.append(host)
        elif is_live:
            live_http.append(
                {
                    "host": host,
                    "statuses": statuses,
                    "urls": sorted(entry["http_urls"]),
                }
            )
        elif entry["dns_resolved"]:
            dns_only.append(host)
        elif passive_sources:
            passive_only.append(host)
        else:
            omitted.append(host)

    actionable = [item["host"] for item in live_http] + dns_only
    if not has_active_validation:
        actionable.extend(passive_only)
        passive_only = []
    else:
        omitted.extend(passive_only)
    return {
        "actionable": sorted(set(actionable)),
        "live_http": live_http,
        "dns_only": sorted(set(dns_only)),
        "omitted": sorted(set(omitted)),
        "active_validation_present": has_active_validation,
    }


def build_key_findings(findings: list[Finding] | list[dict[str, Any]]) -> dict[str, list[str]]:
    """Create stable, deduplicated executive categories without exposing secret values."""
    normalized = [raw.to_dict() if isinstance(raw, Finding) else raw for raw in findings]
    buckets: dict[str, set[str]] = {key: set() for key, _ in KEY_FINDING_LABELS}
    waf_targets: dict[str, set[str]] = {}
    for item in normalized:
        if _is_waf_banner_false_positive(item):
            continue
        kind = str(item.get("kind") or "")
        value = str(item.get("value") or "").strip()
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        if not value:
            continue
        if kind == "waf":
            vendor = str(metadata.get("vendor") or value).strip()
            if str(metadata.get("confidence") or "").casefold() == "candidate":
                qualifier = "candidate"
                if metadata.get("requires_manual_validation"):
                    qualifier += "; manual validation"
                vendor = f"{vendor} [{qualifier}]"
            origin = str(metadata.get("target") or "unknown origin").strip()
            waf_targets.setdefault(vendor, set()).add(origin)
        if kind == "api_key_candidate":
            # Parsers store only redacted fingerprints or the URL where a
            # candidate appeared. Never promote raw secret material here.
            buckets["api_key_candidates"].add(value)
        elif metadata.get("secret_candidate"):
            parsed = urlsplit(value)
            safe_location = (
                urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
                if parsed.scheme and parsed.netloc
                else "redacted candidate location"
            )
            buckets["api_key_candidates"].add(safe_location)
        if kind == "api_endpoint" or (kind == "url" and metadata.get("endpoint")):
            buckets["api_endpoints"].add(value)
        if kind == "email":
            buckets["emails"].add(value)
        if kind == "phone":
            buckets["phones"].add(value)
        if kind == "address":
            buckets["addresses"].add(value)
        if kind == "dns_zone_transfer" and metadata.get("allowed"):
            buckets["zone_transfer_allowed"].add(value)
    for vendor, origins in waf_targets.items():
        ordered = sorted(origins, key=str.casefold)
        shown = ordered[:5]
        suffix = f" (+{len(ordered) - 5} more origins)" if len(ordered) > 5 else ""
        buckets["wafs"].add(f"{vendor} @ {', '.join(shown)}{suffix}")
    buckets["subdomains"].update(build_subdomain_summary(normalized)["actionable"])
    return {key: sorted(values, key=str.casefold) for key, values in buckets.items()}


def render_key_findings_console(
    key_findings: dict[str, list[str]],
    *,
    subdomain_summary: dict[str, Any] | None = None,
    color: bool = True,
    subdomain_limit: int = 10,
) -> str:
    """Render a scan-friendly summary without comma-packed terminal lines."""

    def paint(value: str, code: str) -> str:
        return f"\x1b[{code}m{value}\x1b[0m" if color else value

    def section(label: str, count: int | None = None) -> None:
        suffix = f" ({count})" if count is not None else ""
        lines.append(paint(f"{label}{suffix}", "1;36"))

    def bullets(
        values: list[str],
        *,
        indent: str = "    ",
        limit: int = 8,
        show_remaining: bool = True,
    ) -> None:
        for value in values[:limit]:
            lines.append(f"{indent}- {value}")
        remaining = len(values) - limit
        if remaining > 0 and show_remaining:
            lines.append(paint(f"{indent}+ {remaining} more in the full report", "33"))

    lines = ["", paint("KEY FINDINGS", "1;36"), paint("------------", "36"), ""]

    wafs = list(key_findings.get("wafs", []))
    section("WAFs", len(wafs))
    if not wafs:
        lines.append("    No evidence observed")
    for waf_entry in wafs:
        vendor, separator, raw_origins = waf_entry.partition(" @ ")
        if not separator:
            lines.append(f"    - {waf_entry}")
            continue
        more_match = re.search(r"\s+\(\+(\d+) more origins\)$", raw_origins)
        more_origins = int(more_match.group(1)) if more_match else 0
        if more_match:
            raw_origins = raw_origins[: more_match.start()]
        origins = [value for value in raw_origins.split(", ") if value]
        lines.append(f"    {vendor}")
        bullets(origins, indent="      ", limit=5)
        if more_origins:
            lines.append(
                paint(
                    f"      + {more_origins} additional origins in the full report",
                    "33",
                )
            )

    lines.append("")
    actionable = list(key_findings.get("subdomains", []))
    section("Actionable subdomains", len(actionable))
    if subdomain_summary is None:
        if actionable:
            bullets(actionable, limit=subdomain_limit)
        else:
            lines.append("    None validated")
    else:
        live_http = [
            item
            for item in subdomain_summary.get("live_http", [])
            if isinstance(item, dict) and item.get("host")
        ]
        dns_only = [str(value) for value in subdomain_summary.get("dns_only", [])]
        active_validation = bool(subdomain_summary.get("active_validation_present"))
        remaining_limit = subdomain_limit
        if live_http:
            lines.append(f"    HTTP-responsive ({len(live_http)})")
            for item in live_http[:remaining_limit]:
                statuses = ", ".join(
                    f"HTTP {status}" for status in item.get("statuses", [])
                )
                suffix = f" [{statuses}]" if statuses else ""
                lines.append(f"      - {item['host']}{suffix}")
            shown_live = min(len(live_http), remaining_limit)
            remaining_limit -= shown_live
        if dns_only:
            lines.append(f"    DNS-resolved only ({len(dns_only)})")
            bullets(
                dns_only,
                indent="      ",
                limit=remaining_limit,
                show_remaining=False,
            )
            remaining_limit = max(0, remaining_limit - len(dns_only))
        if actionable and not live_http and not dns_only:
            label = "Passive-only; not actively validated" if not active_validation else "Reported"
            lines.append(f"    {label} ({len(actionable)})")
            bullets(
                actionable,
                indent="      ",
                limit=remaining_limit,
                show_remaining=False,
            )
        if not actionable:
            lines.append("    None validated")
        hidden_actionable = max(0, len(actionable) - subdomain_limit)
        if hidden_actionable:
            lines.append(
                paint(
                    f"    + {hidden_actionable} more actionable subdomains in the full report",
                    "33",
                )
            )
        omitted = len(subdomain_summary.get("omitted", []))
        if omitted:
            lines.append(
                paint(
                    f"    Unverified / wildcard-like candidates omitted: {omitted}",
                    "33",
                )
            )

    lines.extend(["", paint("Other findings", "1;36")])
    for key, label in KEY_FINDING_LABELS:
        if key in {"wafs", "subdomains", "zone_transfer_allowed"}:
            continue
        values = list(key_findings.get(key, []))
        if not values:
            lines.append(f"    {label:<26}: none")
            continue
        lines.append(f"    {label} ({len(values)})")
        bullets(values)

    zone_transfers = list(key_findings.get("zone_transfer_allowed", []))
    if zone_transfers:
        rendered = ", ".join(zone_transfers)
        lines.append(
            f"    {'Zone transfer allowed':<26}: "
            + paint(f"ALLOWED: {rendered}", "1;31")
        )
    else:
        lines.append(
            f"    {'Zone transfer allowed':<26}: " + paint("not observed", "32")
        )
    return "\n".join(lines)


def _csv_safe_cell(value: Any) -> Any:
    """Neutralize spreadsheet formulas while preserving RFC CSV quoting."""
    if not isinstance(value, str):
        return value
    candidate = value.lstrip(" \t\r\n")
    if candidate[:1] in {"=", "+", "-", "@"}:
        return "'" + value
    return value


def _graph_identifier(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def _build_graph(data: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Build a relationship graph from finding metadata and normalized values."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, str]] = {}
    subdomain_summary = data.get("subdomain_summary") or build_subdomain_summary(
        data.get("findings", [])
    )
    visible_subdomains = {
        str(value).casefold() for value in subdomain_summary.get("actionable", [])
    }
    live_http_subdomains = {
        str(item.get("host") or "").casefold()
        for item in subdomain_summary.get("live_http", [])
        if isinstance(item, dict)
    }
    dns_only_subdomains = {
        str(value).casefold() for value in subdomain_summary.get("dns_only", [])
    }
    root_domains = {
        str(value).casefold().rstrip(".") for value in data.get("scope", {}).get("domains", [])
    }

    def hidden_enumeration_domain(value: str) -> bool:
        clean = value.casefold().rstrip(".")
        return any(clean.endswith("." + root) for root in root_domains) and clean not in visible_subdomains

    def add_node(
        kind: str,
        value: Any,
        *,
        in_scope: bool = False,
        source: str | None = None,
        evidence: bool = False,
    ) -> str | None:
        if isinstance(value, bool):
            return None
        clean = str(value or "").strip()
        if not clean:
            return None
        identifier = _graph_identifier(kind, clean)
        node = nodes.setdefault(
            identifier,
            {
                "id": identifier,
                "kind": kind,
                "label": clean,
                "in_scope": False,
                "sources": set(),
                "evidence_count": 0,
            },
        )
        node["in_scope"] = node["in_scope"] or in_scope
        if source:
            node["sources"].add(source)
        if evidence:
            node["evidence_count"] += 1
        return identifier

    def add_edge(source: str | None, target: str | None, relationship: str) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, relationship)
        edges.setdefault(
            key,
            {"source": source, "target": target, "relationship": relationship},
        )

    def add_endpoint(value: Any, *, source: str) -> str | None:
        clean = str(value or "").strip()
        if not clean:
            return None
        if "://" in clean:
            return add_node("url", clean, source=source)
        try:
            address = ipaddress.ip_address(clean.strip("[]"))
            return add_node("ip", str(address), source=source)
        except ValueError:
            pass
        if "/" in clean:
            try:
                network = ipaddress.ip_network(clean, strict=False)
                return add_node("cidr", str(network), source=source)
            except ValueError:
                pass
        host = clean
        if clean.startswith("[") and "]:" in clean:
            host = clean[1 : clean.index("]")]
        elif clean.count(":") == 1:
            possible_host, possible_port = clean.rsplit(":", 1)
            if possible_port.isdigit():
                host = possible_host
        try:
            address = ipaddress.ip_address(host)
            return add_node("ip", str(address), source=source)
        except ValueError:
            return add_node("domain", host, source=source)

    scope = data.get("scope", {})
    for kind, key in (
        ("domain", "domains"),
        ("asn", "asns"),
        ("organization", "organizations"),
        ("cidr", "cidrs"),
    ):
        for value in scope.get(key, []):
            add_node(kind, value, in_scope=True, source="scope")

    for finding in data.get("findings", []):
        if _is_waf_banner_false_positive(finding):
            continue
        kind = str(finding.get("kind") or "finding")
        value = str(finding.get("value") or "")
        source_name = str(finding.get("source") or "unknown")
        if kind == "domain" and hidden_enumeration_domain(value):
            continue
        if kind == "ip" and source_name in NOISY_DNS_ENUM_SOURCES:
            continue
        finding_id = add_node(
            kind,
            value,
            in_scope=bool(finding.get("in_scope")),
            source=source_name,
            evidence=True,
        )
        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}

        root_value = metadata.get("root") or metadata.get("tenant_seed")
        if root_value:
            root_id = add_node("domain", root_value, in_scope=True, source="scope")
            add_edge(root_id, finding_id, str(metadata.get("relationship") or "discovered"))

        input_value = metadata.get("input")
        if input_value and str(input_value) != value:
            input_text = str(input_value)
            input_kind = "asn" if input_text.upper().startswith("AS") else "domain"
            input_id = add_node(input_kind, input_text, source="input")
            add_edge(input_id, finding_id, "mapped")

        raw_asns = metadata.get("asns", [])
        if isinstance(raw_asns, str):
            raw_asns = [raw_asns]
        asn_values = list(raw_asns) if isinstance(raw_asns, list) else []
        if metadata.get("asn"):
            asn_values.append(metadata["asn"])
        for asn_value in asn_values:
            asn_id = add_node("asn", asn_value, source=source_name)
            if kind == "organization":
                add_edge(asn_id, finding_id, str(metadata.get("role") or "holder"))
            elif kind in {"ip", "cidr", "network_registration"}:
                add_edge(finding_id, asn_id, "announced by")
            else:
                add_edge(finding_id, asn_id, "related ASN")

        if metadata.get("ip") and kind != "ip":
            ip_id = add_node("ip", metadata["ip"], source=source_name)
            add_edge(ip_id, finding_id, "registered or observed as")

        providers = metadata.get("providers", [])
        if isinstance(providers, str):
            providers = [providers]
        if metadata.get("provider"):
            providers = list(providers) if isinstance(providers, list) else []
            providers.append(metadata["provider"])
        for provider in providers if isinstance(providers, list) else []:
            provider_id = add_node("cloud_provider", provider, source=source_name)
            add_edge(finding_id, provider_id, "classified as")

        if kind == "url":
            hostname = urlsplit(value).hostname
            if hostname:
                domain_id = add_node("domain", hostname, source=source_name)
                add_edge(domain_id, finding_id, "serves")

        if kind == "api_endpoint":
            hostname = urlsplit(value).hostname
            if hostname:
                domain_id = add_node("domain", hostname, source=source_name)
                add_edge(domain_id, finding_id, "exposes API endpoint")

        if kind == "waf":
            target_id = add_endpoint(metadata.get("target"), source=source_name)
            add_edge(target_id, finding_id, "protected by WAF")

        if kind == "technology":
            target_value = metadata.get("target") or metadata.get("url")
            target_id = add_endpoint(target_value, source=source_name)
            add_edge(target_id, finding_id, "uses technology")
            raw_ips = metadata.get("ips", [])
            if isinstance(raw_ips, str):
                raw_ips = [raw_ips]
            for ip_value in raw_ips if isinstance(raw_ips, list) else []:
                ip_id = add_endpoint(ip_value, source=source_name)
                add_edge(ip_id, finding_id, "technology observed at")

        if kind == "whois":
            ip_id = add_endpoint(metadata.get("ip") or value, source=source_name)
            add_edge(ip_id, finding_id, "WHOIS record")

        if kind == "service":
            endpoint_id = add_endpoint(value, source=source_name)
            add_edge(endpoint_id, finding_id, "exposes service")

        if kind == "cloud_asset":
            asset_id = add_endpoint(value, source=source_name)
            add_edge(asset_id, finding_id, "cloud classification")

        if kind in {"security_finding", "policy_finding", "fingerprint"}:
            target_id = add_endpoint(
                metadata.get("target") or metadata.get("url"), source=source_name
            )
            relationship = {
                "security_finding": "security observation",
                "policy_finding": "policy observation",
                "fingerprint": "has fingerprint",
            }[kind]
            add_edge(target_id, finding_id, relationship)

        if kind == "cve_candidate":
            technology = metadata.get("technology")
            technology_id = add_node("technology", technology, source=source_name)
            add_edge(technology_id, finding_id, "candidate CVE")

        host_value = metadata.get("host")
        if host_value and kind not in {"domain", "url"}:
            host_id = add_endpoint(host_value, source=source_name)
            add_edge(host_id, finding_id, "observed at")

    serialized_nodes: list[dict[str, Any]] = []
    for node in nodes.values():
        node["sources"] = sorted(node["sources"])
        if node["kind"] == "domain":
            label = str(node["label"]).casefold().rstrip(".")
            if label in root_domains:
                node["validation"] = "scope root"
            elif label in live_http_subdomains:
                node["validation"] = "HTTP-responsive"
            elif label in dns_only_subdomains:
                node["validation"] = "DNS-only"
            elif label in visible_subdomains:
                node["validation"] = "passive candidate"
            else:
                node["validation"] = "contextual"
        serialized_nodes.append(node)
    serialized_nodes.sort(key=lambda node: (node["kind"], node["label"]))
    serialized_edges = sorted(
        edges.values(),
        key=lambda edge: (edge["source"], edge["target"], edge["relationship"]),
    )
    return {"nodes": serialized_nodes, "edges": serialized_edges}


def _aggregate(workspace: RunWorkspace, kind: str) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for finding in workspace.findings:
        if finding.kind != kind:
            continue
        entry = grouped.setdefault(
            finding.value,
            {
                "value": finding.value,
                "in_scope": False,
                "sources": set(),
                "evidence": [],
            },
        )
        entry["in_scope"] = entry["in_scope"] or finding.in_scope
        entry["sources"].add(finding.source)
        if finding.metadata and finding.metadata not in entry["evidence"]:
            entry["evidence"].append(finding.metadata)
    results: list[dict[str, Any]] = []
    for entry in grouped.values():
        entry["sources"] = sorted(entry["sources"])
        results.append(entry)
    return sorted(results, key=lambda item: item["value"])


def build_report_data(
    workspace: RunWorkspace,
    target: TargetSpec,
    *,
    version: str,
    failures: list[str],
) -> dict[str, Any]:
    source_status: dict[str, Any] = {}
    source_path = workspace.rest / "ct" / "source-status.json"
    if source_path.is_file():
        try:
            loaded = json.loads(source_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(loaded, dict):
                source_status = loaded
        except (OSError, json.JSONDecodeError):
            pass
    tenant_path = workspace.rest / "tenant-domains" / "status.json"
    if tenant_path.is_file():
        try:
            tenant_targets = json.loads(
                tenant_path.read_text(encoding="utf-8", errors="replace")
            )
            if isinstance(tenant_targets, dict):
                target_rows = [
                    row for row in tenant_targets.values() if isinstance(row, dict)
                ]
                target_errors = [
                    row for row in target_rows if row.get("status") == "error"
                ]
                target_successes = [
                    row for row in target_rows if row.get("status") != "error"
                ]
                if target_errors and target_successes:
                    tenant_state = "partial"
                elif target_errors:
                    tenant_state = "error"
                elif any(row.get("status") == "ok" for row in target_rows):
                    tenant_state = "ok"
                else:
                    tenant_state = "empty"
                related = sum(int(row.get("related_domains", 0)) for row in target_rows)
                tenant_summary: dict[str, Any] = {
                    "status": tenant_state,
                    "retrieved": related,
                    "added": related,
                    "targets": tenant_targets,
                }
                if target_errors:
                    tenant_summary["error"] = "; ".join(
                        f"{root}: {row.get('diagnostic') or 'adapter error'}"
                        for root, row in tenant_targets.items()
                        if isinstance(row, dict) and row.get("status") == "error"
                    )
                source_status["tenant-domains"] = tenant_summary
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            pass
    provider_status: dict[str, Any] = {}
    provider_path = workspace.rest / "api" / "provider-status.json"
    if provider_path.is_file():
        try:
            loaded = json.loads(provider_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(loaded, dict):
                provider_status = loaded
        except (OSError, json.JSONDecodeError):
            pass
    origin_discovery: dict[str, Any] = {}
    origin_path = workspace.rest / "origin" / "final-ranking.json"
    if origin_path.is_file():
        try:
            loaded_origin = json.loads(origin_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(loaded_origin, dict):
                origin_discovery = loaded_origin
        except (OSError, json.JSONDecodeError):
            pass
    provider_issues = [
        f"{name}: {status.get('error') or status.get('status')}"
        for name, status in sorted(provider_status.items())
        if isinstance(status, dict) and status.get("status") == "error"
    ]
    source_issues = [
        f"{name}: {status.get('error') or status.get('status')}"
        for name, status in sorted(source_status.items())
        if isinstance(status, dict) and status.get("status") in {"error", "partial"}
    ]
    data = {
        "tool": "cachaza",
        "version": version,
        "generated_at": utc_now(),
        "scope": target.to_dict(),
        "scope_policy": {
            "passive_by_default": True,
            "derived_networks_are_candidates": True,
            "note": (
                "ASN and prefixes inferred from a domain identify current network operators; "
                "they do not automatically become authorized active-scan scope."
            ),
        },
        "counts": workspace.counts(),
        "network_intelligence": {
            "asns": _aggregate(workspace, "asn"),
            "organizations": _aggregate(workspace, "organization"),
            "prefixes": _aggregate(workspace, "cidr"),
            "resolved_ips": _aggregate(workspace, "ip"),
            "registrations": _aggregate(workspace, "network_registration"),
        },
        "stages": [stage.to_dict() for stage in workspace.stages],
        "failures": list(failures),
        "issues": list(failures) + source_issues + provider_issues,
        "source_status": source_status,
        "provider_status": provider_status,
        "origin_discovery": origin_discovery,
        "findings": [finding.to_dict() for finding in workspace.findings],
    }
    data["subdomain_summary"] = build_subdomain_summary(data["findings"])
    data["key_findings"] = build_key_findings(data["findings"])
    data["graph"] = _build_graph(data)
    return data


def _evidence_value(entry: dict[str, Any], *keys: str) -> str:
    values: list[str] = []
    for metadata in entry.get("evidence", []):
        for key in keys:
            raw = metadata.get(key)
            if isinstance(raw, bool):
                value = "yes" if raw else "no"
            elif isinstance(raw, list):
                value = ", ".join(str(item).strip() for item in raw if str(item).strip())
            elif raw is not None:
                value = str(raw).strip()
            else:
                value = ""
            if value and value not in values:
                values.append(value)
    return ", ".join(values)


def _render_txt(data: dict[str, Any], *, color: bool = True) -> str:
    """Render a detailed terminal-friendly report, optionally with ANSI colors."""

    def paint(value: Any, code: str) -> str:
        text = str(value)
        return f"\x1b[{code}m{text}\x1b[0m" if color else text

    def section(title: str) -> None:
        lines.extend(["", paint(title, "1;34"), paint("-" * len(title), "34")])

    def scope_label(in_scope: bool) -> str:
        return paint("AUTHORIZED", "1;32") if in_scope else paint("CANDIDATE", "1;33")

    def metadata_text(metadata: dict[str, Any]) -> str:
        values: list[str] = []
        for key, raw in sorted(metadata.items()):
            if raw is None or raw == "" or raw == []:
                continue
            if isinstance(raw, (dict, list)):
                rendered = json.dumps(raw, ensure_ascii=False, sort_keys=True)
            elif isinstance(raw, bool):
                rendered = "yes" if raw else "no"
            else:
                rendered = str(raw)
            values.append(f"{key}={rendered}")
        return " | ".join(values)

    findings = data.get("findings", [])
    sources = sorted({str(item.get("source", "unknown")) for item in findings})
    authorized = sum(1 for item in findings if item.get("in_scope"))
    candidates = len(findings) - authorized
    stage_counts: dict[str, int] = {}
    for stage in data.get("stages", []):
        status = str(stage.get("status") or "unknown")
        stage_counts[status] = stage_counts.get(status, 0) + 1

    title = "CACHAZA RECONNAISSANCE REPORT"
    lines = [
        paint(title, "1;36"),
        paint("=" * len(title), "36"),
        f"{paint('Generated', '1')}: {data['generated_at']}",
        f"{paint('Version', '1')}:   {data['version']}",
    ]

    section("EXECUTIVE SUMMARY")
    lines.extend(
        [
            f"Total evidence records : {paint(len(findings), '1;36')}",
            f"Authorized / candidate : {paint(authorized, '1;32')} / {paint(candidates, '1;33')}",
            f"Unique evidence sources: {len(sources)} ({', '.join(sources) or '-'})",
            "Stage status           : "
            + (", ".join(f"{key}={value}" for key, value in sorted(stage_counts.items())) or "not run"),
            f"Collection failures     : {paint(len(data.get('failures', [])), '1;31' if data.get('failures') else '32')}",
        ]
    )

    section("AUTHORIZED SCOPE")
    scope = data["scope"]
    scope_labels = {
        "domains": "Domains",
        "asns": "ASNs",
        "organizations": "Organizations",
        "cidrs": "CIDRs",
        "exclude_domains": "Excluded domains",
        "exclude_cidrs": "Excluded CIDRs",
    }
    for key, label in scope_labels.items():
        lines.append(f"{label:<18}: {', '.join(scope.get(key, [])) or '-'}")

    lines.append(
        render_key_findings_console(
            data["key_findings"],
            subdomain_summary=data.get("subdomain_summary"),
            color=color,
        )
    )

    if data.get("origin_discovery"):
        origin = data["origin_discovery"]
        section("AUTOMATIC ORIGIN DISCOVERY")
        lines.extend(
            [
                f"Status                         : {origin.get('status', 'unknown')}",
                f"Mode                           : {origin.get('mode', 'unknown')}",
                f"CDN/WAF detected               : {origin.get('cdn_waf_detected', {}).get('provider', 'Unknown')}",
                f"Candidates collected           : {origin.get('candidates_collected', 0)}",
                f"Rejected before validation     : {origin.get('candidates_rejected_before_validation', 0)}",
                f"Actively validated             : {origin.get('candidates_actively_validated', 0)}",
                f"Direct requests performed      : {origin.get('direct_requests_performed', 0)}",
                f"Highest-confidence candidate   : {origin.get('highest_confidence_candidate') or 'none'}",
                f"Confidence score               : {origin.get('confidence_score', 0)}/100",
                f"Classification                 : {origin.get('classification', 'inconclusive')}",
                "Manual confirmation recommended: yes",
            ]
        )
        if origin.get("message"):
            lines.append(str(origin["message"]))
        lines.append(str(origin.get("warning") or ""))

    section("EXTERNAL SOURCE STATUS")
    if data.get("source_status"):
        for source, status in sorted(data["source_status"].items()):
            details = status if isinstance(status, dict) else {}
            rendered = str(details.get("status") or "unknown")
            retrieved = details.get("retrieved", 0)
            added = details.get("added", 0)
            error = str(details.get("error") or "").strip()
            lines.append(
                f"{source:<16}: {rendered} | retrieved={retrieved} | new={added}"
                + (f" | {error}" if error else "")
            )
    else:
        lines.append("No external CT source status was recorded.")

    section("PROVIDER EXECUTION STATUS")
    if data.get("provider_status"):
        for provider, status in sorted(data["provider_status"].items()):
            details = status if isinstance(status, dict) else {}
            rendered = str(details.get("status") or "unknown")
            findings_count = details.get("findings", 0)
            error = str(details.get("error") or "").strip()
            lines.append(f"{provider:<16}: {rendered} | findings={findings_count}" + (f" | {error}" if error else ""))
    else:
        lines.append("No native provider request status was recorded.")

    section("INVENTORY COUNTS")
    if data["counts"]:
        width = max(len(kind) for kind in data["counts"])
        lines.extend(
            f"{kind:<{width}} : {paint(count, '1;36')}"
            for kind, count in data["counts"].items()
        )
    else:
        lines.append("No findings.")

    network = data["network_intelligence"]
    section("NETWORK INTELLIGENCE")
    lines.append(paint(f"ASNs ({len(network['asns'])})", "1"))
    if network["asns"]:
        for entry in network["asns"]:
            holder = _evidence_value(entry, "holder", "as_name") or "unknown"
            announced = _evidence_value(entry, "announced") or "unknown"
            lines.append(
                f"  {paint(entry['value'], '1;36')} [{scope_label(entry['in_scope'])}] "
                f"holder={holder} | announced={announced} | sources={','.join(entry['sources'])}"
            )
    else:
        lines.append("  No ASN findings.")

    lines.append(paint(f"Organizations ({len(network['organizations'])})", "1"))
    if network["organizations"]:
        for entry in network["organizations"]:
            asn = _evidence_value(entry, "asn") or "-"
            lines.append(
                f"  {entry['value']} | asn={asn} | sources={','.join(entry['sources'])}"
            )
    else:
        lines.append("  No organization findings.")

    lines.append(paint(f"Prefixes ({len(network['prefixes'])})", "1"))
    if network["prefixes"]:
        for entry in network["prefixes"]:
            asn = _evidence_value(entry, "asn", "asns") or "-"
            lines.append(
                f"  {paint(entry['value'], '36')} [{scope_label(entry['in_scope'])}] "
                f"asn={asn} | sources={','.join(entry['sources'])}"
            )
    else:
        lines.append("  No prefix findings.")

    lines.append(paint(f"Resolved IPs ({len(network['resolved_ips'])})", "1"))
    if network["resolved_ips"]:
        for entry in network["resolved_ips"]:
            asn = _evidence_value(entry, "asn", "asns") or "-"
            lines.append(
                f"  {paint(entry['value'], '36')} [{scope_label(entry['in_scope'])}] "
                f"asn={asn} | sources={','.join(entry['sources'])}"
            )
    else:
        lines.append("  No resolved addresses.")

    lines.append(paint(f"Registry records ({len(network['registrations'])})", "1"))
    if network["registrations"]:
        for entry in network["registrations"]:
            handle = _evidence_value(entry, "handle") or "-"
            allocation = _evidence_value(entry, "start_address", "end_address") or "-"
            lines.append(
                f"  {entry['value']} | handle={handle} | allocation={allocation} | "
                f"sources={','.join(entry['sources'])}"
            )
    else:
        lines.append("  No registry records.")

    section("WEB AND TECHNOLOGY ASSETS")
    for kind, label in (
        ("domain", "Domains"),
        ("url", "URLs"),
        ("service", "Services"),
        ("technology", "Technologies"),
        ("cloud_asset", "Cloud classifications"),
    ):
        items = sorted(
            {str(item["value"]) for item in findings if item.get("kind") == kind}
        )
        lines.append(f"{paint(label, '1')} ({len(items)}): {', '.join(items) or '-'}")

    section("EXECUTION STAGES")
    if data["stages"]:
        status_colors = {
            "completed": "1;32",
            "failed": "1;31",
            "interrupted": "1;31",
            "running": "1;36",
        }
        for stage in data["stages"]:
            status = str(stage["status"])
            detail = f" | {stage['details']}" if stage.get("details") else ""
            timing = ""
            if stage.get("started_at") or stage.get("finished_at"):
                timing = f" | {stage.get('started_at') or '?'} -> {stage.get('finished_at') or '?'}"
            lines.append(
                f"{stage['name']:<14} {paint(status.upper(), status_colors.get(status, '1;33'))}{detail}{timing}"
            )
    else:
        lines.append("No execution stages recorded.")

    section("DETAILED EVIDENCE")
    if findings:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            grouped.setdefault(str(finding.get("kind") or "unknown"), []).append(finding)
        for kind in sorted(grouped):
            entries = sorted(
                grouped[kind],
                key=lambda item: (str(item.get("value", "")), str(item.get("source", ""))),
            )
            lines.append(paint(f"{kind.upper()} ({len(entries)})", "1;35"))
            for item in entries:
                lines.append(
                    f"  - {paint(item.get('value', ''), '1')} [{scope_label(bool(item.get('in_scope')))}]"
                )
                lines.append(
                    f"    stage={item.get('stage', '-')} | source={item.get('source', '-')} | "
                    f"observed={item.get('observed_at', '-')}"
                )
                metadata = item.get("metadata")
                if isinstance(metadata, dict) and metadata:
                    lines.append(f"    evidence: {metadata_text(metadata)}")
    else:
        lines.append("No evidence records.")

    if data["failures"]:
        section("FAILURES")
        lines.extend(f"{paint('ERROR', '1;31')} {failure}" for failure in data["failures"])

    section("SAFETY AND PROVENANCE")
    lines.extend(
        [
            paint(data["scope_policy"]["note"], "1;33"),
            "Full structured evidence is available in report.json/report.csv; raw and intermediate "
            "artifacts are stored under rest/.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_csv(data: dict[str, Any]) -> str:
    """Export one normalized row per finding for filtering and spreadsheet use."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("observed_at", "stage", "source", "kind", "value", "scope", "metadata_json"))
    for finding in sorted(
        data.get("findings", []),
        key=lambda item: (
            str(item.get("kind", "")),
            str(item.get("value", "")),
            str(item.get("source", "")),
        ),
    ):
        writer.writerow(
            tuple(
                _csv_safe_cell(value)
                for value in (
                    finding.get("observed_at", ""),
                    finding.get("stage", ""),
                    finding.get("source", ""),
                    finding.get("kind", ""),
                    finding.get("value", ""),
                    "authorized" if finding.get("in_scope") else "candidate",
                    json.dumps(
                        finding.get("metadata") or {},
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                )
            )
        )
    return output.getvalue()


def _html_table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{html_escape(value)}</th>" for value in headers)
    if rows:
        body = "".join(
            "<tr>" + "".join(f"<td>{html_escape(str(value))}</td>" for value in row) + "</tr>"
            for row in rows
        )
    else:
        body = f'<tr><td colspan="{len(headers)}" class="empty">No findings</td></tr>'
    return f"<div class=\"table-wrap\"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _render_html_legacy(data: dict[str, Any]) -> str:
    network = data["network_intelligence"]
    asn_rows = [
        [
            item["value"],
            _evidence_value(item, "holder", "as_name") or "Unknown",
            _evidence_value(item, "announced") or "Unknown",
            "Authorized" if item["in_scope"] else "Candidate",
            ", ".join(item["sources"]),
        ]
        for item in network["asns"]
    ]
    org_rows = [
        [item["value"], _evidence_value(item, "asn") or "-", ", ".join(item["sources"])]
        for item in network["organizations"]
    ]
    prefix_rows = [
        [
            item["value"],
            _evidence_value(item, "asn") or "-",
            "Authorized" if item["in_scope"] else "Candidate",
            ", ".join(item["sources"]),
        ]
        for item in network["prefixes"]
    ]
    ip_rows = [
        [item["value"], _evidence_value(item, "asn", "asns") or "-", ", ".join(item["sources"])]
        for item in network["resolved_ips"]
    ]
    registration_rows = [
        [
            item["value"],
            _evidence_value(item, "handle") or "-",
            _evidence_value(item, "start_address", "end_address") or "-",
            ", ".join(item["sources"]),
        ]
        for item in network["registrations"]
    ]
    stage_rows = [
        [item["name"], item["status"], item.get("details", "")] for item in data["stages"]
    ]
    counts = "".join(
        f'<div class="stat"><span>{html_escape(str(count))}</span>{html_escape(kind)}</div>'
        for kind, count in data["counts"].items()
    ) or '<div class="stat"><span>0</span>findings</div>'
    domains = ", ".join(data["scope"].get("domains", [])) or "No domains supplied"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>Cachaza report</title><style>
:root{{--bg:#07111f;--panel:#0e1b2d;--line:#253750;--text:#e8f0fa;--muted:#9db0c8;--accent:#53d3a4;--blue:#63a8ff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,Segoe UI,Arial,sans-serif}}
main{{max-width:1180px;margin:auto;padding:38px 24px 70px}}header{{border:1px solid var(--line);border-radius:18px;padding:30px;background:linear-gradient(135deg,#112641,#0c1b2d)}}
h1{{margin:0;font-size:34px;letter-spacing:.02em}}h2{{margin:34px 0 12px;font-size:20px}}.eyebrow{{color:var(--accent);font-weight:700;text-transform:uppercase;letter-spacing:.14em}}
.muted{{color:var(--muted)}}.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}}.stat{{min-width:120px;padding:13px 16px;border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--muted)}}
.stat span{{display:block;color:var(--text);font-size:24px;font-weight:750}}.callout{{border-left:4px solid var(--accent);padding:12px 16px;background:#0d201f;border-radius:5px;margin:20px 0}}
.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:12px}}table{{width:100%;border-collapse:collapse;background:var(--panel)}}th,td{{padding:12px 14px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.08em}}tr:last-child td{{border-bottom:0}}.empty{{color:var(--muted)}}code{{color:var(--accent)}}
</style></head><body><main>
<header><div class="eyebrow">Passive-first reconnaissance</div><h1>Cachaza</h1>
<p>{html_escape(domains)}</p><p class="muted">Generated {html_escape(data['generated_at'])} · version {html_escape(data['version'])}</p>
<div class="stats">{counts}</div></header>
<div class="callout"><strong>Scope guard:</strong> {html_escape(data['scope_policy']['note'])}</div>
<h2>ASN intelligence</h2>{_html_table(['ASN','Holder','Announced','Scope','Sources'], asn_rows)}
<h2>Network organizations</h2>{_html_table(['Organization','ASN','Sources'], org_rows)}
<h2>Prefixes</h2>{_html_table(['Prefix','ASN','Scope','Sources'], prefix_rows)}
<h2>Resolved addresses</h2>{_html_table(['IP','ASN','Sources'], ip_rows)}
<h2>Network registrations</h2>{_html_table(['Name','Handle','Allocation','Sources'], registration_rows)}
<h2>Stages</h2>{_html_table(['Stage','Status','Details'], stage_rows)}
</main></body></html>"""


def _pdf_text(value: Any) -> str:
    return xml_escape("-" if value is None or value == "" else str(value))


def _write_pdf(path: Path, data: dict[str, Any]) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_RIGHT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            LongTable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - packaging installs this dependency
        raise RuntimeError("PDF output requires reportlab; reinstall Cachaza with pipx install --force .") from exc

    palette = {
        "navy": colors.HexColor("#0B1E33"),
        "blue": colors.HexColor("#246BCE"),
        "green": colors.HexColor("#21A179"),
        "line": colors.HexColor("#CBD6E4"),
        "soft": colors.HexColor("#EEF3F8"),
        "muted": colors.HexColor("#52657A"),
        "red": colors.HexColor("#C73E4D"),
        "amber": colors.HexColor("#D78B20"),
        "white": colors.white,
    }
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=27, leading=31, textColor=palette["navy"], spaceAfter=4))
    styles.add(ParagraphStyle(name="Kicker", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=palette["green"], spaceAfter=6))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=palette["navy"], spaceBefore=13, spaceAfter=7))
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["BodyText"], fontSize=8.5, leading=11, textColor=palette["muted"]))
    styles.add(ParagraphStyle(name="Cell", parent=styles["BodyText"], fontSize=7.5, leading=9.5, textColor=palette["navy"]))
    styles.add(ParagraphStyle(name="CellHead", parent=styles["Cell"], fontName="Helvetica-Bold", textColor=colors.white))
    styles.add(ParagraphStyle(name="Footer", parent=styles["BodySmall"], fontSize=7, alignment=TA_RIGHT))
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["ReportTitle"], fontSize=28, leading=31, textColor=colors.white, spaceAfter=3))
    styles.add(ParagraphStyle(name="CoverBody", parent=styles["BodySmall"], textColor=colors.HexColor("#D9E6F3"), leading=12))
    styles.add(ParagraphStyle(name="Metric", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=18, leading=20, alignment=TA_CENTER, textColor=palette["blue"]))
    styles.add(ParagraphStyle(name="MetricLabel", parent=styles["BodySmall"], fontSize=7, leading=9, alignment=TA_CENTER, textColor=palette["muted"]))
    styles.add(ParagraphStyle(name="Warning", parent=styles["BodySmall"], fontName="Helvetica-Bold", textColor=palette["red"]))

    document = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=16 * mm,
        leftMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=17 * mm,
        title="Cachaza reconnaissance report",
        author="Cachaza",
    )

    def page(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        canvas.setFillColor(palette["blue"])
        canvas.rect(16 * mm, A4[1] - 10 * mm, A4[0] - 32 * mm, 1.2 * mm, fill=1, stroke=0)
        canvas.setStrokeColor(palette["line"])
        canvas.line(16 * mm, 12 * mm, A4[0] - 16 * mm, 12 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(palette["muted"])
        canvas.drawString(16 * mm, 8 * mm, "Cachaza - passive-first reconnaissance")
        canvas.drawRightString(A4[0] - 16 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()

    def p(value: Any, style: str = "Cell") -> Any:
        return Paragraph(_pdf_text(value), styles[style])

    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), palette["navy"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, palette["line"]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, palette["soft"]]),
        ]
    )
    domains = ", ".join(data["scope"].get("domains", [])) or "No domains supplied"
    cover = Table(
        [[
            [
                Paragraph("PASSIVE-FIRST OSINT &amp; AUTHORIZED RECONNAISSANCE", styles["CoverBody"]),
                Paragraph("Cachaza", styles["CoverTitle"]),
                Paragraph(_pdf_text(domains), styles["CoverBody"]),
            ],
            [
                Paragraph(f"<b>VERSION</b><br/>{_pdf_text(data['version'])}", styles["CoverBody"]),
                Spacer(1, 2 * mm),
                Paragraph(f"<b>GENERATED</b><br/>{_pdf_text(data['generated_at'])}", styles["CoverBody"]),
            ],
        ]],
        colWidths=[112 * mm, 53 * mm],
        style=TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), palette["navy"]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 15),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 15),
                ("LINEBEFORE", (1, 0), (1, 0), 0.6, colors.HexColor("#41617E")),
            ]
        ),
    )
    findings = data.get("findings", [])
    sources = {str(item.get("source") or "unknown") for item in findings}
    key_findings = data.get("key_findings", {})
    metrics = (
        (len(findings), "EVIDENCE RECORDS"),
        (len(key_findings.get("subdomains", [])), "ACTIONABLE SUBDOMAINS"),
        (len(sources), "EVIDENCE SOURCES"),
        (len(data.get("issues", data.get("failures", []))), "RUN ISSUES"),
    )
    metric_cells = [
        [Paragraph(str(value), styles["Metric"]), Paragraph(label, styles["MetricLabel"])]
        for value, label in metrics
    ]
    metric_table = Table(
        [metric_cells],
        colWidths=[41.25 * mm] * 4,
        style=TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), palette["soft"]),
                ("BOX", (0, 0), (-1, -1), 0.5, palette["line"]),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, palette["line"]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ]
        ),
    )
    key_rows = [[p("Category", "CellHead"), p("Count", "CellHead"), p("Highlights", "CellHead")]]
    for key, label in KEY_FINDING_LABELS:
        values = list(key_findings.get(key, []))
        limit = 13 if key == "subdomains" else 8
        rendered = ", ".join(values[:limit]) or (
            "No evidence observed" if key == "wafs" else "-"
        )
        if len(values) > limit:
            rendered += f" (+{len(values) - limit} more in structured reports)"
        if key == "zone_transfer_allowed":
            rendered = "ALLOWED: " + rendered if values else "Not observed"
        key_rows.append([p(label), p(len(values)), p(rendered)])
    key_style = TableStyle(list(table_style.getCommands()))
    if key_findings.get("zone_transfer_allowed"):
        key_style.add("BACKGROUND", (0, len(key_rows) - 1), (-1, len(key_rows) - 1), colors.HexColor("#FDE8EA"))
        key_style.add("TEXTCOLOR", (0, len(key_rows) - 1), (-1, len(key_rows) - 1), palette["red"])

    scope_rows = [[p("Scope type", "CellHead"), p("Explicit values", "CellHead")]]
    for key, label in (
        ("domains", "Domains"),
        ("asns", "ASNs"),
        ("organizations", "Organizations"),
        ("cidrs", "CIDRs"),
        ("exclude_domains", "Excluded domains"),
        ("exclude_cidrs", "Excluded CIDRs"),
    ):
        scope_rows.append([p(label), p(", ".join(data["scope"].get(key, [])) or "-")])

    origin_story: list[Any] = []
    origin = data.get("origin_discovery", {})
    if origin:
        origin_rows = [[p("Metric", "CellHead"), p("Result", "CellHead")]]
        for label, value in (
            ("Mode", origin.get("mode", "unknown")),
            ("CDN/WAF", origin.get("cdn_waf_detected", {}).get("provider", "Unknown")),
            ("Candidates", origin.get("candidates_collected", 0)),
            ("Actively validated", origin.get("candidates_actively_validated", 0)),
            ("Direct requests", origin.get("direct_requests_performed", 0)),
            ("Highest-confidence candidate", origin.get("highest_confidence_candidate") or "none"),
            ("Confidence", f"{origin.get('confidence_score', 0)}/100"),
            ("Classification", origin.get("classification", "inconclusive")),
        ):
            origin_rows.append([p(label), p(value)])
        origin_story = [
            Paragraph("Automatic Origin discovery", styles["Section"]),
            Table(origin_rows, colWidths=[70 * mm, 95 * mm], repeatRows=1, style=table_style),
            Paragraph(_pdf_text(origin.get("warning", "")), styles["Warning"]),
        ]

    story: list[Any] = [
        cover,
        Spacer(1, 5 * mm),
        metric_table,
        Paragraph("Executive key findings", styles["Section"]),
        LongTable(key_rows, colWidths=[48 * mm, 17 * mm, 100 * mm], repeatRows=1, style=key_style),
        *origin_story,
        Paragraph("Authorized scope", styles["Section"]),
        Table(scope_rows, colWidths=[48 * mm, 117 * mm], repeatRows=1, style=table_style),
        Spacer(1, 3 * mm),
        Paragraph(_pdf_text(data["scope_policy"]["note"]), styles["BodySmall"]),
        PageBreak(),
        Paragraph("Infrastructure intelligence", styles["ReportTitle"]),
        Paragraph("ASN intelligence", styles["Section"]),
    ]

    network = data["network_intelligence"]
    asn_rows = [[p(value, "CellHead") for value in ("ASN", "Holder", "Announced", "Scope", "Sources")]]
    for item in network["asns"]:
        asn_rows.append(
            [
                p(item["value"]),
                p(_evidence_value(item, "holder", "as_name") or "Unknown"),
                p(_evidence_value(item, "announced") or "Unknown"),
                p("Authorized" if item["in_scope"] else "Candidate"),
                p(", ".join(item["sources"])),
            ]
        )
    if len(asn_rows) == 1:
        asn_rows.append([p("No ASN findings"), p("-"), p("-"), p("-"), p("-")])
    story.append(LongTable(asn_rows, colWidths=[22 * mm, 53 * mm, 22 * mm, 24 * mm, 44 * mm], repeatRows=1, style=table_style))

    story.append(Paragraph("Network organizations", styles["Section"]))
    org_rows = [[p(value, "CellHead") for value in ("Organization", "ASN", "Sources")]]
    for item in network["organizations"]:
        org_rows.append([p(item["value"]), p(_evidence_value(item, "asn") or "-"), p(", ".join(item["sources"]))])
    if len(org_rows) == 1:
        org_rows.append([p("No organization findings"), p("-"), p("-")])
    story.append(LongTable(org_rows, colWidths=[80 * mm, 30 * mm, 55 * mm], repeatRows=1, style=table_style))

    story.append(Paragraph("Prefixes", styles["Section"]))
    prefix_rows = [[p(value, "CellHead") for value in ("Prefix", "ASN", "Scope", "Sources")]]
    for item in network["prefixes"]:
        prefix_rows.append(
            [
                p(item["value"]),
                p(_evidence_value(item, "asn") or "-"),
                p("Authorized" if item["in_scope"] else "Candidate"),
                p(", ".join(item["sources"])),
            ]
        )
    if len(prefix_rows) == 1:
        prefix_rows.append([p("No prefix findings"), p("-"), p("-"), p("-")])
    story.append(LongTable(prefix_rows, colWidths=[48 * mm, 28 * mm, 32 * mm, 57 * mm], repeatRows=1, style=table_style))

    story.extend([PageBreak(), Paragraph("Address and execution detail", styles["ReportTitle"]), Paragraph("Resolved addresses", styles["Section"])])
    ip_rows = [[p(value, "CellHead") for value in ("IP", "ASN", "Sources")]]
    for item in network["resolved_ips"]:
        ip_rows.append(
            [
                p(item["value"]),
                p(_evidence_value(item, "asn", "asns") or "-"),
                p(", ".join(item["sources"])),
            ]
        )
    if len(ip_rows) == 1:
        ip_rows.append([p("No resolved addresses"), p("-"), p("-")])
    story.append(LongTable(ip_rows, colWidths=[55 * mm, 38 * mm, 72 * mm], repeatRows=1, style=table_style))

    story.append(Paragraph("Network registrations", styles["Section"]))
    registration_rows = [[p(value, "CellHead") for value in ("Name", "Handle", "Allocation")]]
    for item in network["registrations"]:
        registration_rows.append(
            [
                p(item["value"]),
                p(_evidence_value(item, "handle") or "-"),
                p(_evidence_value(item, "start_address", "end_address") or "-"),
            ]
        )
    if len(registration_rows) == 1:
        registration_rows.append([p("No registry records"), p("-"), p("-")])
    story.append(LongTable(registration_rows, colWidths=[50 * mm, 52 * mm, 63 * mm], repeatRows=1, style=table_style))

    story.append(Paragraph("Execution stages", styles["Section"]))
    stage_rows = [[p(value, "CellHead") for value in ("Stage", "Status", "Details")]]
    stage_rows.extend([[p(item["name"]), p(item["status"]), p(item.get("details", ""))] for item in data["stages"]])
    story.append(LongTable(stage_rows, colWidths=[35 * mm, 30 * mm, 100 * mm], repeatRows=1, style=table_style))

    source_rows = [
        [p(value, "CellHead") for value in ("External source", "Status", "Retrieved", "New", "Diagnostic")]
    ]
    for source, status in sorted(data.get("source_status", {}).items()):
        if not isinstance(status, dict):
            continue
        source_rows.append(
            [
                p(source),
                p(status.get("status", "unknown")),
                p(status.get("retrieved", 0)),
                p(status.get("added", 0)),
                p(status.get("error") or "-"),
            ]
        )
    if len(source_rows) > 1:
        story.append(Paragraph("External source status", styles["Section"]))
        story.append(
            LongTable(
                source_rows,
                colWidths=[32 * mm, 23 * mm, 20 * mm, 17 * mm, 73 * mm],
                repeatRows=1,
                style=table_style,
            )
        )

    provider_rows = [
        [p(value, "CellHead") for value in ("Provider", "Status", "Findings", "Diagnostic")]
    ]
    for provider, status in sorted(data.get("provider_status", {}).items()):
        if not isinstance(status, dict):
            continue
        provider_rows.append(
            [
                p(provider),
                p(status.get("status", "unknown")),
                p(status.get("findings", 0)),
                p(status.get("error") or "-"),
            ]
        )
    if len(provider_rows) > 1:
        story.append(Paragraph("Provider execution status", styles["Section"]))
        story.append(
            LongTable(
                provider_rows,
                colWidths=[32 * mm, 25 * mm, 22 * mm, 86 * mm],
                repeatRows=1,
                style=table_style,
            )
        )

    inventory_rows = [[p("Type", "CellHead"), p("Count", "CellHead")]]
    inventory_rows.extend([[p(kind), p(count)] for kind, count in data["counts"].items()])
    if len(inventory_rows) == 1:
        inventory_rows.append([p("findings"), p("0")])
    story.extend(
        [
            Paragraph("Normalized inventory", styles["Section"]),
            Table(inventory_rows, colWidths=[125 * mm, 40 * mm], repeatRows=1, style=table_style),
            PageBreak(),
            Paragraph("Evidence appendix", styles["ReportTitle"]),
            Paragraph(
                "Normalized evidence with source and scope. Metadata is summarized here; full, lossless records remain in report.json and rest/findings.jsonl.",
                styles["BodySmall"],
            ),
            Spacer(1, 3 * mm),
        ]
    )
    evidence_rows = [[p(value, "CellHead") for value in ("Type", "Value", "Source", "Scope", "Metadata")]]
    actionable_domains = {
        str(value).casefold()
        for value in data.get("subdomain_summary", {}).get("actionable", [])
    }
    root_domains = {
        str(value).casefold() for value in data.get("scope", {}).get("domains", [])
    }
    omitted_waf_banners = sum(_is_waf_banner_false_positive(item) for item in findings)
    report_findings = [
        item
        for item in findings
        if not _is_waf_banner_false_positive(item)
        and not (
                str(item.get("source") or "") in NOISY_DNS_ENUM_SOURCES
                and (
                    item.get("kind") == "ip"
                    or (
                        item.get("kind") == "domain"
                        and str(item.get("value") or "").casefold()
                        not in actionable_domains | root_domains
                    )
                )
            )
    ]
    omitted_noisy = len(findings) - len(report_findings)
    omitted_dns_enumeration = omitted_noisy - omitted_waf_banners
    sorted_findings = sorted(
        report_findings,
        key=lambda item: (
            str(item.get("kind", "")),
            str(item.get("value", "")),
            str(item.get("source", "")),
        ),
    )
    for item in sorted_findings[:PDF_EVIDENCE_LIMIT]:
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        summary = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if len(summary) > 420:
            summary = summary[:417] + "..."
        evidence_rows.append(
            [
                p(item.get("kind", "finding")),
                p(item.get("value", "-")),
                p(item.get("source", "unknown")),
                p("In scope" if item.get("in_scope") else "Contextual"),
                p(summary or "-"),
            ]
        )
    if len(evidence_rows) == 1:
        evidence_rows.append([p("-"), p("No evidence"), p("-"), p("-"), p("-")])
    story.append(
        LongTable(
            evidence_rows,
            colWidths=[22 * mm, 49 * mm, 28 * mm, 22 * mm, 44 * mm],
            repeatRows=1,
            style=table_style,
        )
    )
    if len(sorted_findings) > PDF_EVIDENCE_LIMIT or omitted_noisy:
        details = []
        if len(sorted_findings) > PDF_EVIDENCE_LIMIT:
            details.append(
                f"appendix limited to {PDF_EVIDENCE_LIMIT} of {len(sorted_findings)} reportable records"
            )
        if omitted_dns_enumeration:
            details.append(
                f"{omitted_dns_enumeration} unverified dnsenum/Fierce records omitted as noise"
            )
        if omitted_waf_banners:
            details.append(
                f"{omitted_waf_banners} wafw00f banner false positives omitted"
            )
        story.append(
            Paragraph(
                "PDF "
                + "; ".join(details)
                + "; consult JSON/CSV for the complete evidence set.",
                styles["Warning"],
            )
        )
    story.extend(
        [
            Paragraph("Report provenance", styles["Section"]),
            Paragraph(
                _pdf_text(
                    "Full per-finding provenance and metadata are preserved in report.json and rest/findings.jsonl. "
                    f"Generated {data['generated_at']} with Cachaza {data['version']}."
                ),
                styles["BodySmall"],
            ),
        ]
    )
    document.build(story, onFirstPage=page, onLaterPages=page)


def export_reports(
    workspace: RunWorkspace,
    target: TargetSpec,
    formats: list[str],
    *,
    version: str,
    failures: list[str],
    txt_color: bool = True,
) -> list[Path]:
    data = build_report_data(workspace, target, version=version, failures=failures)
    paths: list[Path] = []
    for report_format in formats:
        path = workspace.root / f"report.{report_format}"
        if report_format == "json":
            workspace.write_report_json(path.name, data)
        elif report_format == "txt":
            workspace.write_report_text(path.name, _render_txt(data, color=txt_color))
        elif report_format == "html":
            workspace.write_report_text(path.name, render_html(data))
        elif report_format == "pdf":
            _write_pdf(path, data)
        elif report_format == "csv":
            workspace.write_report_text(path.name, _render_csv(data))
        else:  # validated by the CLI; protects direct API use
            raise ValueError(f"unsupported report format: {report_format}")
        paths.append(path)
    return paths
