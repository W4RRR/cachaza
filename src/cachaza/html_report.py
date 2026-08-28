"""Interactive, self-contained HTML report renderer."""

from __future__ import annotations

import json
import re
from html import escape
from typing import Any


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


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{escape(value)}</th>" for value in headers)
    if rows:
        body = "".join(
            "<tr>" + "".join(f"<td>{escape(str(value))}</td>" for value in row) + "</tr>"
            for row in rows
        )
    else:
        body = f'<tr><td colspan="{len(headers)}" class="empty">No findings</td></tr>'
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _provider_table(statuses: dict[str, Any]) -> str:
    rows: list[str] = []
    for provider, raw in sorted(statuses.items()):
        if not isinstance(raw, dict):
            continue
        state = str(raw.get("status") or "unknown").lower()
        diagnostic = str(raw.get("action") or raw.get("error") or "-")
        rows.append(
            f'<tr class="status-row status-{escape(state)}"><td>{escape(provider)}</td>'
            f'<td><span class="status-pill {escape(state)}">{escape(state)}</span></td>'
            f'<td>{escape(str(raw.get("findings", 0)))}</td><td>{escape(diagnostic)}</td></tr>'
        )
    body = "".join(rows) or '<tr><td colspan="4" class="empty">No providers configured</td></tr>'
    return '<div class="table-wrap"><table><thead><tr><th>Provider</th><th>Status</th><th>Findings</th><th>Diagnostic / action</th></tr></thead><tbody>' + body + '</tbody></table></div>'


def _white_label_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _white_label_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_white_label_value(item) for item in value]
    if not isinstance(value, str):
        return value
    if value.casefold() == "cachaza":
        return "professional-recon-report"
    rendered = value
    for pattern, replacement in (
        (r"Cachaza Direct-origin validator", "Direct-origin validator"),
        (r"Cachaza reporting engine", "Reporting engine"),
        (r"Cachaza's normalized evidence", "The report's normalized evidence"),
        (r"deterministic Cachaza report", "deterministic reconnaissance report"),
        (r"\bCachaza\b", "recon workflow"),
    ):
        rendered = re.sub(pattern, replacement, rendered, flags=re.IGNORECASE)
    return rendered


def render_html(data: dict[str, Any]) -> str:
    """Render every finding plus a relationship graph without external assets."""
    presentation = data.get("presentation", {})
    professional = bool(
        isinstance(presentation, dict) and presentation.get("mode") == "professional"
    )
    if professional:
        data = _white_label_value(data)
        presentation = data.get("presentation", {})
    report_title = str(
        presentation.get("title") if isinstance(presentation, dict) else ""
    ) or ("Professional Recon Report" if professional else "Cachaza")
    report_subject = str(
        presentation.get("subject") if isinstance(presentation, dict) else ""
    ) or ", ".join(data.get("scope", {}).get("domains", [])) or "authorized scope"
    network = data["network_intelligence"]
    origin = data.get("origin_discovery", {})
    origin_rows = []
    if isinstance(origin, dict):
        for group in ("primary", "additional", "historical", "related_infrastructure"):
            for item in origin.get(group, []) if isinstance(origin.get(group, []), list) else []:
                origin_rows.append(
                    [
                        str(item.get("ip") or "-"),
                        f"{item.get('origin_probability_percent', item.get('final_score', 0))}%",
                        str(item.get("confidence_band") or "inconclusive"),
                        str(item.get("initial_score", 0)),
                        str(item.get("final_score", 0)),
                        str(item.get("classification") or "inconclusive"),
                        group.replace("_", " "),
                        ", ".join(item.get("independent_source_families", [])),
                        ", ".join(item.get("rejection_reasons", [])),
                    ]
                )
    origin_probability_rows = (
        origin.get("candidate_probabilities", []) if isinstance(origin, dict) else []
    )
    origin_ip = (
        origin.get("origin_ip") or origin.get("highest_confidence_candidate")
        if isinstance(origin, dict)
        else None
    )
    origin_probability = int(
        origin.get("origin_probability_percent", origin.get("confidence_score", 0)) or 0
    ) if isinstance(origin, dict) else 0
    origin_ranking = ""
    if isinstance(origin_probability_rows, list) and origin_probability_rows:
        cards = []
        for item in origin_probability_rows[:20]:
            if not isinstance(item, dict):
                continue
            probability = max(0, min(100, int(item.get("origin_probability_percent", 0) or 0)))
            eligibility = "origin candidate" if item.get("eligible_origin") else "context / rejected"
            cards.append(
                '<article class="origin-rank-card">'
                f'<div class="origin-rank-head"><span class="origin-rank-number">#{escape(str(item.get("rank", "-")))}</span>'
                f'<code>{escape(str(item.get("ip") or "-"))}</code><strong>{probability}%</strong></div>'
                f'<progress max="100" value="{probability}" aria-label="Origin probability {probability} percent"></progress>'
                f'<div class="origin-rank-meta"><span>{escape(str(item.get("confidence_band") or "inconclusive"))}</span>'
                f'<span>{escape(str(item.get("classification") or "inconclusive"))}</span>'
                f'<span>{escape(eligibility)}</span></div>'
                '</article>'
            )
        origin_ranking = '<div class="origin-ranking">' + "".join(cards) + "</div>"
    origin_trace = data.get("origin_trace", {})
    trace_status = (
        str(origin_trace.get("status") or "not_available")
        if isinstance(origin_trace, dict) else "not_available"
    )
    trace_direct = trace_status == "direct_path_validated"
    trace_severity = str(origin_trace.get("severity") or "information")
    origin_hero = (
        f'<div class="origin-hero {escape(trace_severity)}">'
        '<div class="origin-identity"><span class="origin-hero-label">'
        + ("Exposed origin behind the CDN/WAF" if trace_direct else "Most likely real origin IP")
        + '</span>'
        f'<code>{escape(str(origin_ip or "Not identified"))}</code>'
        f'<span class="origin-status-chip {escape(trace_severity)}">'
        f'{escape(str(origin_trace.get("status_label") or "Attribution pending"))}</span></div>'
        f'<div class="origin-probability"><strong>{origin_probability}%</strong>'
        f'<span>{escape(str(origin.get("confidence_band", "inconclusive") if isinstance(origin, dict) else "inconclusive"))} confidence</span></div>'
        '</div>'
    )
    origin_trace_html = ""
    graph_origin_alert = ""
    if isinstance(origin_trace, dict) and origin_trace.get("origin_ip"):
        trace_steps: list[str] = []
        chain_items: list[str] = []
        for step in origin_trace.get("steps", []):
            if not isinstance(step, dict):
                continue
            step_number = str(step.get("number") or "-")
            tools = "".join(
                f'<span>{escape(str(value))}</span>'
                for value in step.get("tools", []) if str(value).strip()
            )
            compact_tools = " · ".join(
                str(value) for value in step.get("tools", [])[:2] if str(value).strip()
            )
            evidence = [str(value) for value in step.get("evidence", []) if str(value).strip()]
            evidence_html = "".join(f'<li>{escape(value)}</li>' for value in evidence[:6])
            chain_items.append(
                '<article class="origin-chain-node">'
                f'<span class="origin-chain-step">Step {escape(step_number)}</span>'
                f'<strong>{escape(str(step.get("technique") or "Origin analysis"))}</strong>'
                f'<small>{escape(compact_tools or str(step.get("tactic") or "Evidence analysis"))}</small>'
                f'<a href="#origin-step-{escape(step_number)}">View evidence</a>'
                '</article>'
                '<div class="origin-chain-link" aria-hidden="true">'
                f'<span>{escape(str(step.get("relationship") or "correlates"))}</span><b>→</b>'
                '</div>'
            )
            trace_steps.append(
                f'<article class="trace-step" id="origin-step-{escape(step_number)}">'
                f'<div class="trace-number">{escape(str(step.get("number") or "-"))}</div>'
                '<div class="trace-content">'
                f'<div class="trace-step-head"><span>{escape(str(step.get("tactic") or "Analysis"))}</span>'
                f'<strong>{escape(str(step.get("technique") or "Origin analysis"))}</strong>'
                f'<em class="trace-state {escape(str(step.get("status") or "unknown").replace(" ", "-"))}">'
                f'{escape(str(step.get("status") or "unknown"))}</em></div>'
                f'<p>{escape(str(step.get("procedure") or ""))}</p>'
                + (f'<div class="trace-tools">{tools}</div>' if tools else "")
                + (f'<ul class="trace-evidence">{evidence_html}</ul>' if evidence_html else "")
                + '</div></article>'
            )
        outcomes = origin_trace.get("origin_outcomes", []) or [{
            "ip": origin_trace.get("origin_ip"),
            "probability_percent": origin_trace.get("probability_percent", 0),
            "confidence_band": origin_trace.get("confidence_band", "inconclusive"),
        }]
        for index, outcome in enumerate(outcomes):
            if not isinstance(outcome, dict) or not outcome.get("ip"):
                continue
            if index:
                chain_items.append('<div class="origin-chain-link" aria-hidden="true"><span>alternate validated path</span><b>↗</b></div>')
            chain_items.append(
                f'<article class="origin-chain-node origin-chain-result {escape(trace_severity)}">'
                f'<span class="origin-chain-step">{"Leading" if index == 0 else "Additional"} Origin IP</span>'
                f'<code>{escape(str(outcome.get("ip")))}</code>'
                f'<strong>{escape(str(outcome.get("probability_percent") or 0))}% · '
                f'{escape(str(outcome.get("confidence_band") or "inconclusive"))}</strong>'
                f'<small>{escape(str(origin_trace.get("status_label") or "Origin candidate"))}</small>'
                '</article>'
            )
        exposure_title = (
            "HIGH-PRIORITY EXPOSURE · DIRECT ORIGIN PATH VALIDATED"
            if trace_direct else "ORIGIN ATTRIBUTION · VALIDATION STATUS REQUIRES REVIEW"
        )
        chain_badge = "Validated bypass" if trace_direct else "Evidence correlation"
        origin_trace_html = (
            f'<div class="origin-exposure-alert {escape(trace_severity)}" role="note">'
            '<div class="origin-alert-icon">!</div><div>'
            f'<span>{escape(exposure_title)}</span>'
            f'<strong>{escape(str(origin_trace.get("origin_ip")))} is the leading address behind '
            f'{escape(str(origin_trace.get("cdn_waf_provider") or "the observed edge"))}</strong>'
            f'<p>{escape(str(origin_trace.get("summary") or ""))}</p></div></div>'
            '<div class="origin-trace-intro"><div><span class="eyebrow">Attribution chain</span>'
            '<h3>'
            + (
                "How the assessment reached this IP"
                if professional
                else "How Cachaza reached this IP"
            )
            + '</h3></div>'
            f'<p>{escape(str(origin_trace.get("qualification") or ""))}</p></div>'
            '<section class="origin-chain-shell" aria-labelledby="origin-chain-title">'
            '<div class="origin-chain-header"><div><span class="eyebrow">Evidence graph</span>'
            '<h3 id="origin-chain-title">Origin Exposure Path</h3></div>'
            f'<span class="origin-chain-badge {escape(trace_severity)}">{escape(chain_badge)}</span></div>'
            '<p class="origin-chain-caption">The connected nodes show the evidence-backed process '
            'that reduced public-edge observations to the leading Origin address. A red outcome '
            'means direct reachability outside the CDN/WAF path was validated.</p>'
            '<div class="origin-chain-viewport"><div class="origin-chain-track" role="img" '
            f'aria-label="Five-step Origin attribution chain ending at {escape(str(origin_trace.get("origin_ip")))}">'
            f'{"".join(chain_items)}</div></div></section>'
            '<div class="origin-procedure-heading"><span>Procedure detail</span>'
            '<small>Tools, techniques and observed evidence for each graph node</small></div>'
            f'<div class="origin-trace">{"".join(trace_steps)}</div>'
        )
        graph_origin_alert = (
            f'<div class="graph-origin-alert {escape(trace_severity)}">'
            '<span>Origin exposure</span>'
            f'<strong>{escape(str(origin_trace.get("origin_ip")))}</strong>'
            f'<small>{escape(str(origin_trace.get("status_label") or "Origin candidate"))}</small>'
            '</div>'
        )

    ai_assistance = data.get("ai_assistance", {})
    ai_panel = ""
    if isinstance(ai_assistance, dict):
        narrative = ai_assistance.get("narrative", {})
        if ai_assistance.get("status") == "generated" and isinstance(narrative, dict):
            ai_spanish = ai_assistance.get("language") == "es"
            summary_value = narrative.get("executive_summary", [])
            if isinstance(summary_value, list):
                summary_points = [
                    str(value).strip() for value in summary_value if str(value).strip()
                ]
            else:
                summary_points = [
                    value.strip()
                    for value in re.split(
                        r"(?:\r?\n)+|(?<=[.!?])\s+(?=[A-ZÁÉÍÓÚÜÑ0-9])",
                        str(summary_value),
                    )
                    if value.strip()
                ]
            summary_html = "".join(
                f"<li>{escape(value)}</li>" for value in summary_points[:6]
            )
            actions = "".join(
                f'<li>{escape(str(value))}</li>'
                for value in narrative.get("recommended_actions", []) if str(value).strip()
            )
            labels = {
                "brief": "Resumen ejecutivo asistido por IA" if ai_spanish else "AI-assisted executive brief",
                "model": "Modelo editorial" if ai_spanish else "Editorial model",
                "evidence": "La evidencia y las puntuaciones siguen siendo deterministas" if ai_spanish else "Evidence and scores remain deterministic",
                "summary": "Resumen ejecutivo" if ai_spanish else "Executive summary",
                "origin": "Evaluación del origen" if ai_spanish else "Origin assessment",
                "impact": "Impacto empresarial" if ai_spanish else "Business impact",
                "actions": "Acciones recomendadas" if ai_spanish else "Recommended actions",
                "limitations": "Limitaciones" if ai_spanish else "Limitations",
            }
            ai_panel = (
                '<details class="section ai-section" open id="ai-executive-section">'
                f'<summary>{labels["brief"]} <span class="ai-badge">OpenRouter</span></summary>'
                '<div class="section-body"><div class="ai-provenance">'
                f'<span>{labels["model"]}: {escape(str(ai_assistance.get("model") or ai_assistance.get("model_requested") or "unknown"))}</span>'
                f'<span>{labels["evidence"]}</span></div>'
                f'<h2 class="ai-headline">{escape(str(narrative.get("headline") or "Executive assessment"))}</h2>'
                '<div class="ai-brief-grid">'
                f'<article class="ai-summary"><h3>{labels["summary"]}</h3><ul class="ai-summary-list">{summary_html}</ul></article>'
                f'<article><h3>{labels["origin"]}</h3><p>{escape(str(narrative.get("origin_assessment") or ""))}</p></article>'
                f'<article><h3>{labels["impact"]}</h3><p>{escape(str(narrative.get("business_impact") or ""))}</p></article>'
                f'<article><h3>{labels["actions"]}</h3><ol>{actions}</ol></article>'
                '</div>'
                f'<p class="ai-limitations"><strong>{labels["limitations"]}:</strong> {escape(str(narrative.get("limitations") or ""))}</p>'
                f'<p class="section-note">{escape(str(ai_assistance.get("notice") or ""))}</p>'
                '</div></details>'
            )
        elif ai_assistance.get("status") == "error":
            ai_panel = (
                '<details class="section ai-section" open id="ai-executive-section">'
                '<summary>AI-assisted executive brief <span class="ai-badge warning">Unavailable</span></summary>'
                '<div class="section-body"><p class="section-note">'
                f'{escape(str(ai_assistance.get("notice") or "Optional OpenRouter editorial pass was unavailable."))}'
                '</p><div class="zone-warning"><strong>OpenRouter diagnostic:</strong> '
                f'{escape(str(ai_assistance.get("error") or "No provider diagnostic was returned."))}'
                '</div><p class="section-note">Check OPENROUTER_API_KEY, account credits, model access and the requested model slug. The deterministic report remains complete.</p></div></details>'
            )
    remediation = data.get("origin_remediation", {})
    remediation_panel = ""
    if isinstance(remediation, dict) and remediation.get("actions"):
        remediation_cards: list[str] = []
        for item in remediation.get("actions", []):
            if not isinstance(item, dict):
                continue
            remediation_cards.append(
                '<article class="remediation-card">'
                '<div class="remediation-card-head">'
                f'<span class="priority {escape(str(item.get("priority") or "P2").lower())}">'
                f'{escape(str(item.get("priority") or "P2"))}</span>'
                f'<span class="remediation-phase">{escape(str(item.get("phase") or "Remediate"))}</span>'
                '</div>'
                f'<h3>{escape(str(item.get("title") or "Security control"))}</h3>'
                f'<p>{escape(str(item.get("action") or ""))}</p>'
                '<dl>'
                f'<dt>Owner</dt><dd>{escape(str(item.get("owner") or "-"))}</dd>'
                f'<dt>Closure test</dt><dd>{escape(str(item.get("verification") or "-"))}</dd>'
                '</dl></article>'
            )
        remediation_panel = (
            '<details class="section remediation-section" open id="origin-remediation-section">'
            '<summary>How to remediate the Origin exposure '
            '<span class="remediation-badge">Action plan</span></summary>'
            '<div class="section-body">'
            '<div class="remediation-intro"><div><span class="eyebrow">Defense roadmap</span>'
            f'<h2>{escape(str(remediation.get("title") or "Origin exposure remediation plan"))}</h2></div>'
            f'<p>{escape(str(remediation.get("objective") or ""))}</p></div>'
            f'<div class="remediation-context">{escape(str(remediation.get("context") or ""))}</div>'
            f'<div class="remediation-grid">{"".join(remediation_cards)}</div>'
            '</div></details>'
        )
    tables = {
        "__ASN_TABLE__": _table(
            ["ASN", "Holder", "Announced", "Scope", "Sources"],
            [
                [
                    item["value"],
                    _evidence_value(item, "holder", "as_name") or "Unknown",
                    _evidence_value(item, "announced") or "Unknown",
                    "Authorized" if item["in_scope"] else "Candidate",
                    ", ".join(item["sources"]),
                ]
                for item in network["asns"]
            ],
        ),
        "__ORG_TABLE__": _table(
            ["Organization", "ASN", "Sources"],
            [
                [item["value"], _evidence_value(item, "asn") or "-", ", ".join(item["sources"])]
                for item in network["organizations"]
            ],
        ),
        "__PREFIX_TABLE__": _table(
            ["Prefix", "ASN", "Scope", "Sources"],
            [
                [
                    item["value"],
                    _evidence_value(item, "asn") or "-",
                    "Authorized" if item["in_scope"] else "Candidate",
                    ", ".join(item["sources"]),
                ]
                for item in network["prefixes"]
            ],
        ),
        "__IP_TABLE__": _table(
            ["IP", "ASN", "Sources"],
            [
                [
                    item["value"],
                    _evidence_value(item, "asn", "asns") or "-",
                    ", ".join(item["sources"]),
                ]
                for item in network["resolved_ips"]
            ],
        ),
        "__REGISTRATION_TABLE__": _table(
            ["Name", "Handle", "Allocation", "Sources"],
            [
                [
                    item["value"],
                    _evidence_value(item, "handle") or "-",
                    _evidence_value(item, "start_address", "end_address") or "-",
                    ", ".join(item["sources"]),
                ]
                for item in network["registrations"]
            ],
        ),
        "__STAGE_TABLE__": _table(
            ["Stage", "Status", "Details"],
            [[item["name"], item["status"], item.get("details", "")] for item in data["stages"]],
        ),
        "__PROVIDER_TABLE__": _provider_table(data.get("provider_status", {})),
        "__SOURCE_TABLE__": _table(
            ["Source", "Status", "Retrieved", "New", "Diagnostic"],
            [
                [
                    source,
                    str(status.get("status") or "unknown"),
                    str(status.get("retrieved", 0)),
                    str(status.get("added", 0)),
                    str(status.get("error") or "-"),
                ]
                for source, status in sorted(data.get("source_status", {}).items())
                if isinstance(status, dict)
            ],
        ),
        "__ORIGIN_TABLE__": _table(
            ["IP", "Origin probability", "Band", "Initial score", "Final score", "Classification", "Group", "Sources", "Rejection reason"],
            origin_rows,
        ),
    }
    counts = "".join(
        (
            '<button class="stat" type="button" '
            f'data-kind="{escape(kind)}" aria-pressed="false">'
            f'<span>{escape(str(count))}</span>{escape(kind)}</button>'
        )
        for kind, count in data["counts"].items()
    ) or '<button class="stat" type="button" data-kind="" aria-pressed="false"><span>0</span>findings</button>'
    key_findings = data.get("key_findings", {})
    waf_entries: list[str] = []
    for entry in key_findings.get("wafs", []):
        vendor, separator, raw_origins = str(entry).partition(" @ ")
        qualifier = "Observed"
        if vendor.endswith("]") and " [" in vendor:
            vendor, raw_qualifier = vendor.rsplit(" [", 1)
            qualifier = raw_qualifier[:-1].replace(";", " ·").title()
        origins: list[str] = []
        more_origins = 0
        if separator:
            more_match = re.search(r"\s+\(\+(\d+) more origins\)$", raw_origins)
            if more_match:
                more_origins = int(more_match.group(1))
                raw_origins = raw_origins[: more_match.start()]
            origins = [value for value in raw_origins.split(", ") if value]
        origin_rows = "".join(
            f'<li class="key-list-item"><code>{escape(origin)}</code></li>'
            for origin in origins
        )
        if more_origins:
            origin_rows += (
                f'<li class="key-list-more">+{more_origins} additional origins in the full evidence</li>'
            )
        waf_entries.append(
            '<article class="waf-entry">'
            f'<div class="waf-entry-head"><strong>{escape(vendor)}</strong>'
            f'<span class="key-status {"candidate" if "Candidate" in qualifier else "observed"}">'
            f'{escape(qualifier)}</span></div>'
            + (f'<ul class="key-list">{origin_rows}</ul>' if origin_rows else '<p class="key-empty">Origin not recorded</p>')
            + "</article>"
        )
    waf_values = list(key_findings.get("wafs", []))
    waf_body = (
        '<div class="waf-grid">' + "".join(waf_entries) + "</div>"
        if waf_entries
        else '<p class="key-empty">No WAF evidence observed.</p>'
    )

    subdomain_summary = data.get("subdomain_summary", {})
    actionable = list(key_findings.get("subdomains", []))
    live_http = [
        item for item in subdomain_summary.get("live_http", []) if isinstance(item, dict)
    ]
    dns_only = [str(value) for value in subdomain_summary.get("dns_only", [])]
    remaining_slots = 13
    live_rows: list[str] = []
    for item in live_http[:remaining_slots]:
        host = str(item.get("host") or "-")
        statuses = [str(value) for value in item.get("statuses", [])]
        status_text = " · ".join(f"HTTP {value}" for value in statuses) or "HTTP responsive"
        live_rows.append(
            '<li class="subdomain-item">'
            f'<code>{escape(host)}</code><span class="key-status live">{escape(status_text)}</span>'
            "</li>"
        )
    remaining_slots -= len(live_rows)
    dns_rows = [
        '<li class="subdomain-item">'
        f'<code>{escape(host)}</code><span class="key-status dns">DNS resolved</span></li>'
        for host in dns_only[:remaining_slots]
    ]
    remaining_slots -= len(dns_rows)
    represented = {str(item.get("host") or "") for item in live_http} | set(dns_only)
    passive = [value for value in actionable if value not in represented]
    passive_rows = [
        '<li class="subdomain-item">'
        f'<code>{escape(host)}</code><span class="key-status passive">Passive candidate</span></li>'
        for host in passive[:remaining_slots]
    ]
    shown_actionable = len(live_rows) + len(dns_rows) + len(passive_rows)

    def subdomain_group(label: str, rows: list[str], count: int) -> str:
        if not rows:
            return ""
        return (
            '<div class="subdomain-group">'
            f'<h4>{escape(label)} <span>{count}</span></h4>'
            f'<ul class="subdomain-list">{"".join(rows)}</ul></div>'
        )

    subdomain_body = "".join(
        (
            subdomain_group("HTTP-responsive", live_rows, len(live_http)),
            subdomain_group("DNS-only", dns_rows, len(dns_only)),
            subdomain_group("Passive-only", passive_rows, len(passive)),
        )
    )
    if actionable:
        hidden_actionable = max(0, len(actionable) - shown_actionable)
        subdomain_body = '<div class="subdomain-grid">' + subdomain_body + "</div>"
        if hidden_actionable:
            subdomain_body += (
                f'<p class="key-more-note">+{hidden_actionable} actionable subdomains remain in the full evidence.</p>'
            )
    else:
        subdomain_body = '<p class="key-empty">No actionable subdomains were validated.</p>'

    omitted = len(subdomain_summary.get("omitted", []))
    if omitted:
        subdomain_body += (
            f'<p class="key-omitted">{omitted} unverified or wildcard-like candidates were omitted from highlights and the graph.</p>'
        )

    other_cards: list[str] = []
    for key, label, empty_text in (
        ("api_endpoints", "API endpoints", "No endpoints observed"),
        ("api_key_candidates", "API key/secret candidates", "No candidates observed"),
        ("emails", "Emails", "No addresses observed"),
        ("phones", "Phones", "No numbers observed"),
        ("addresses", "Physical addresses", "No addresses observed"),
        ("zone_transfer_allowed", "Zone transfer", "Not observed"),
    ):
        values = list(key_findings.get(key, []))
        shown = values[:8]
        value_rows = "".join(
            f'<li class="key-list-item"><code>{escape(str(value))}</code></li>'
            for value in shown
        )
        if len(values) > len(shown):
            value_rows += f'<li class="key-list-more">+{len(values) - len(shown)} more in the full evidence</li>'
        state_class = " danger" if key == "zone_transfer_allowed" and values else ""
        other_cards.append(
            f'<article class="key-card key-card-compact{state_class}">'
            f'<header class="key-card-head"><h3>{escape(label)}</h3><span class="key-count">{len(values)}</span></header>'
            + (f'<ul class="key-list">{value_rows}</ul>' if value_rows else f'<p class="key-empty">{escape(empty_text)}</p>')
            + "</article>"
        )

    key_cards = (
        '<div class="key-findings-layout">'
        '<article class="key-card key-card-wide">'
        f'<header class="key-card-head"><h3>WAF observations</h3><span class="key-count">{len(waf_values)}</span></header>{waf_body}</article>'
        '<article class="key-card key-card-wide">'
        f'<header class="key-card-head"><h3>Actionable subdomains</h3><span class="key-count">{len(actionable)}</span></header>{subdomain_body}</article>'
        + "".join(other_cards)
        + "</div>"
    )
    zone_values = list(key_findings.get("zone_transfer_allowed", []))
    zone_warning = (
        '<div class="zone-warning"><strong>ZONE TRANSFER ALLOWED:</strong> '
        + escape(", ".join(zone_values))
        + ". Validate immediately; complete evidence is preserved below.</div>"
        if zone_values
        else ""
    )
    subdomains = data.get("subdomain_summary", {})
    live_count = len(subdomains.get("live_http", []))
    dns_only_count = len(subdomains.get("dns_only", []))
    omitted_count = len(subdomains.get("omitted", []))
    if subdomains.get("active_validation_present"):
        subdomain_note = (
            f"{live_count} HTTP-responsive and {dns_only_count} DNS-only subdomains are actionable. "
            f"{omitted_count} unverified or wildcard-like enumeration candidates are retained in "
            "the complete evidence but omitted from highlights and the graph."
        )
    else:
        subdomain_note = (
            "No active DNS/HTTP validation was run; passive discoveries remain candidates. "
            f"{omitted_count} dnsenum/Fierce-only names are omitted as noise."
        )
    domains = ", ".join(data["scope"].get("domains", [])) or "No domains supplied"
    tool_cards: list[str] = []
    for item in data.get("tool_findings", []):
        types = "".join(
            f'<span>{escape(str(kind))}: {escape(str(count))}</span>'
            for kind, count in sorted(item.get("types", {}).items())
        )
        highlights = "".join(
            f'<li><code>{escape(str(row.get("value") or "-"))}</code><small>{escape(str(row.get("kind") or "other"))}</small></li>'
            for row in item.get("highlights", [])
        )
        tool_cards.append(
            '<details class="tool-finding"><summary>'
            f'<strong>{escape(str(item.get("tool") or "unknown"))}</strong>'
            f'<span>{escape(str(item.get("total", 0)))} findings · {escape(str(item.get("in_scope", 0)))} in scope</span>'
            f'</summary><div class="tool-finding-body"><div class="tool-types">{types}</div><ul>{highlights}</ul></div></details>'
        )
    tool_findings_panel = (
        '<div class="tool-findings-grid">' + "".join(tool_cards) + "</div>"
        if tool_cards else '<p class="key-empty">No tool findings recorded.</p>'
    )
    # Keep report data inert even inside an HTML script element. Escaping the
    # HTML-significant code points also protects against premature tag closure
    # if a tool returns attacker-controlled metadata.
    report_json = (
        json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    template = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>__DOCUMENT_TITLE__</title><style>
:root{--bg:#07111f;--panel:#0e1b2d;--soft:#102239;--line:#2b3f5c;--text:#e8f0fa;--muted:#9db0c8;--accent:#53d3a4;--blue:#70b0ff;--domain:#53d3a4;--url:#70b0ff;--ip:#c490ff;--cidr:#ffb86b;--asn:#ff7d9f;--org:#ffd166;--registration:#85e0e0;--cloud:#a7e46f;--other:#9db0c8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,Segoe UI,Arial,sans-serif}button,input,select{font:inherit}button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid var(--blue);outline-offset:2px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
main{width:100%;max-width:none;margin:0;padding:clamp(16px,2vw,38px) clamp(12px,1.5vw,28px) 70px}main>header{position:relative;overflow:hidden;border:1px solid var(--line);border-radius:18px;padding:30px;background:linear-gradient(135deg,#112641,#0c1b2d)}h1{margin:0;font-size:clamp(30px,4vw,48px);line-height:1.04;letter-spacing:-.03em}h2{margin:0;font-size:20px}h3{margin:0 0 8px;font-size:15px}.eyebrow{color:var(--accent);font-weight:700;text-transform:uppercase;letter-spacing:.14em}.muted{color:var(--muted)}.report-subject{display:inline-flex;align-items:center;gap:7px;margin:12px 0 8px;border:1px solid rgba(112,176,255,.3);border-radius:999px;background:rgba(7,17,31,.34);padding:5px 10px;color:var(--muted);font-size:12px}.report-subject strong{color:var(--text);overflow-wrap:anywhere}.report-meta{margin:8px 0 0}.classification{position:absolute;right:24px;top:24px;border:1px solid rgba(83,211,164,.4);border-radius:999px;background:rgba(83,211,164,.1);color:var(--accent);padding:5px 10px;font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}.stat{min-width:120px;padding:13px 16px;text-align:left;border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--muted);cursor:pointer}.stat:hover,.stat[aria-pressed="true"]{border-color:var(--accent);background:var(--soft)}.stat span{display:block;color:var(--text);font-size:24px;font-weight:700}.callout{border-left:4px solid var(--accent);padding:12px 16px;background:#0d201f;border-radius:5px;margin:20px 0}
.zone-warning{margin:12px 0;border:1px solid #ff5d6c;border-left:5px solid #ff5d6c;border-radius:9px;background:rgba(197,50,65,.18);color:#ffd8dc;padding:11px 13px}
.section{margin-top:16px;border:1px solid var(--line);border-radius:14px;background:var(--panel);overflow:hidden}.section>summary{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 18px;cursor:pointer;font-size:18px;font-weight:700;list-style:none}.section>summary::-webkit-details-marker{display:none}.section>summary::after{content:"+";color:var(--accent);font-size:24px}.section[open]>summary::after{content:"−"}.section-body{padding:0 18px 18px}.section-note{margin:0;color:var(--muted)}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;background:var(--panel)}th,td{padding:12px 14px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.08em}tr:last-child td{border-bottom:0}.empty{color:var(--muted)}code{color:var(--accent);overflow-wrap:anywhere}
.status-row.status-error td{background:rgba(255,89,111,.07);color:#ffd5db}.status-pill{display:inline-flex;border:1px solid var(--line);border-radius:999px;padding:2px 8px;font-size:10px;font-weight:900;text-transform:uppercase}.status-pill.error{border-color:#ff596f;background:rgba(255,89,111,.14);color:#ff9aaa}.status-pill.ok{border-color:var(--accent);background:rgba(83,211,164,.1);color:var(--accent)}.status-pill.pending,.status-pill.partial{border-color:#f6b94a;background:rgba(246,185,74,.1);color:#ffd083}.tool-findings-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;margin-top:14px}.tool-finding{border:1px solid var(--line);border-radius:11px;background:rgba(7,20,33,.58);overflow:hidden}.tool-finding>summary{display:grid;gap:3px;padding:12px;cursor:pointer}.tool-finding>summary span{color:var(--muted);font-size:11px}.tool-finding-body{border-top:1px solid var(--line);padding:10px}.tool-types{display:flex;gap:5px;flex-wrap:wrap}.tool-types span{border-radius:999px;background:rgba(112,176,255,.1);color:#abd0fa;padding:2px 7px;font-size:9px}.tool-finding ul{display:grid;gap:6px;margin:10px 0 0;padding:0;list-style:none}.tool-finding li{display:flex;justify-content:space-between;gap:8px;border-radius:7px;background:rgba(15,37,62,.65);padding:6px 8px}.tool-finding li small{color:var(--muted)}
.node-info{opacity:0!important;pointer-events:none;transition:opacity .15s}.node-card.active .node-info,.node-card:focus .node-info{opacity:1!important}
.origin-hero{display:flex;align-items:center;justify-content:space-between;gap:18px;margin:14px 0;padding:18px;border:1px solid rgba(83,211,164,.45);border-radius:14px;background:linear-gradient(135deg,rgba(83,211,164,.12),rgba(112,176,255,.08))}.origin-hero-label{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}.origin-hero code{display:block;margin-top:4px;color:#fff;font-size:22px;font-weight:800}.origin-probability{text-align:right}.origin-probability strong{display:block;color:var(--accent);font-size:30px;line-height:1}.origin-probability span{color:var(--muted);font-size:11px;text-transform:uppercase}.origin-ranking{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px;margin:12px 0 16px}.origin-rank-card{border:1px solid var(--line);border-radius:11px;background:rgba(7,20,33,.66);padding:11px}.origin-rank-head{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:9px;align-items:center}.origin-rank-number{color:var(--muted);font-size:11px}.origin-rank-head code{overflow:hidden;text-overflow:ellipsis}.origin-rank-head strong{color:var(--accent)}.origin-rank-card progress{width:100%;height:8px;margin:10px 0 7px;border:0;border-radius:999px;overflow:hidden;background:var(--soft);accent-color:var(--accent)}.origin-rank-card progress::-webkit-progress-bar{background:var(--soft)}.origin-rank-card progress::-webkit-progress-value{background:linear-gradient(90deg,var(--blue),var(--accent))}.origin-rank-meta{display:flex;gap:6px;flex-wrap:wrap}.origin-rank-meta span{border:1px solid var(--line);border-radius:999px;color:var(--muted);padding:2px 7px;font-size:10px}
.origin-hero.critical{border-color:rgba(255,89,111,.72);background:linear-gradient(135deg,rgba(183,36,58,.26),rgba(112,176,255,.08));box-shadow:inset 0 0 0 1px rgba(255,89,111,.12),0 16px 46px rgba(88,9,25,.16)}.origin-identity{min-width:0}.origin-status-chip{display:inline-flex;margin-top:9px;border:1px solid var(--line);border-radius:999px;padding:3px 8px;color:var(--muted);font-size:10px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}.origin-status-chip.critical{border-color:rgba(255,89,111,.62);background:rgba(255,89,111,.14);color:#ff9aaa}.origin-status-chip.warning{border-color:rgba(246,185,74,.62);background:rgba(246,185,74,.12);color:#ffd083}.origin-exposure-alert{display:grid;grid-template-columns:46px minmax(0,1fr);gap:14px;align-items:start;margin:16px 0;border:1px solid rgba(112,176,255,.42);border-left:5px solid var(--blue);border-radius:13px;background:rgba(16,39,64,.74);padding:15px}.origin-exposure-alert.critical{border-color:rgba(255,89,111,.58);border-left-color:#ff596f;background:linear-gradient(110deg,rgba(142,30,49,.28),rgba(16,39,64,.72))}.origin-exposure-alert.warning{border-left-color:#f6b94a}.origin-alert-icon{display:grid;place-items:center;width:42px;height:42px;border:1px solid currentColor;border-radius:13px;color:#ff8294;font-size:21px;font-weight:900}.origin-exposure-alert span{display:block;color:#ff91a1;font-size:10px;font-weight:900;letter-spacing:.12em;text-transform:uppercase}.origin-exposure-alert strong{display:block;margin-top:3px;color:#fff;font-size:18px}.origin-exposure-alert p{margin:5px 0 0;color:#c4d3e2}.origin-trace-intro{display:flex;align-items:end;justify-content:space-between;gap:24px;margin:23px 0 11px}.origin-trace-intro h3{margin:3px 0 0;font-size:20px}.origin-trace-intro p{max-width:680px;margin:0;color:var(--muted);font-size:12px}
.origin-chain-shell{position:relative;overflow:hidden;margin:14px 0 22px;border:1px solid rgba(255,154,82,.38);border-radius:16px;background:radial-gradient(circle at 8% 10%,rgba(112,176,255,.14),transparent 30%),linear-gradient(145deg,rgba(8,23,39,.96),rgba(13,31,51,.96));padding:16px}.origin-chain-shell::before{content:"";position:absolute;inset:0;pointer-events:none;background-image:radial-gradient(rgba(112,176,255,.16) 1px,transparent 1px);background-size:18px 18px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.72),transparent)}.origin-chain-header,.origin-chain-caption,.origin-chain-viewport{position:relative}.origin-chain-header{display:flex;align-items:center;justify-content:space-between;gap:16px}.origin-chain-header h3{margin:3px 0 0;font-size:20px}.origin-chain-badge{display:inline-flex;border:1px solid rgba(246,185,74,.48);border-radius:999px;background:rgba(246,185,74,.1);color:#ffd083;padding:4px 9px;font-size:10px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}.origin-chain-badge.critical{border-color:rgba(255,89,111,.62);background:rgba(255,89,111,.14);color:#ff9aaa}.origin-chain-caption{max-width:920px;margin:9px 0 15px;color:var(--muted);font-size:11px}.origin-chain-viewport{overflow-x:auto;overscroll-behavior-inline:contain;padding:3px 2px 8px}.origin-chain-track{display:flex;align-items:stretch;width:max-content;min-width:100%}.origin-chain-node{display:flex;flex:0 0 172px;min-height:154px;flex-direction:column;border:1px solid rgba(112,176,255,.34);border-top:3px solid var(--blue);border-radius:12px;background:rgba(7,20,33,.94);padding:12px;box-shadow:0 11px 28px rgba(0,0,0,.2)}.origin-chain-step{color:var(--blue);font-size:9px;font-weight:900;letter-spacing:.1em;text-transform:uppercase}.origin-chain-node>strong{margin-top:8px;color:#eef7ff;font-size:12px;line-height:1.35}.origin-chain-node>small{margin-top:7px;color:var(--muted);font-size:9px;line-height:1.4}.origin-chain-node>a{align-self:flex-start;margin-top:auto;color:#9dccff;font-size:9px;font-weight:800;text-decoration:none}.origin-chain-node>a:hover{text-decoration:underline}.origin-chain-link{display:grid;flex:0 0 58px;place-content:center;text-align:center;color:#ffb77f}.origin-chain-link span{display:block;max-width:58px;font-size:8px;line-height:1.2}.origin-chain-link b{display:block;margin-top:4px;font-size:19px;line-height:1}.origin-chain-result{border-color:rgba(246,185,74,.58);border-top-color:#f6b94a;background:linear-gradient(150deg,rgba(77,53,12,.56),rgba(7,20,33,.96))}.origin-chain-result.critical{border-color:rgba(255,89,111,.72);border-top-color:#ff596f;background:linear-gradient(150deg,rgba(112,23,41,.72),rgba(27,15,28,.97));box-shadow:0 12px 34px rgba(92,9,28,.32)}.origin-chain-result code{margin-top:9px;color:#fff;font-size:15px;font-weight:900}.origin-chain-result>strong{color:#ffb2bd}.origin-procedure-heading{display:flex;align-items:end;justify-content:space-between;gap:14px;margin-top:18px;border-bottom:1px solid rgba(121,160,205,.22);padding-bottom:8px}.origin-procedure-heading span{font-size:14px;font-weight:800}.origin-procedure-heading small{color:var(--muted);font-size:10px}.origin-trace{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin:11px 0 18px}.trace-step{position:relative;min-width:0;border:1px solid rgba(121,160,205,.28);border-radius:13px;background:linear-gradient(155deg,rgba(15,37,62,.92),rgba(8,22,38,.94));padding:14px;scroll-margin-top:18px}.trace-step:not(:last-child)::after{content:"→";position:absolute;z-index:2;right:-16px;top:29px;color:var(--blue);font-size:17px}.trace-number{display:grid;place-items:center;width:28px;height:28px;margin-bottom:11px;border:1px solid rgba(112,176,255,.48);border-radius:9px;background:rgba(36,107,206,.18);color:var(--blue);font-weight:900}.trace-step-head span{display:block;color:var(--muted);font-size:9px;letter-spacing:.09em;text-transform:uppercase}.trace-step-head strong{display:block;min-height:38px;margin-top:3px;font-size:12px;line-height:1.35}.trace-state{display:inline-flex;margin-top:7px;border:1px solid var(--line);border-radius:999px;padding:2px 6px;color:var(--muted);font-size:9px;font-style:normal;text-transform:uppercase}.trace-state.validated,.trace-state.completed{border-color:rgba(83,211,164,.46);color:var(--accent)}.trace-state.protected,.trace-state.inconclusive,.trace-state.not-performed{border-color:rgba(246,185,74,.5);color:#ffd083}.trace-content>p{min-height:96px;margin:10px 0;color:#b6c6d8;font-size:11px}.trace-tools{display:flex;gap:4px;flex-wrap:wrap}.trace-tools span{border-radius:6px;background:rgba(112,176,255,.11);color:#a8cdf7;padding:3px 6px;font-size:9px}.trace-evidence{display:grid;gap:4px;margin:9px 0 0;padding-left:15px;color:var(--muted);font-size:9px}.ai-section{border-color:rgba(167,120,255,.45);background:linear-gradient(150deg,rgba(34,27,67,.78),var(--panel) 45%)}.ai-section>summary{justify-content:flex-start}.ai-section>summary::after{margin-left:auto}.ai-badge{display:inline-flex;border:1px solid rgba(167,120,255,.55);border-radius:999px;background:rgba(167,120,255,.13);color:#c9abff;padding:2px 8px;font-size:9px;letter-spacing:.08em;text-transform:uppercase}.ai-badge.warning{border-color:rgba(246,185,74,.55);color:#ffd083}.ai-provenance{display:flex;justify-content:space-between;gap:12px;border-bottom:1px solid rgba(167,120,255,.22);padding-bottom:11px;color:var(--muted);font-size:10px;text-transform:uppercase}.ai-headline{max-width:980px;margin:18px 0 12px;font-size:24px;line-height:1.25}.ai-brief-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.ai-brief-grid article{border:1px solid rgba(167,120,255,.2);border-radius:11px;background:rgba(7,20,33,.55);padding:13px}.ai-brief-grid h3{color:#c9abff}.ai-brief-grid p,.ai-brief-grid ol{margin:0;color:#c4d3e2}.ai-brief-grid ol{padding-left:20px}.ai-brief-grid li+li{margin-top:5px}.ai-limitations{border-left:3px solid #a778ff;margin:12px 0;padding:8px 11px;background:rgba(167,120,255,.08);color:var(--muted)}
.remediation-section{border-color:rgba(83,211,164,.38);background:linear-gradient(145deg,rgba(13,43,47,.72),var(--panel) 42%)}.remediation-section>summary{justify-content:flex-start}.remediation-section>summary::after{margin-left:auto}.remediation-badge{display:inline-flex;border:1px solid rgba(83,211,164,.45);border-radius:999px;background:rgba(83,211,164,.1);color:var(--accent);padding:2px 8px;font-size:9px;letter-spacing:.08em;text-transform:uppercase}.remediation-intro{display:grid;grid-template-columns:minmax(260px,.7fr) minmax(320px,1.3fr);gap:24px;align-items:end;border-bottom:1px solid rgba(83,211,164,.18);padding:4px 0 14px}.remediation-intro h2{margin-top:4px;font-size:clamp(22px,3vw,32px);line-height:1.15}.remediation-intro p{margin:0;color:#c5d6e5}.remediation-context{margin:14px 0;border-left:3px solid #f6b94a;border-radius:0 9px 9px 0;background:rgba(246,185,74,.08);color:#dfcfab;padding:10px 13px}.remediation-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.remediation-card{min-width:0;border:1px solid rgba(121,160,205,.25);border-radius:13px;background:rgba(7,20,33,.65);padding:14px}.remediation-card-head{display:flex;align-items:center;justify-content:space-between;gap:8px}.priority{display:inline-flex;border:1px solid var(--line);border-radius:7px;padding:2px 6px;color:var(--muted);font-size:10px;font-weight:900}.priority.p0{border-color:rgba(255,89,111,.58);background:rgba(255,89,111,.12);color:#ff9aaa}.priority.p1{border-color:rgba(246,185,74,.52);background:rgba(246,185,74,.1);color:#ffd083}.remediation-phase{color:var(--accent);font-size:9px;font-weight:800;letter-spacing:.09em;text-transform:uppercase}.remediation-card h3{min-height:42px;margin:12px 0 8px;line-height:1.35}.remediation-card>p{min-height:145px;margin:0;color:#bdccdc;font-size:11px}.remediation-card dl{display:grid;grid-template-columns:1fr;gap:3px;margin:13px 0 0;border-top:1px solid var(--line);padding-top:10px}.remediation-card dt{color:var(--muted);font-size:9px;text-transform:uppercase}.remediation-card dd{margin:0 0 7px;color:#dbe7f3;font-size:10px}.professional{background:radial-gradient(circle at 12% 0,rgba(42,111,151,.18),transparent 32%),var(--bg)}.professional main{max-width:1720px;margin:auto}.professional main>header{min-height:245px;display:flex;flex-direction:column;justify-content:center;border-color:rgba(112,176,255,.32);background:linear-gradient(118deg,#0b2037 0%,#102d47 55%,#102b35 100%);box-shadow:0 28px 80px rgba(0,0,0,.24)}.professional main>header::after{content:"";position:absolute;right:-70px;bottom:-125px;width:390px;height:390px;border:1px solid rgba(83,211,164,.2);border-radius:50%;box-shadow:0 0 0 54px rgba(83,211,164,.035),0 0 0 108px rgba(112,176,255,.025);pointer-events:none}.professional main>header>*:not(.classification){position:relative;z-index:1}.professional main>header>.classification{position:absolute;right:24px;top:24px;z-index:2}.professional .section{box-shadow:0 12px 38px rgba(0,0,0,.09)}
.key-findings-layout{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:14px}.key-card{min-width:0;border:1px solid var(--line);border-radius:12px;background:linear-gradient(145deg,rgba(16,34,57,.86),rgba(10,24,41,.94));padding:14px}.key-card-wide{grid-column:1/-1}.key-card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.key-card-head h3{margin:0;color:var(--text);font-size:14px}.key-count{display:inline-grid;place-items:center;min-width:28px;height:24px;border:1px solid rgba(112,176,255,.35);border-radius:999px;background:rgba(36,93,145,.25);color:var(--blue);padding:0 8px;font-size:12px;font-weight:800}.waf-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.waf-entry{min-width:0;border:1px solid rgba(121,160,205,.22);border-radius:10px;background:rgba(7,20,33,.6);padding:11px}.waf-entry-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:8px}.waf-entry-head strong{overflow-wrap:anywhere}.key-status{display:inline-flex;align-items:center;flex:0 0 auto;border:1px solid var(--line);border-radius:999px;padding:2px 7px;color:var(--muted);font-size:10px;white-space:nowrap}.key-status.observed,.key-status.live{border-color:rgba(83,211,164,.45);background:rgba(83,211,164,.1);color:var(--accent)}.key-status.candidate,.key-status.passive{border-color:rgba(255,184,107,.48);background:rgba(255,184,107,.1);color:#ffc783}.key-status.dns{border-color:rgba(112,176,255,.45);background:rgba(112,176,255,.1);color:var(--blue)}.key-list,.subdomain-list{display:grid;gap:6px;margin:0;padding:0;list-style:none}.key-list-item,.subdomain-item{min-width:0;border-radius:8px;background:rgba(7,20,33,.68);padding:7px 9px}.key-list-item code,.subdomain-item code{display:block;color:#dceafa;white-space:normal;word-break:break-word}.key-list-more{color:var(--muted);padding:3px 9px;font-size:11px}.subdomain-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.subdomain-group{min-width:0}.subdomain-group h4{display:flex;align-items:center;justify-content:space-between;gap:8px;margin:0 0 7px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.subdomain-group h4 span{color:var(--text)}.subdomain-item{display:flex;align-items:center;justify-content:space-between;gap:10px}.subdomain-item code{min-width:0}.key-empty{margin:0;color:var(--muted)}.key-more-note,.key-omitted{margin:10px 0 0;border-radius:8px;padding:8px 10px;color:var(--muted);font-size:12px}.key-more-note{background:rgba(112,176,255,.08)}.key-omitted{border-left:3px solid #f6b94a;background:rgba(246,185,74,.08);color:#d8c49d}.key-card.danger{border-color:rgba(255,93,108,.62);background:rgba(197,50,65,.13)}
.controls{display:flex;gap:12px;align-items:end;flex-wrap:wrap;margin-bottom:14px}.field{display:grid;gap:5px;min-width:210px;flex:1}.field span{color:var(--muted);font-size:12px}.field input,.field select,.action{min-height:42px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--text);padding:8px 11px}.action{cursor:pointer;flex:0}.action:hover{border-color:var(--accent)}
.evidence-status{margin:0 0 10px;color:var(--muted)}.finding{border-top:1px solid var(--line)}.finding:first-child{border-top:0}.finding>summary{display:grid;grid-template-columns:minmax(88px,.55fr) minmax(220px,2.5fr) minmax(120px,1fr) auto;gap:12px;align-items:center;padding:12px 2px;cursor:pointer}.finding-kind{color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.finding-value{overflow-wrap:anywhere}.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;color:var(--muted);font-size:12px}.badge.scope{color:var(--accent);border-color:var(--accent)}.finding-body{padding:0 2px 15px 100px}.metadata{display:grid;grid-template-columns:minmax(130px,.5fr) minmax(200px,2fr);gap:0;border:1px solid var(--line);border-radius:9px;overflow:hidden}.metadata dt,.metadata dd{margin:0;padding:8px 11px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.metadata dt{color:var(--muted);background:var(--soft)}.metadata dd{white-space:pre-wrap}.metadata dt:last-of-type,.metadata dd:last-of-type{border-bottom:0}
.graph-shell{position:relative;margin-top:14px;border:1px solid #294566;border-radius:18px;overflow:hidden;background:linear-gradient(145deg,#0d1e33,#0a1728);box-shadow:0 24px 70px rgba(0,0,0,.22)}
.graph-toolbar{display:grid;grid-template-columns:minmax(220px,1fr) auto;gap:12px;align-items:center;padding:14px;border-bottom:1px solid rgba(121,160,205,.2);background:rgba(8,20,35,.74);backdrop-filter:blur(16px)}.graph-search{position:relative;display:flex;align-items:center;max-width:460px}.graph-search::before{content:"⌕";position:absolute;left:13px;color:var(--blue);font-size:20px}.graph-search input{width:100%;height:42px;border:1px solid #315173;border-radius:11px;background:#071523;color:var(--text);padding:8px 38px 8px 38px}.graph-search input::placeholder{color:#7188a4}.graph-search-clear{position:absolute;right:6px;width:30px;height:30px;border:0;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer}.graph-search-clear:hover{background:var(--soft);color:var(--text)}
.graph-actions{display:flex;align-items:center;justify-content:flex-end;gap:7px;flex-wrap:wrap}.graph-action,.layout-button{height:38px;min-width:38px;border:1px solid #315173;border-radius:10px;background:#0b1a2b;color:var(--text);padding:0 11px;cursor:pointer}.graph-action:hover,.layout-button:hover,.layout-button[aria-pressed="true"]{border-color:var(--blue);background:#132a44;color:#fff}.graph-action:active,.layout-button:active{transform:translateY(1px)}.layout-switch{display:inline-flex;padding:3px;border:1px solid #294867;border-radius:11px;background:#071523}.layout-button{height:30px;border:0;background:transparent;color:var(--muted);padding:0 10px}.layout-button[aria-pressed="true"]{background:#1d4f7b;color:#fff}.graph-range-control{display:inline-flex;align-items:center;gap:6px;height:38px;border:1px solid #294867;border-radius:10px;background:#071523;padding:0 9px}.graph-range-label{color:var(--muted);font-size:11px}.zoom-range,.spacing-range{width:96px;accent-color:var(--blue)}.spacing-range{accent-color:var(--accent)}.zoom-value,.spacing-value{min-width:42px;color:var(--muted);font-size:12px;text-align:center}.spacing-value{color:var(--accent)}
.graph-status-strip{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid rgba(121,160,205,.16);background:rgba(12,31,52,.65)}.graph-metric{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(112,176,255,.22);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:12px}.graph-metric strong{color:var(--text)}.graph-selection-status{margin-left:auto;color:var(--blue);font-size:12px;overflow-wrap:anywhere}
.graph-layout{display:grid;grid-template-columns:minmax(0,1fr) 310px;min-height:680px}.graph-canvas{position:relative;min-width:0;height:680px;overflow:hidden;background:radial-gradient(circle at 18% 15%,rgba(37,91,142,.34),transparent 34%),radial-gradient(circle at 80% 75%,rgba(83,211,164,.12),transparent 30%),#071421;isolation:isolate}.graph-canvas::before{content:"";position:absolute;inset:0;pointer-events:none;background-image:radial-gradient(rgba(123,165,211,.22) 1px,transparent 1px);background-size:24px 24px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.8),transparent 94%)}#relationship-graph{position:relative;z-index:1;display:block;width:100%;height:680px;touch-action:none;cursor:grab;user-select:none}#relationship-graph.is-panning{cursor:grabbing}
.graph-help{position:absolute;z-index:2;left:14px;bottom:14px;max-width:520px;border:1px solid rgba(112,176,255,.2);border-radius:10px;background:rgba(5,15,26,.82);color:#94a9c1;padding:7px 10px;font-size:11px;pointer-events:none;backdrop-filter:blur(10px)}.graph-tooltip{position:absolute;z-index:6;display:none;width:min(300px,calc(100% - 24px));border:1px solid #41678e;border-radius:13px;background:rgba(8,21,36,.96);box-shadow:0 16px 45px rgba(0,0,0,.42);padding:12px;pointer-events:none;backdrop-filter:blur(14px)}.graph-tooltip.visible{display:block}.tooltip-kind{color:var(--blue);font-size:10px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.tooltip-title{margin-top:3px;color:#fff;font-weight:700;overflow-wrap:anywhere}.tooltip-meta{margin-top:7px;color:var(--muted);font-size:12px}
.graph-inspector{min-width:0;border-left:1px solid rgba(121,160,205,.2);background:linear-gradient(180deg,rgba(14,33,55,.96),rgba(8,21,36,.96));padding:18px;overflow:auto}.inspector-empty{display:grid;place-items:center;min-height:300px;text-align:center;color:var(--muted)}.inspector-empty-icon{display:grid;place-items:center;width:62px;height:62px;margin:0 auto 12px;border:1px dashed #426486;border-radius:18px;color:var(--blue);font-size:26px}.inspector-hero{display:flex;gap:12px;align-items:center;padding-bottom:15px;border-bottom:1px solid var(--line)}.inspector-icon{display:grid;place-items:center;flex:0 0 50px;height:50px;border-radius:15px;color:#fff;font-weight:800;box-shadow:inset 0 0 0 1px rgba(255,255,255,.2),0 9px 22px rgba(0,0,0,.24)}.inspector-title{min-width:0}.inspector-title h3{margin:0;overflow-wrap:anywhere}.inspector-title p{margin:3px 0 0;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.inspector-badges{display:flex;gap:6px;flex-wrap:wrap;margin:13px 0}.inspector-badge{border:1px solid var(--line);border-radius:999px;padding:3px 8px;color:var(--muted);font-size:11px}.inspector-badge.authorized{border-color:rgba(83,211,164,.55);color:var(--accent)}.inspector-block{margin-top:16px}.inspector-block h4{margin:0 0 8px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.12em}.source-list{display:flex;gap:5px;flex-wrap:wrap}.source-pill{border-radius:7px;background:#122a43;color:#b7c9dc;padding:4px 7px;font-size:11px}.relation-list{display:grid;gap:6px}.relation-item{display:grid;grid-template-columns:8px minmax(0,1fr);gap:8px;width:100%;border:1px solid transparent;border-radius:9px;background:#0a192a;color:var(--text);padding:8px;text-align:left;cursor:pointer}.relation-item:hover{border-color:#315b83;background:#10253d}.relation-dot{width:8px;height:8px;margin-top:5px;border-radius:50%}.relation-name{display:block;font-size:12px;overflow-wrap:anywhere}.relation-kind{display:block;margin-top:2px;color:var(--muted);font-size:10px}.inspector-facts{display:grid;grid-template-columns:auto 1fr;gap:6px 9px;margin:0}.inspector-facts dt{color:var(--muted);font-size:11px}.inspector-facts dd{margin:0;overflow-wrap:anywhere;font-size:12px}
.edge{fill:none;stroke:#42617e;stroke-width:1.35;opacity:.38;vector-effect:non-scaling-stroke;transition:opacity .18s,stroke .18s,stroke-width .18s}.edge.origin-path{stroke:#ff9a52;stroke-width:2.35;stroke-dasharray:7 5;opacity:.82;filter:drop-shadow(0 0 4px rgba(255,154,82,.34))}.edge.active{stroke:#78d8ff;stroke-width:2.8;opacity:1;filter:drop-shadow(0 0 5px rgba(112,176,255,.65))}.edge.dim,.edge.filtered{opacity:.035}.edge-label{fill:#d6e7f7;font-size:10px;font-weight:700;paint-order:stroke;stroke:#071421;stroke-width:4px;stroke-linejoin:round;pointer-events:none;opacity:0}.edge-label.origin-path{fill:#ffc28f;opacity:.72}.edge-label.active{opacity:1}.edge-label.filtered{display:none}
.node-card{cursor:pointer;outline:none;transition:opacity .18s}.node-card .node-position{transition:transform .45s cubic-bezier(.2,.8,.2,1)}.node-card.dim{opacity:.12}.node-card.filtered{display:none}.node-card.match .node-halo{opacity:.85;stroke-width:4}.node-card.active .node-halo{opacity:1;stroke:#fff;stroke-width:4;filter:drop-shadow(0 0 12px rgba(112,176,255,.9))}.node-card.related .node-halo{opacity:.78}.node-card.primary-origin .node-halo{opacity:1;stroke:#ff596f;stroke-width:5;filter:drop-shadow(0 0 14px rgba(255,89,111,.82))}.node-card.primary-origin .node-core{fill:#c92f4a;stroke:#ffd6dc;stroke-width:2}.node-card.primary-origin .node-info-bg{stroke:#ff7187;stroke-width:1.8;fill:rgba(68,15,28,.96)}.node-card.origin-path-node .node-halo{opacity:.92;stroke:#ff9a52}.node-halo{fill:rgba(5,16,28,.9);stroke-width:2.5;opacity:.58;vector-effect:non-scaling-stroke;transition:all .18s}.node-core{stroke:rgba(255,255,255,.65);stroke-width:1.5;vector-effect:non-scaling-stroke}.node-icon{fill:#fff;font-size:11px;font-weight:900;text-anchor:middle;dominant-baseline:central;pointer-events:none}.node-info-bg{fill:rgba(9,25,42,.94);stroke:#345473;stroke-width:1;vector-effect:non-scaling-stroke;filter:drop-shadow(0 6px 8px rgba(0,0,0,.25))}.node-title{fill:#eff7ff;font-size:11px;font-weight:700}.node-meta{fill:#8fa8c2;font-size:8.5px;text-transform:uppercase}.node-scope{stroke:none}.node-card:hover .node-info-bg,.node-card:focus .node-info-bg{stroke:#70b0ff;stroke-width:1.8}.node-card:hover .node-halo{opacity:1}.zoomed-out .node-info{opacity:0;pointer-events:none}.zoomed-out .node-card.active .node-info,.zoomed-out .node-card.related .node-info,.zoomed-out .node-card.match .node-info{opacity:1}.cluster-label{fill:#9fb5ca;font-size:12px;font-weight:800;letter-spacing:.1em;text-anchor:middle;text-transform:uppercase;paint-order:stroke;stroke:#071421;stroke-width:5px}.cluster-orbit{fill:rgba(18,43,70,.18);stroke:rgba(112,176,255,.18);stroke-width:1.2;stroke-dasharray:4 8;vector-effect:non-scaling-stroke}
.graph-origin-alert{position:absolute;z-index:3;top:14px;right:14px;display:grid;max-width:280px;border:1px solid rgba(255,89,111,.62);border-radius:12px;background:rgba(58,14,27,.9);box-shadow:0 14px 34px rgba(0,0,0,.3);padding:10px 12px;pointer-events:none;backdrop-filter:blur(12px)}.graph-origin-alert span{color:#ff8fa0;font-size:9px;font-weight:900;letter-spacing:.11em;text-transform:uppercase}.graph-origin-alert strong{color:#fff;font-size:17px}.graph-origin-alert small{color:#d9b9c0}.graph-origin-alert.warning,.graph-origin-alert.information{border-color:rgba(246,185,74,.58);background:rgba(54,40,12,.9)}
.legend{display:flex;gap:7px;flex-wrap:wrap;padding:12px 14px;border-top:1px solid rgba(121,160,205,.18);background:rgba(8,20,35,.78)}.legend-item{display:inline-flex;align-items:center;gap:7px;border:1px solid #294866;border-radius:999px;background:#0a192a;color:var(--muted);padding:5px 9px;cursor:pointer;font-size:11px}.legend-item:hover,.legend-item[aria-pressed="true"]{border-color:#70b0ff;background:#132a44;color:#fff}.legend-item[aria-pressed="false"]{opacity:.42}.legend-dot{width:10px;height:10px;border-radius:4px;box-shadow:0 0 10px currentColor}.graph-shell.is-expanded{position:fixed;z-index:1000;inset:10px;margin:0;background:#071421}.graph-shell.is-expanded .graph-canvas,.graph-shell.is-expanded #relationship-graph{height:calc(100vh - 190px)}.graph-shell.is-expanded .graph-layout{min-height:calc(100vh - 190px)}body.graph-expanded{overflow:hidden}
.origin-chain-track{width:100%;min-width:1180px}.origin-chain-node{flex:1 1 165px}.origin-chain-link{flex-basis:46px}
@media(max-width:1320px){.remediation-grid{grid-template-columns:repeat(3,minmax(0,1fr))}.remediation-card>p{min-height:96px}}
@media(max-width:1200px){.origin-trace{grid-template-columns:repeat(3,minmax(0,1fr))}.trace-step::after{display:none}}
@media(max-width:900px){.key-findings-layout{grid-template-columns:repeat(2,minmax(0,1fr))}.waf-grid,.subdomain-grid,.ai-brief-grid{grid-template-columns:1fr}.origin-trace,.remediation-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.origin-trace-intro{align-items:flex-start;flex-direction:column}.remediation-intro{grid-template-columns:1fr}.graph-toolbar{grid-template-columns:1fr}.graph-actions{justify-content:flex-start}.graph-search{max-width:none}.graph-layout{grid-template-columns:1fr}.graph-inspector{border-left:0;border-top:1px solid var(--line);max-height:380px}.graph-selection-status{width:100%;margin-left:0}.graph-canvas,#relationship-graph{height:580px}.graph-layout{min-height:0}}
@media(max-width:760px){main{padding:12px 10px 38px}main>header{padding:24px 18px}.classification,.professional main>header>.classification{position:static;align-self:flex-start;margin-bottom:14px;order:-1}.stat{min-width:calc(50% - 6px);flex:1}.key-findings-layout,.origin-trace,.remediation-grid{grid-template-columns:1fr}.key-card-wide{grid-column:auto}.origin-hero{align-items:flex-start;flex-direction:column}.origin-probability{text-align:left}.origin-exposure-alert{grid-template-columns:1fr}.trace-content>p,.remediation-card>p,.remediation-card h3{min-height:0}.ai-provenance{flex-direction:column}.subdomain-item{align-items:flex-start;flex-direction:column;gap:5px}.finding>summary{grid-template-columns:minmax(72px,.55fr) minmax(0,1.45fr)}.finding-source,.finding>summary .badge{display:none}.finding-body{padding-left:2px}.metadata{grid-template-columns:1fr}.metadata dt{border-bottom:0}.graph-canvas,#relationship-graph{height:480px}.zoom-control,.spacing-control{display:none}.graph-help{right:12px;max-width:calc(100% - 24px)}.graph-action,.layout-button{padding:0 8px}.graph-origin-alert{left:12px;right:12px;max-width:none}.graph-shell.is-expanded{inset:0;border-radius:0}.graph-shell.is-expanded .graph-canvas,.graph-shell.is-expanded #relationship-graph{height:calc(100vh - 235px)}.section>summary{align-items:flex-start;font-size:16px;padding:14px}.section-body{padding:0 12px 14px}.table-wrap{max-width:100%}}
@media(max-width:480px){h1{font-size:30px}.stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.stat{min-width:0;width:100%;padding:10px}.stat span{font-size:20px}.graph-actions{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));width:100%}.layout-switch{grid-column:span 2}.graph-action,.layout-button{width:100%}.origin-path-action{grid-column:1/-1}.graph-canvas,#relationship-graph{height:420px}.graph-help{display:none}.controls{align-items:stretch;flex-direction:column}.field{min-width:0}.report-subject{align-items:flex-start;flex-direction:column;border-radius:12px}}
@media(max-width:760px){.origin-chain-header,.origin-procedure-heading{align-items:flex-start;flex-direction:column}.origin-chain-viewport{overflow:visible}.origin-chain-track{display:grid;width:100%;min-width:0}.origin-chain-node{width:100%;min-height:0}.origin-chain-link{min-height:54px}.origin-chain-link span{max-width:none}.origin-chain-link b{transform:rotate(90deg)}.origin-chain-caption{font-size:10px}}
@media(prefers-color-scheme:light){:root{--bg:#f5f8fc;--panel:#fff;--soft:#edf4fb;--line:#c8d5e4;--text:#102238;--muted:#526a83;--accent:#087a5b;--blue:#176fc1}main>header{background:linear-gradient(135deg,#e8f2ff,#f7fbff)}.professional main>header{background:linear-gradient(118deg,#e8f3fb,#eef8f6)}.callout{background:#eaf8f1}.key-card,.remediation-card{background:#f8fbff}.waf-entry,.key-list-item,.subdomain-item{background:#fff}.origin-chain-shell{background:radial-gradient(circle at 8% 10%,#dcecf9,transparent 32%),#f7fbff}.origin-chain-node{background:#fff;box-shadow:0 9px 24px rgba(56,90,122,.12)}.origin-chain-node>strong{color:#102238}.origin-chain-result{background:#fff8e9}.origin-chain-result.critical{background:#fff0f2}.origin-chain-result code{color:#8f2530}.graph-shell{background:#f7fbff;box-shadow:0 18px 50px rgba(56,90,122,.18)}.graph-toolbar,.graph-status-strip,.legend{background:rgba(240,247,253,.94)}.graph-search input,.graph-action,.layout-switch,.graph-range-control,.legend-item{background:#fff;color:var(--text)}.graph-canvas{background:radial-gradient(circle at 20% 10%,#d9ebfa,transparent 38%),#f7fbff}.graph-inspector{background:#f0f6fc}.graph-help,.graph-tooltip{background:rgba(255,255,255,.96);color:var(--muted)}.tooltip-title{color:var(--text)}.node-info-bg{fill:rgba(255,255,255,.97);stroke:#9bb4cc}.node-title{fill:#102238}.node-meta{fill:#526a83}.edge-label{fill:#284b6c;stroke:#f7fbff}.cluster-label{fill:#526a83;stroke:#f7fbff}.relation-item{background:#fff}.source-pill{background:#e1edf8;color:#34506b}}
.node-position{transition:none!important}.node-count-bg{fill:#071421;stroke:rgba(255,255,255,.8);stroke-width:1.2;vector-effect:non-scaling-stroke}.node-count{fill:#fff;font-size:7px;font-weight:900;text-anchor:middle;dominant-baseline:central;pointer-events:none}.zoomed-out .node-card.related .node-info{opacity:0}
@media(prefers-color-scheme:light){.zone-warning{background:#fff0f1;color:#8f2530}}
.ai-brief-grid{align-items:start}.ai-brief-grid article{min-width:0;height:auto;overflow:visible;padding:15px}.ai-brief-grid p,.ai-brief-grid ol,.ai-summary-list{margin:0;color:#c4d3e2;overflow-wrap:anywhere}.ai-brief-grid ol,.ai-summary-list{padding-left:21px}.ai-brief-grid li+li,.ai-summary-list li+li{margin-top:8px}.ai-summary-list li::marker{color:#a778ff}.ai-summary-list li{padding-left:3px;line-height:1.55}
</style></head><body class="__BODY_CLASS__"><main>
<header class="report-header"><span class="classification">Executive assessment</span><div class="eyebrow">__REPORT_KICKER__</div><div class="report-subject">Report prepared for <strong>__REPORT_SUBJECT__</strong></div><h1>__REPORT_TITLE__</h1><p class="muted report-meta">Generated __GENERATED__ &middot; version __VERSION__</p><div class="stats" aria-label="Finding counts. Select a type to filter the evidence below.">__COUNTS__</div></header>
<div class="callout"><strong>Scope guard:</strong> __SCOPE_NOTE__</div>
__AI_PANEL__
<details class="section" open id="key-findings-section"><summary>Key findings</summary><div class="section-body"><p class="section-note">__SUBDOMAIN_NOTE__ Highlights are grouped by validation state; complete evidence remains in JSON/CSV.</p>__ZONE_WARNING____KEY_FINDINGS__</div></details>
<details class="section" open id="tool-findings-section"><summary>Findings by tool</summary><div class="section-body"><p class="section-note">Results are grouped by the collector or provider that produced them. Open a tool to inspect representative findings.</p>__TOOL_FINDINGS__</div></details>
<details class="section" open id="origin-discovery-section"><summary>Automatic Origin discovery</summary><div class="section-body"><p class="section-note">__ORIGIN_SUMMARY__</p>__ORIGIN_HERO____ORIGIN_TRACE____ORIGIN_RANKING____ORIGIN_TABLE__</div></details>
__REMEDIATION_PANEL__
<details class="section" open id="graph-section"><summary>Interactive relationship explorer</summary><div class="section-body"><p class="section-note">Explore correlations between domains, addresses, infrastructure, technologies and evidence. Search or filter to focus a dense graph.</p><div class="graph-shell" id="graph-shell"><div class="graph-toolbar"><label class="graph-search"><span class="sr-only">Search graph nodes</span><input id="graph-search" type="search" placeholder="Find a domain, IP, ASN, technology…" autocomplete="off"><button class="graph-search-clear" id="clear-graph-search" type="button" title="Clear graph search" aria-label="Clear graph search">×</button></label><div class="graph-actions" role="toolbar" aria-label="Graph controls"><button class="graph-action origin-path-action" id="focus-origin" type="button" title="Focus the leading Origin IP and its attribution path">Origin path</button><div class="layout-switch" role="group" aria-label="Graph layout"><button class="layout-button" id="layout-network" type="button" aria-pressed="true">Network</button><button class="layout-button" id="layout-groups" type="button" aria-pressed="false">Groups</button></div><label class="graph-range-control spacing-control" title="Increase or reduce the distance between nodes"><span class="graph-range-label">Spacing</span><input class="spacing-range" id="graph-spacing" type="range" min="60" max="180" value="100" step="10" aria-label="Node spacing"><output class="spacing-value" id="graph-spacing-value">100%</output></label><button class="graph-action" id="zoom-out" type="button" title="Zoom out" aria-label="Zoom out">&minus;</button><label class="graph-range-control zoom-control" title="Graph zoom"><span class="sr-only">Zoom</span><input class="zoom-range" id="graph-zoom" type="range" min="25" max="260" value="100" step="5" aria-label="Graph zoom"><output class="zoom-value" id="graph-zoom-value">100%</output></label><button class="graph-action" id="zoom-in" type="button" title="Zoom in" aria-label="Zoom in">+</button><button class="graph-action" id="fit-graph" type="button" title="Fit all visible nodes">Fit</button><button class="graph-action" id="fullscreen-graph" type="button" title="Expand graph" aria-label="Expand graph">&#x26F6;</button><button class="graph-action" id="reset-graph" type="button" title="Reset filters, spacing, and layout">Reset</button></div></div><div class="graph-status-strip"><span class="graph-metric"><strong id="visible-node-count">0</strong> nodes</span><span class="graph-metric"><strong id="visible-edge-count">0</strong> relationships</span><span class="graph-metric"><strong id="visible-kind-count">0</strong> types</span><span class="graph-selection-status" id="graph-selection-status">Select a node to reveal its correlation path</span></div><div class="graph-layout"><div class="graph-canvas" id="graph-canvas"><svg id="relationship-graph" role="img" aria-labelledby="graph-title graph-description"><title id="graph-title">Reconnaissance relationship graph</title><desc id="graph-description">Interactive network of domains, addresses, infrastructure, technologies and evidence.</desc></svg><div class="graph-tooltip" id="graph-tooltip" role="tooltip"></div>__GRAPH_ORIGIN_ALERT__<div class="graph-help">Orange dashed relationships show the Origin attribution chain · wheel or +/− zooms · drag the background to pan</div></div><aside class="graph-inspector" id="graph-inspector" aria-live="polite"><div class="inspector-empty"><div><div class="inspector-empty-icon">◎</div><h3>Nothing selected</h3><p>Select a node to inspect its evidence and connected relationships.</p></div></div></aside></div><div class="legend" id="graph-legend" aria-label="Filter nodes by type"></div></div></div></details>
<details class="section" open id="evidence-section"><summary>Complete evidence explorer</summary><div class="section-body"><div class="controls"><label class="field"><span>Search findings and metadata</span><input id="evidence-search" type="search" placeholder="Domain, ASN, source, provider…"></label><label class="field"><span>Finding type</span><select id="evidence-kind"><option value="">All types</option></select></label><button class="action" id="show-all-evidence" type="button">Show all</button></div><p class="evidence-status" id="evidence-status" aria-live="polite"></p><div id="evidence-list"></div></div></details>
<details class="section"><summary>ASN intelligence</summary><div class="section-body">__ASN_TABLE__</div></details>
<details class="section"><summary>Network organizations</summary><div class="section-body">__ORG_TABLE__</div></details>
<details class="section"><summary>Prefixes</summary><div class="section-body">__PREFIX_TABLE__</div></details>
<details class="section"><summary>Resolved addresses</summary><div class="section-body">__IP_TABLE__</div></details>
<details class="section"><summary>Network registrations</summary><div class="section-body">__REGISTRATION_TABLE__</div></details>
<details class="section"><summary>External source status</summary><div class="section-body"><p class="section-note">Retrieved counts what a CT source returned; New counts evidence records added to this workspace. Empty is a valid response, while partial/error identifies a source availability issue.</p>__SOURCE_TABLE__</div></details>
<details class="section"><summary>Provider execution status</summary><div class="section-body"><p class="section-note">Credential presence is not acceptance. Censys 401 means an invalid Platform PAT; 403 means the accepted account is not entitled to the requested endpoint. IntelX keys must be used with the exact API URL assigned in the Developer tab.</p>__PROVIDER_TABLE__</div></details>
<details class="section"><summary>Execution stages</summary><div class="section-body">__STAGE_TABLE__</div></details>
</main><script type="application/json" id="report-data">__REPORT_JSON__</script><script>
(() => {
"use strict";
const report=JSON.parse(document.getElementById("report-data").textContent),findings=Array.isArray(report.findings)?report.findings:[];
const search=document.getElementById("evidence-search"),kindSelect=document.getElementById("evidence-kind"),list=document.getElementById("evidence-list"),status=document.getElementById("evidence-status"),evidenceSection=document.getElementById("evidence-section");
const kinds=[...new Set(findings.map(item=>String(item.kind||"finding")))].sort();
const valueText=value=>value===null||value===undefined||value===""?"-":typeof value==="object"?JSON.stringify(value,null,2):String(value);
function addRow(dl,key,value){const dt=document.createElement("dt"),dd=document.createElement("dd");dt.textContent=key;dd.textContent=valueText(value);dl.append(dt,dd)}
function findingElement(finding){const item=document.createElement("details");item.className="finding";const summary=document.createElement("summary"),kind=document.createElement("span"),value=document.createElement("span"),source=document.createElement("span"),scope=document.createElement("span");kind.className="finding-kind";kind.textContent=finding.kind||"finding";value.className="finding-value";value.textContent=finding.value||"-";source.className="finding-source muted";source.textContent=finding.source||"unknown source";scope.className="badge"+(finding.in_scope?" scope":"");scope.textContent=finding.in_scope?"In scope":"Contextual";summary.append(kind,value,source,scope);const body=document.createElement("div"),metadata=document.createElement("dl");body.className="finding-body";metadata.className="metadata";addRow(metadata,"stage",finding.stage);addRow(metadata,"source",finding.source);addRow(metadata,"scope",finding.in_scope?"in scope":"contextual / out of scope");addRow(metadata,"observed_at",finding.observed_at);const raw=finding.metadata&&typeof finding.metadata==="object"?finding.metadata:{};Object.keys(raw).sort().forEach(key=>addRow(metadata,key,raw[key]));body.append(metadata);item.append(summary,body);return item}
function renderEvidence(){const query=search.value.trim().toLowerCase(),selected=kindSelect.value,matching=findings.filter(finding=>(!selected||finding.kind===selected)&&(!query||JSON.stringify(finding).toLowerCase().includes(query)));list.replaceChildren(...matching.map(findingElement));status.textContent=`Showing ${matching.length} of ${findings.length} findings`;document.querySelectorAll(".stat").forEach(card=>card.setAttribute("aria-pressed",String(Boolean(selected)&&card.dataset.kind===selected)))}
kinds.forEach(kind=>{const option=document.createElement("option");option.value=kind;option.textContent=kind;kindSelect.append(option)});search.addEventListener("input",renderEvidence);kindSelect.addEventListener("change",renderEvidence);document.getElementById("show-all-evidence").addEventListener("click",()=>{search.value="";kindSelect.value="";renderEvidence()});document.querySelectorAll(".stat").forEach(card=>card.addEventListener("click",()=>{const kind=card.dataset.kind||"";kindSelect.value=kindSelect.value===kind?"":kind;search.value="";evidenceSection.open=true;renderEvidence();evidenceSection.scrollIntoView({behavior:"smooth",block:"start"})}));renderEvidence();

const svg=document.getElementById("relationship-graph"),shell=document.getElementById("graph-shell"),canvas=document.getElementById("graph-canvas"),tooltip=document.getElementById("graph-tooltip"),inspector=document.getElementById("graph-inspector"),graphSearch=document.getElementById("graph-search"),zoomSlider=document.getElementById("graph-zoom"),zoomOutput=document.getElementById("graph-zoom-value"),spacingSlider=document.getElementById("graph-spacing"),spacingOutput=document.getElementById("graph-spacing-value"),selectionStatus=document.getElementById("graph-selection-status");
const graph=report.graph||{nodes:[],edges:[]},nodes=Array.isArray(graph.nodes)?graph.nodes.map(node=>({...node})):[],byId=new Map(nodes.map(node=>[node.id,node])),edges=(Array.isArray(graph.edges)?graph.edges:[]).filter(edge=>byId.has(edge.source)&&byId.has(edge.target));
const order=["domain","origin_technique","origin_candidate","url","api_endpoint","email","phone","address","waf","dns_zone_transfer","ip","cidr","asn","organization","network_registration","service","technology","whois","cloud_asset","cloud_provider","fingerprint"],present=[...new Set(nodes.map(node=>node.kind))];
present.sort((a,b)=>{const ai=order.indexOf(a),bi=order.indexOf(b);return(ai<0?999:ai)-(bi<0?999:bi)||a.localeCompare(b)});
const groups=new Map(present.map(kind=>[kind,nodes.filter(node=>node.kind===kind)])),activeKinds=new Set(present),adjacency=new Map(nodes.map(node=>[node.id,[]]));
edges.forEach(edge=>{adjacency.get(edge.source)?.push(edge);adjacency.get(edge.target)?.push(edge)});nodes.forEach(node=>node.degree=adjacency.get(node.id)?.length||0);
const styles={domain:{color:"#3ddc97",icon:"D"},origin_technique:{color:"#ff9a52",icon:"TTP"},origin_candidate:{color:"#ff596f",icon:"OR"},url:{color:"#4da3ff",icon:"↗"},api_endpoint:{color:"#38bdf8",icon:"API"},email:{color:"#f0abfc",icon:"@"},phone:{color:"#fbbf24",icon:"T"},address:{color:"#a3e635",icon:"A"},waf:{color:"#fb7185",icon:"WAF"},dns_zone_transfer:{color:"#ef4444",icon:"AX"},ip:{color:"#b779ff",icon:"IP"},cidr:{color:"#ff9f43",icon:"/"},asn:{color:"#ff5d8f",icon:"AS"},organization:{color:"#f7c948",icon:"O"},network_registration:{color:"#35d0ba",icon:"R"},service:{color:"#fb7185",icon:":"},technology:{color:"#22d3ee",icon:"{}"},whois:{color:"#94a3b8",icon:"W"},cloud_asset:{color:"#8ee34d",icon:"☁"},cloud_provider:{color:"#5ee3a1",icon:"C"},fingerprint:{color:"#a78bfa",icon:"#"},other:{color:"#94a3b8",icon:"•"}},styleFor=kind=>styles[kind]||styles.other,kindName=kind=>String(kind||"finding").replaceAll("_"," ");
const width=1800,height=1000,ns="http://www.w3.org/2000/svg",makeSvg=(tag,attrs={})=>{const element=document.createElementNS(ns,tag);Object.entries(attrs).forEach(([key,value])=>element.setAttribute(key,value));return element};
svg.setAttribute("viewBox",`0 0 ${width} ${height}`);
const defs=makeSvg("defs"),marker=makeSvg("marker",{id:"edge-arrow",viewBox:"0 0 10 10",refX:"9",refY:"5",markerWidth:"5",markerHeight:"5",orient:"auto-start-reverse"}),arrow=makeSvg("path",{d:"M 0 0 L 10 5 L 0 10 z",fill:"#6385a5"});
marker.append(arrow);defs.append(marker);svg.append(defs);
const viewport=makeSvg("g"),orbitLayer=makeSvg("g",{"aria-hidden":"true"}),edgeLayer=makeSvg("g",{"aria-hidden":"true"}),edgeLabelLayer=makeSvg("g",{"aria-hidden":"true"}),nodeLayer=makeSvg("g");viewport.append(orbitLayer,edgeLayer,edgeLabelLayer,nodeLayer);svg.append(viewport);
function hashNumber(value){let hash=2166136261;for(const char of String(value)){hash^=char.charCodeAt(0);hash=Math.imul(hash,16777619)}return(hash>>>0)/4294967295}
function networkLayout(){
  const centers=new Map(),radiusX=width*.34,radiusY=height*.3;
  present.forEach((kind,index)=>{const angle=(index/Math.max(1,present.length))*Math.PI*2-Math.PI/2;centers.set(kind,{x:width/2+Math.cos(angle)*radiusX,y:height/2+Math.sin(angle)*radiusY})});
  nodes.forEach((node,index)=>{const center=centers.get(node.kind)||{x:width/2,y:height/2},angle=hashNumber(node.id)*Math.PI*2,distance=35+Math.sqrt(index%Math.max(1,nodes.length))*13;node.x=center.x+Math.cos(angle)*distance;node.y=center.y+Math.sin(angle)*distance;node.vx=0;node.vy=0});
  const iterations=nodes.length>450?85:145;
  for(let tick=0;tick<iterations;tick++){
    const cooling=1-tick/iterations;
    edges.forEach(edge=>{const source=byId.get(edge.source),target=byId.get(edge.target),dx=target.x-source.x,dy=target.y-source.y,distance=Math.max(1,Math.hypot(dx,dy)),desired=175+Math.min(105,(source.degree+target.degree)*4),force=(distance-desired)*.0019*cooling,fx=dx/distance*force,fy=dy/distance*force;source.vx+=fx;source.vy+=fy;target.vx-=fx;target.vy-=fy});
    for(let i=0;i<nodes.length;i++){for(let j=i+1;j<nodes.length;j++){const a=nodes[i],b=nodes[j],dx=b.x-a.x,dy=b.y-a.y,distance=Math.max(1,Math.hypot(dx,dy)),minimum=72+(a.degree===0||b.degree===0?18:0);if(distance<minimum){const force=(minimum-distance)*.018*cooling,fx=dx/distance*force,fy=dy/distance*force;a.vx-=fx;a.vy-=fy;b.vx+=fx;b.vy+=fy}}}
    nodes.forEach(node=>{const center=centers.get(node.kind)||{x:width/2,y:height/2};node.vx+=(center.x-node.x)*.00135*cooling;node.vy+=(center.y-node.y)*.00135*cooling;node.vx+=(width/2-node.x)*.0001;node.vy+=(height/2-node.y)*.0001;node.vx=Math.max(-18,Math.min(18,node.vx))*.82;node.vy=Math.max(-18,Math.min(18,node.vy))*.82;node.x+=node.vx;node.y+=node.vy})
  }
  return new Map(nodes.map(node=>[node.id,{x:node.x,y:node.y}]))
}
function groupedLayout(){
  const positions=new Map(),count=Math.max(1,present.length),radiusX=width*.34,radiusY=height*.31;
  present.forEach((kind,groupIndex)=>{const group=[...(groups.get(kind)||[])].sort((a,b)=>b.degree-a.degree||a.label.localeCompare(b.label)),groupAngle=groupIndex/count*Math.PI*2-Math.PI/2,center={x:width/2+Math.cos(groupAngle)*radiusX,y:height/2+Math.sin(groupAngle)*radiusY};group.forEach((node,index)=>{if(index===0){positions.set(node.id,{...center});return}const angle=index*2.399963229728653+groupAngle,radius=48+Math.sqrt(index)*25;positions.set(node.id,{x:center.x+Math.cos(angle)*radius,y:center.y+Math.sin(angle)*radius})})});
  return positions
}
function originPathLayout(basePositions){
  const positions=new Map(),pathNodes=nodes.filter(node=>node.is_origin_path||node.is_primary_origin).sort((a,b)=>(a.stage_number??999)-(b.stage_number??999)),otherNodes=nodes.filter(node=>!pathNodes.includes(node));
  const pathSpan=Math.min(width-320,Math.max(0,pathNodes.length-1)*245),pathStep=pathNodes.length>1?pathSpan/(pathNodes.length-1):0,pathStart=(width-pathSpan)/2;
  pathNodes.forEach((node,index)=>positions.set(node.id,{x:pathStart+index*pathStep,y:height*.2}));
  const base=otherNodes.map(node=>basePositions.get(node.id)).filter(Boolean),minX=Math.min(...base.map(point=>point.x),0),maxX=Math.max(...base.map(point=>point.x),1),minY=Math.min(...base.map(point=>point.y),0),maxY=Math.max(...base.map(point=>point.y),1),spanX=Math.max(1,maxX-minX),spanY=Math.max(1,maxY-minY);
  otherNodes.forEach(node=>{const point=basePositions.get(node.id)||{x:width/2,y:height/2};positions.set(node.id,{x:135+(point.x-minX)/spanX*(width-270),y:height*.43+(point.y-minY)/spanY*(height*.48)})});
  return positions
}
const networkPositions=networkLayout(),groupPositions=groupedLayout(),originPositions=originPathLayout(networkPositions),clusterGuides=[];
let spacingScale=1;
function scalePosition(point){return{x:width/2+(point.x-width/2)*spacingScale,y:height/2+(point.y-height/2)*spacingScale}}
function layoutPositions(name=currentLayout){const source=name==="groups"?groupPositions:name==="origin"?originPositions:networkPositions;return new Map([...source].map(([id,point])=>[id,scalePosition(point)]))}
function updateClusterGuides(){clusterGuides.forEach(({kind,orbit,label})=>{const group=groups.get(kind)||[],points=group.map(node=>groupPositions.get(node.id)).filter(Boolean).map(scalePosition),center=points[0]||{x:width/2,y:height/2},radius=Math.max(82,...points.map(point=>Math.hypot(point.x-center.x,point.y-center.y)+38));orbit.setAttribute("cx",center.x);orbit.setAttribute("cy",center.y);orbit.setAttribute("r",radius);label.setAttribute("x",center.x);label.setAttribute("y",center.y-radius-18)})}
present.forEach(kind=>{const group=groups.get(kind)||[],container=makeSvg("g",{display:"none"}),orbit=makeSvg("circle",{class:"cluster-orbit"}),label=makeSvg("text",{class:"cluster-label"});label.textContent=`${kindName(kind)} · ${group.length}`;container.append(orbit,label);orbitLayer.append(container);clusterGuides.push({kind,container,orbit,label})});updateClusterGuides();
nodes.forEach(node=>{const position=networkPositions.get(node.id)||{x:width/2,y:height/2};node.x=position.x;node.y=position.y});
const edgeElements=edges.map((edge,index)=>{const path=makeSvg("path",{class:"edge"+(edge.origin_path?" origin-path":""),"data-source":edge.source,"data-target":edge.target,"marker-end":"url(#edge-arrow)"}),label=makeSvg("text",{class:"edge-label"+(edge.origin_path?" origin-path":""),"text-anchor":"middle"}),title=makeSvg("title");title.textContent=edge.relationship;label.textContent=edge.relationship;path.append(title);edgeLayer.append(path);edgeLabelLayer.append(label);return{edge,path,label,index}}),nodeElements=new Map();
const short=(value,limit=22)=>String(value||"").length>limit?String(value).slice(0,limit-1)+"…":String(value||"-");
nodes.forEach(node=>{
  const visual=styleFor(node.kind),nodeClass="node-card"+(node.is_primary_origin?" primary-origin":"")+(node.is_origin_path?" origin-path-node":""),outer=makeSvg("g",{class:nodeClass,role:"button",tabindex:"0","aria-label":`${kindName(node.kind)}: ${node.label}`}),position=makeSvg("g",{class:"node-position",transform:`translate(${node.x} ${node.y})`}),halo=makeSvg("circle",{class:"node-halo",r:node.is_primary_origin?"33":"29",stroke:visual.color}),core=makeSvg("circle",{class:"node-core",r:node.is_primary_origin?"23":"21",fill:visual.color}),icon=makeSvg("text",{class:"node-icon",x:"0",y:"1"}),info=makeSvg("g",{class:"node-info"}),infoBg=makeSvg("rect",{class:"node-info-bg",x:"31",y:"-24",width:"178",height:"48",rx:"10"}),scopeBar=makeSvg("rect",{class:"node-scope",x:"38",y:"-15",width:"4",height:"30",rx:"2",fill:node.is_primary_origin?"#ff596f":node.in_scope?"#3ddc97":"#f6b94a"}),title=makeSvg("text",{class:"node-title",x:"49",y:"-5"}),meta=makeSvg("text",{class:"node-meta",x:"49",y:"12"}),nativeTitle=makeSvg("title");
  const countBg=makeSvg("circle",{class:"node-count-bg",cx:"17",cy:"-17",r:"9"}),countText=makeSvg("text",{class:"node-count",x:"17",y:"-17"});
  icon.textContent=visual.icon;countText.textContent=node.degree>99?"99+":String(node.degree||node.evidence_count||0);title.textContent=short(node.label);meta.textContent=`${kindName(node.kind)} · ${node.validation||`${node.evidence_count||0} evidence`} · ${node.degree} links`;nativeTitle.textContent=`${kindName(node.kind)}: ${node.label}`;info.append(infoBg,scopeBar,title,meta);position.append(halo,core,icon,countBg,countText,info,nativeTitle);outer.append(position);nodeLayer.append(outer);nodeElements.set(node.id,{outer,position})
});
function updateNode(node){nodeElements.get(node.id)?.position.setAttribute("transform",`translate(${node.x} ${node.y})`)}
function updateEdges(){edgeElements.forEach(({edge,path,label,index})=>{const source=byId.get(edge.source),target=byId.get(edge.target);if(!source||!target)return;const dx=target.x-source.x,dy=target.y-source.y,distance=Math.max(1,Math.hypot(dx,dy)),bend=((index%5)-2)*10+(hashNumber(edge.relationship)-.5)*18,nx=-dy/distance,ny=dx/distance,cx=(source.x+target.x)/2+nx*bend,cy=(source.y+target.y)/2+ny*bend;path.setAttribute("d",`M ${source.x} ${source.y} Q ${cx} ${cy} ${target.x} ${target.y}`);label.setAttribute("x",cx);label.setAttribute("y",cy-5)})}
let selectedNode=null,hoveredNode=null,query="",currentLayout="network",animationId=0,dragNode=null,dragStart=null,dragMoved=false,panning=false,panMoved=false,lastPoint=null,view={x:0,y:0,scale:1};
const visible=node=>activeKinds.has(node.kind),matchesQuery=node=>!query||`${node.label} ${node.kind} ${(node.sources||[]).join(" ")}`.toLowerCase().includes(query);
function updateMetrics(){const visibleNodes=nodes.filter(visible),visibleIds=new Set(visibleNodes.map(node=>node.id)),visibleEdges=edges.filter(edge=>visibleIds.has(edge.source)&&visibleIds.has(edge.target));document.getElementById("visible-node-count").textContent=String(visibleNodes.length);document.getElementById("visible-edge-count").textContent=String(visibleEdges.length);document.getElementById("visible-kind-count").textContent=String(new Set(visibleNodes.map(node=>node.kind)).size)}
function refreshHighlight(){
  const focus=hoveredNode&&visible(hoveredNode)?hoveredNode:selectedNode&&visible(selectedNode)?selectedNode:null,connectedIds=new Set(focus?[focus.id]:[]),matchIds=new Set(query?nodes.filter(node=>visible(node)&&matchesQuery(node)).map(node=>node.id):[]);
  if(focus)(adjacency.get(focus.id)||[]).forEach(edge=>connectedIds.add(edge.source===focus.id?edge.target:edge.source));else if(query)edges.forEach(edge=>{if(matchIds.has(edge.source))connectedIds.add(edge.target);if(matchIds.has(edge.target))connectedIds.add(edge.source)});
  nodeElements.forEach(({outer},id)=>{const node=byId.get(id),filtered=!visible(node),isActive=Boolean(focus&&id===focus.id),related=Boolean(focus&&connectedIds.has(id)&&!isActive),matched=Boolean(query&&matchIds.has(id)),dim=Boolean(!filtered&&((focus&&!connectedIds.has(id))||(query&&!focus&&!matched&&!connectedIds.has(id))));outer.classList.toggle("filtered",filtered);outer.classList.toggle("active",isActive||selectedNode?.id===id);outer.classList.toggle("related",related);outer.classList.toggle("match",matched);outer.classList.toggle("dim",dim)});
  edgeElements.forEach(({edge,path,label})=>{const filtered=!visible(byId.get(edge.source))||!visible(byId.get(edge.target)),active=Boolean(focus&&(edge.source===focus.id||edge.target===focus.id)),searchActive=Boolean(!focus&&query&&(matchIds.has(edge.source)||matchIds.has(edge.target)));path.classList.toggle("filtered",filtered);label.classList.toggle("filtered",filtered);path.classList.toggle("active",active||searchActive);label.classList.toggle("active",active);path.classList.toggle("dim",Boolean(!filtered&&((focus&&!active)||(query&&!focus&&!searchActive))))});
  if(focus)selectionStatus.textContent=`${focus.label} · ${focus.degree} direct relationships`;else if(query)selectionStatus.textContent=`${matchIds.size} matching nodes · press Enter to focus the first`;else selectionStatus.textContent="Hover or select a node to reveal its correlation path"
}
function emptyInspector(){inspector.innerHTML='<div class="inspector-empty"><div><div class="inspector-empty-icon">◎</div><h3>Nothing selected</h3><p>Hover or select a node to inspect its evidence and connected relationships.</p></div></div>'}
function renderInspector(node){
  inspector.replaceChildren();const visual=styleFor(node.kind),hero=document.createElement("div"),icon=document.createElement("div"),title=document.createElement("div"),heading=document.createElement("h3"),type=document.createElement("p");hero.className="inspector-hero";icon.className="inspector-icon";icon.style.background=visual.color;icon.textContent=visual.icon;title.className="inspector-title";heading.textContent=node.label;type.textContent=kindName(node.kind);title.append(heading,type);hero.append(icon,title);
  const badges=document.createElement("div");badges.className="inspector-badges";[[node.in_scope?"In scope":"Contextual",node.in_scope?"inspector-badge authorized":"inspector-badge"],...(node.validation?[[node.validation,"inspector-badge"]]:[]),[`${node.evidence_count||0} evidence`,"inspector-badge"],[`${node.degree} links`,"inspector-badge"]].forEach(([text,className])=>{const badge=document.createElement("span");badge.className=className;badge.textContent=text;badges.append(badge)});inspector.append(hero,badges);
  if(node.kind==="origin_candidate"){const facts=document.createElement("dl");facts.className="inspector-facts";[["Priority",node.is_primary_origin?"Leading Origin IP":"Candidate"],["Exposure status",node.validation||"Origin candidate"],["Origin probability",`${node.origin_probability_percent||0}%`],["Confidence",node.confidence_band||"inconclusive"],["Classification",node.classification||"inconclusive"],["Method",node.probability_method||"heuristic correlation score"]].forEach(([key,value])=>addRow(facts,key,value));inspector.append(facts)}
  if(node.kind==="origin_technique"){const facts=document.createElement("dl");facts.className="inspector-facts";[["Step",node.stage_number||"-"],["Tactic",node.tactic||"-"],["Technique",node.technique||"-"],["Status",node.validation||"unknown"],["Procedure",node.procedure||"-"],["Tools",(node.tools||[]).join(", ")||"-"]].forEach(([key,value])=>addRow(facts,key,value));inspector.append(facts);if((node.stage_evidence||[]).length){const block=document.createElement("div"),heading=document.createElement("h4"),items=document.createElement("div");block.className="inspector-block";heading.textContent="Attribution evidence";items.className="source-list";node.stage_evidence.slice(0,12).forEach(value=>{const pill=document.createElement("span");pill.className="source-pill";pill.textContent=value;items.append(pill)});block.append(heading,items);inspector.append(block)}}
  const sources=document.createElement("div"),sourcesTitle=document.createElement("h4"),sourceList=document.createElement("div");sources.className="inspector-block";sourcesTitle.textContent="Evidence sources";sourceList.className="source-list";(node.sources||[]).forEach(value=>{const pill=document.createElement("span");pill.className="source-pill";pill.textContent=value;sourceList.append(pill)});if(!sourceList.children.length){const none=document.createElement("span");none.className="muted";none.textContent="No source metadata";sourceList.append(none)}sources.append(sourcesTitle,sourceList);inspector.append(sources);
  const relationBlock=document.createElement("div"),relationTitle=document.createElement("h4"),relationList=document.createElement("div"),relations=(adjacency.get(node.id)||[]).map(edge=>({edge,other:byId.get(edge.source===node.id?edge.target:edge.source),outgoing:edge.source===node.id})).filter(item=>item.other&&visible(item.other)).sort((a,b)=>a.edge.relationship.localeCompare(b.edge.relationship)||a.other.label.localeCompare(b.other.label));relationBlock.className="inspector-block";relationTitle.textContent=`Connected relationships (${relations.length})`;relationList.className="relation-list";
  relations.slice(0,80).forEach(({edge,other,outgoing})=>{const button=document.createElement("button"),dot=document.createElement("span"),content=document.createElement("span"),name=document.createElement("span"),meta=document.createElement("span");button.type="button";button.className="relation-item";dot.className="relation-dot";dot.style.background=styleFor(other.kind).color;name.className="relation-name";name.textContent=`${outgoing?"→":"←"} ${other.label}`;meta.className="relation-kind";meta.textContent=`${edge.relationship} · ${kindName(other.kind)}`;content.append(name,meta);button.append(dot,content);button.addEventListener("click",()=>{selectNode(other);centerOn(other,Math.max(1.1,view.scale))});relationList.append(button)});
  if(relations.length>80){const note=document.createElement("p");note.className="muted";note.textContent=`Showing the first 80 of ${relations.length} relationships.`;relationList.append(note)}relationBlock.append(relationTitle,relationList);inspector.append(relationBlock)
}
function selectNode(node){selectedNode=node;renderInspector(node);refreshHighlight()}
function clearSelection(){selectedNode=null;emptyInspector();refreshHighlight()}
function showTooltip(node,event){tooltip.replaceChildren();const kind=document.createElement("div"),title=document.createElement("div"),meta=document.createElement("div");kind.className="tooltip-kind";kind.textContent=kindName(node.kind);title.className="tooltip-title";title.textContent=node.label;meta.className="tooltip-meta";meta.textContent=`${node.in_scope?"In scope":"Contextual"} · ${node.validation||`${node.evidence_count||0} evidence`} · ${node.degree} relationships`;tooltip.append(kind,title,meta);tooltip.classList.add("visible");positionTooltip(event)}
function positionTooltip(event){if(!tooltip.classList.contains("visible"))return;const rect=canvas.getBoundingClientRect(),left=Math.max(10,Math.min(rect.width-tooltip.offsetWidth-10,event.clientX-rect.left+16)),top=Math.max(10,Math.min(rect.height-tooltip.offsetHeight-10,event.clientY-rect.top+16));tooltip.style.left=`${left}px`;tooltip.style.top=`${top}px`}
function hideTooltip(){tooltip.classList.remove("visible")}
nodeElements.forEach(({outer},id)=>{
  const node=byId.get(id);
  outer.addEventListener("pointerenter",event=>{hoveredNode=node;showTooltip(node,event);renderInspector(node);refreshHighlight()});
  outer.addEventListener("pointermove",positionTooltip);
  outer.addEventListener("pointerleave",()=>{hoveredNode=null;hideTooltip();if(selectedNode)renderInspector(selectedNode);else emptyInspector();refreshHighlight()});
  outer.addEventListener("click",event=>{event.stopPropagation();if(dragMoved){dragMoved=false;return}selectNode(node)});
  outer.addEventListener("dblclick",event=>{event.stopPropagation();selectNode(node);centerOn(node,Math.max(1.55,view.scale))});
  outer.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();selectNode(node);centerOn(node,Math.max(1.3,view.scale))}});
  outer.addEventListener("pointerdown",event=>{dragNode=node;dragStart={clientX:event.clientX,clientY:event.clientY};dragMoved=false;outer.setPointerCapture(event.pointerId);event.stopPropagation()})
});
function applyView(){viewport.setAttribute("transform",`translate(${view.x} ${view.y}) scale(${view.scale})`);zoomSlider.value=String(Math.round(view.scale*100));zoomOutput.textContent=`${Math.round(view.scale*100)}%`;svg.classList.toggle("zoomed-out",view.scale<1.2)}
function svgPoint(event){const point=svg.createSVGPoint();point.x=event.clientX;point.y=event.clientY;return point.matrixTransform(svg.getScreenCTM().inverse())}
function graphPoint(event){const point=svg.createSVGPoint();point.x=event.clientX;point.y=event.clientY;return point.matrixTransform(viewport.getScreenCTM().inverse())}
function setZoom(scale,anchor={x:width/2,y:height/2}){const next=Math.max(.25,Math.min(2.6,scale));view.x=anchor.x-(anchor.x-view.x)*next/view.scale;view.y=anchor.y-(anchor.y-view.y)*next/view.scale;view.scale=next;applyView()}
function fitGraph(){
  const visibleNodes=nodes.filter(visible);if(!visibleNodes.length){view={x:0,y:0,scale:1};applyView();return}
  const minX=Math.min(...visibleNodes.map(node=>node.x))-50,maxX=Math.max(...visibleNodes.map(node=>node.x))+225,minY=Math.min(...visibleNodes.map(node=>node.y))-55,maxY=Math.max(...visibleNodes.map(node=>node.y))+55,padding=70,scale=Math.max(.25,Math.min(1.55,Math.min((width-padding*2)/(maxX-minX),(height-padding*2)/(maxY-minY))));
  view.scale=scale;view.x=(width-(minX+maxX)*scale)/2;view.y=(height-(minY+maxY)*scale)/2;applyView()
}
function centerOn(node,scale=1.45){view.scale=Math.max(.25,Math.min(2.6,scale));view.x=width/2-node.x*view.scale;view.y=height/2-node.y*view.scale;applyView()}
function applySpacing(){spacingScale=Number(spacingSlider.value)/100;spacingOutput.textContent=`${Math.round(spacingScale*100)}%`;animationId++;const targets=layoutPositions(currentLayout);nodes.forEach(node=>{const target=targets.get(node.id);if(target){node.x=target.x;node.y=target.y;updateNode(node)}});updateClusterGuides();updateEdges()}
function setLayout(name,animate=true){
  currentLayout=name;document.getElementById("layout-network").setAttribute("aria-pressed",String(name==="network"));document.getElementById("layout-groups").setAttribute("aria-pressed",String(name==="groups"));clusterGuides.forEach(({container})=>container.setAttribute("display",name==="groups"?"":"none"));updateClusterGuides();
  const targets=layoutPositions(name),starts=new Map(nodes.map(node=>[node.id,{x:node.x,y:node.y}])),token=++animationId;
  if(!animate){nodes.forEach(node=>{const target=targets.get(node.id);if(target){node.x=target.x;node.y=target.y;updateNode(node)}});updateEdges();fitGraph();return}
  const started=performance.now(),duration=520;
  function frame(now){if(token!==animationId)return;const progress=Math.min(1,(now-started)/duration),eased=1-Math.pow(1-progress,3);nodes.forEach(node=>{const start=starts.get(node.id),target=targets.get(node.id);if(!start||!target)return;node.x=start.x+(target.x-start.x)*eased;node.y=start.y+(target.y-start.y)*eased;updateNode(node)});updateEdges();if(progress<1)requestAnimationFrame(frame);else fitGraph()}
  requestAnimationFrame(frame)
}
function updateVisibility(){nodeElements.forEach(({outer},id)=>outer.classList.toggle("filtered",!visible(byId.get(id))));edgeElements.forEach(({edge,path,label})=>{const filtered=!visible(byId.get(edge.source))||!visible(byId.get(edge.target));path.classList.toggle("filtered",filtered);label.classList.toggle("filtered",filtered)});if(selectedNode&&!visible(selectedNode))clearSelection();updateMetrics();refreshHighlight()}
svg.addEventListener("pointerdown",event=>{if(event.target.closest?.(".node-card"))return;panning=true;panMoved=false;lastPoint=svgPoint(event);svg.classList.add("is-panning");svg.setPointerCapture(event.pointerId)});
svg.addEventListener("pointermove",event=>{if(dragNode&&dragStart){const moved=Math.hypot(event.clientX-dragStart.clientX,event.clientY-dragStart.clientY);if(moved>3){dragMoved=true;const point=graphPoint(event);dragNode.x=point.x;dragNode.y=point.y;updateNode(dragNode);updateEdges()}}else if(panning){const point=svgPoint(event),dx=point.x-lastPoint.x,dy=point.y-lastPoint.y;if(Math.hypot(dx,dy)>1)panMoved=true;view.x+=dx;view.y+=dy;lastPoint=point;applyView()}});
function releasePointer(){dragNode=null;dragStart=null;panning=false;lastPoint=null;svg.classList.remove("is-panning")}
svg.addEventListener("pointerup",releasePointer);svg.addEventListener("pointercancel",releasePointer);
svg.addEventListener("click",event=>{if(!event.target.closest?.(".node-card")&&!panMoved)clearSelection();panMoved=false});
svg.addEventListener("wheel",event=>{event.preventDefault();setZoom(view.scale*(event.deltaY<0?1.13:.885),svgPoint(event))},{passive:false});
const legend=document.getElementById("graph-legend");
present.forEach(kind=>{const item=document.createElement("button"),dot=document.createElement("span"),label=document.createElement("span");item.type="button";item.className="legend-item";item.setAttribute("aria-pressed","true");item.title=`Show or hide ${kindName(kind)} nodes`;dot.className="legend-dot";dot.style.background=styleFor(kind).color;dot.style.color=styleFor(kind).color;label.textContent=`${kindName(kind)} (${groups.get(kind).length})`;item.append(dot,label);item.addEventListener("click",()=>{if(activeKinds.has(kind)&&activeKinds.size>1){activeKinds.delete(kind);item.setAttribute("aria-pressed","false")}else{activeKinds.add(kind);item.setAttribute("aria-pressed","true")}updateVisibility();fitGraph()});legend.append(item)});
graphSearch.addEventListener("input",()=>{query=graphSearch.value.trim().toLowerCase();refreshHighlight()});
graphSearch.addEventListener("keydown",event=>{if(event.key!=="Enter")return;const first=nodes.find(node=>visible(node)&&matchesQuery(node));if(first){selectNode(first);centerOn(first,Math.max(1.1,view.scale))}});
document.getElementById("clear-graph-search").addEventListener("click",()=>{graphSearch.value="";query="";graphSearch.focus();refreshHighlight()});
document.getElementById("layout-network").addEventListener("click",()=>setLayout("network"));document.getElementById("layout-groups").addEventListener("click",()=>setLayout("groups"));
document.getElementById("zoom-in").addEventListener("click",()=>setZoom(view.scale*1.2));document.getElementById("zoom-out").addEventListener("click",()=>setZoom(view.scale/1.2));zoomSlider.addEventListener("input",()=>setZoom(Number(zoomSlider.value)/100));spacingSlider.addEventListener("input",applySpacing);document.getElementById("fit-graph").addEventListener("click",fitGraph);
const focusOrigin=document.getElementById("focus-origin"),primaryOrigin=nodes.find(node=>node.is_primary_origin);if(!primaryOrigin){focusOrigin.hidden=true}else{focusOrigin.addEventListener("click",()=>{activeKinds.add("origin_candidate");activeKinds.add("origin_technique");updateVisibility();setLayout("origin");setTimeout(()=>{selectNode(primaryOrigin);centerOn(primaryOrigin,1.1)},560)})}
document.getElementById("fullscreen-graph").addEventListener("click",()=>{const expanded=shell.classList.toggle("is-expanded");document.body.classList.toggle("graph-expanded",expanded);document.getElementById("fullscreen-graph").title=expanded?"Exit expanded view":"Expand graph";setTimeout(fitGraph,80)});
document.addEventListener("keydown",event=>{if(event.key==="Escape"&&shell.classList.contains("is-expanded")){shell.classList.remove("is-expanded");document.body.classList.remove("graph-expanded");setTimeout(fitGraph,80)}});
document.getElementById("reset-graph").addEventListener("click",()=>{graphSearch.value="";query="";spacingSlider.value="100";spacingScale=1;spacingOutput.textContent="100%";activeKinds.clear();present.forEach(kind=>activeKinds.add(kind));legend.querySelectorAll(".legend-item").forEach(item=>item.setAttribute("aria-pressed","true"));clearSelection();updateVisibility();setLayout(primaryOrigin?"origin":"network")});
if(nodes.length){nodes.forEach(updateNode);updateEdges();updateVisibility();if(primaryOrigin){setLayout("origin",false)}requestAnimationFrame(fitGraph)}else{const empty=makeSvg("text",{x:width/2,y:height/2,"text-anchor":"middle",class:"cluster-label"});empty.textContent="No relationship data was collected";viewport.append(empty);updateMetrics();applyView()}
})();
</script></body></html>"""
    template = template.replace(
        "Explore correlations between domains, addresses, infrastructure, technologies and evidence. Search or filter to focus a dense graph.",
        "Explore correlations between domains, addresses, infrastructure, technologies and evidence. Hover for a compact tooltip; click a node to open its detail card and inspector.",
    ).replace(
        "Select a node to reveal its correlation path",
        "Select a node to reveal its correlation path",
    ).replace(
        "Select a node to inspect its evidence and connected relationships.",
        "Select a node to inspect its evidence and connected relationships.",
    )
    replacements = {
        "__DOCUMENT_TITLE__": escape(f"{report_title} - {report_subject}"),
        "__BODY_CLASS__": "professional" if professional else "standard",
        "__REPORT_KICKER__": (
            "Executive reconnaissance and Origin exposure assessment"
            if professional
            else "Passive-first reconnaissance"
        ),
        "__REPORT_TITLE__": escape(report_title),
        "__REPORT_SUBJECT__": escape(report_subject),
        "__DOMAINS__": escape(domains),
        "__GENERATED__": escape(data["generated_at"]),
        "__VERSION__": escape(data["version"]),
        "__COUNTS__": counts,
        "__SUBDOMAIN_NOTE__": escape(subdomain_note),
        "__SCOPE_NOTE__": escape(data["scope_policy"]["note"]),
        "__ORIGIN_SUMMARY__": escape(
            (
                f"Mode {origin.get('mode', 'not run')}; CDN/WAF {origin.get('cdn_waf_detected', {}).get('provider', 'Unknown')}; "
                f"{origin.get('candidates_collected', 0)} candidates; {origin.get('direct_requests_performed', 0)} direct requests. "
                f"Origin IP: {origin.get('origin_ip') or origin.get('highest_confidence_candidate') or 'none'} "
                f"({origin.get('origin_probability_percent', origin.get('confidence_score', 0))}%, {origin.get('confidence_band', 'inconclusive')}). "
                f"{origin.get('probability_notice', '')} {origin.get('warning', '')}"
            ) if isinstance(origin, dict) and origin else "Automatic Origin discovery was not run."
        ),
        "__ORIGIN_HERO__": origin_hero,
        "__ORIGIN_TRACE__": origin_trace_html,
        "__ORIGIN_RANKING__": origin_ranking,
        "__GRAPH_ORIGIN_ALERT__": graph_origin_alert,
        "__AI_PANEL__": ai_panel,
        "__REMEDIATION_PANEL__": remediation_panel,
        "__KEY_FINDINGS__": key_cards,
        "__TOOL_FINDINGS__": tool_findings_panel,
        "__ZONE_WARNING__": zone_warning,
        **tables,
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)
    return template.replace("__REPORT_JSON__", report_json)
