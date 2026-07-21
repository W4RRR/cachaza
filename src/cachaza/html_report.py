"""Interactive, self-contained HTML report renderer."""

from __future__ import annotations

import json
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


def render_html(data: dict[str, Any]) -> str:
    """Render every finding plus a relationship graph without external assets."""
    network = data["network_intelligence"]
    origin = data.get("origin_discovery", {})
    origin_rows = []
    if isinstance(origin, dict):
        for group in ("primary", "additional", "historical", "related_infrastructure"):
            for item in origin.get(group, []) if isinstance(origin.get(group, []), list) else []:
                origin_rows.append(
                    [
                        str(item.get("ip") or "-"),
                        str(item.get("initial_score", 0)),
                        str(item.get("final_score", 0)),
                        str(item.get("classification") or "inconclusive"),
                        group.replace("_", " "),
                        ", ".join(item.get("rejection_reasons", [])),
                    ]
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
        "__PROVIDER_TABLE__": _table(
            ["Provider", "Status", "Findings", "Diagnostic"],
            [
                [
                    provider,
                    str(status.get("status") or "unknown"),
                    str(status.get("findings", 0)),
                    str(status.get("error") or "-"),
                ]
                for provider, status in sorted(data.get("provider_status", {}).items())
                if isinstance(status, dict)
            ],
        ),
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
            ["IP", "Initial score", "Final score", "Classification", "Group", "Rejection reason"],
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
    key_labels = (
        ("wafs", "WAFs"),
        ("api_key_candidates", "API key/secret candidates"),
        ("api_endpoints", "API endpoints"),
        ("subdomains", "Actionable subdomains"),
        ("emails", "Emails"),
        ("phones", "Phones"),
        ("addresses", "Addresses"),
        ("zone_transfer_allowed", "Zone transfer allowed"),
    )
    key_findings = data.get("key_findings", {})
    key_rows: list[list[str]] = []
    for key, label in key_labels:
        values = list(key_findings.get(key, []))
        limit = 13 if key == "subdomains" else 8
        shown = values[:limit]
        suffix = f" (+{len(values) - limit} more on reports)" if len(values) > limit else ""
        if key == "zone_transfer_allowed":
            rendered = "ALLOWED: " + ", ".join(shown) if shown else "Not observed"
        elif key == "wafs" and not shown:
            rendered = "No evidence observed"
        else:
            rendered = ", ".join(shown) if shown else "-"
        key_rows.append([label, str(len(values)), rendered + suffix])
    key_table = _table(["Category", "Count", "Highlights"], key_rows)
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
<title>Cachaza report</title><style>
:root{--bg:#07111f;--panel:#0e1b2d;--soft:#102239;--line:#2b3f5c;--text:#e8f0fa;--muted:#9db0c8;--accent:#53d3a4;--blue:#70b0ff;--domain:#53d3a4;--url:#70b0ff;--ip:#c490ff;--cidr:#ffb86b;--asn:#ff7d9f;--org:#ffd166;--registration:#85e0e0;--cloud:#a7e46f;--other:#9db0c8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,Segoe UI,Arial,sans-serif}button,input,select{font:inherit}button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{outline:3px solid var(--blue);outline-offset:2px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
main{max-width:1280px;margin:auto;padding:38px 24px 70px}header{border:1px solid var(--line);border-radius:18px;padding:30px;background:linear-gradient(135deg,#112641,#0c1b2d)}h1{margin:0;font-size:34px;letter-spacing:.02em}h2{margin:0;font-size:20px}h3{margin:0 0 8px;font-size:15px}.eyebrow{color:var(--accent);font-weight:700;text-transform:uppercase;letter-spacing:.14em}.muted{color:var(--muted)}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}.stat{min-width:120px;padding:13px 16px;text-align:left;border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--muted);cursor:pointer}.stat:hover,.stat[aria-pressed="true"]{border-color:var(--accent);background:var(--soft)}.stat span{display:block;color:var(--text);font-size:24px;font-weight:700}.callout{border-left:4px solid var(--accent);padding:12px 16px;background:#0d201f;border-radius:5px;margin:20px 0}
.zone-warning{margin:12px 0;border:1px solid #ff5d6c;border-left:5px solid #ff5d6c;border-radius:9px;background:rgba(197,50,65,.18);color:#ffd8dc;padding:11px 13px}
.section{margin-top:16px;border:1px solid var(--line);border-radius:14px;background:var(--panel);overflow:hidden}.section>summary{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 18px;cursor:pointer;font-size:18px;font-weight:700;list-style:none}.section>summary::-webkit-details-marker{display:none}.section>summary::after{content:"+";color:var(--accent);font-size:24px}.section[open]>summary::after{content:"−"}.section-body{padding:0 18px 18px}.section-note{margin:0;color:var(--muted)}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;background:var(--panel)}th,td{padding:12px 14px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.08em}tr:last-child td{border-bottom:0}.empty{color:var(--muted)}code{color:var(--accent);overflow-wrap:anywhere}
.controls{display:flex;gap:12px;align-items:end;flex-wrap:wrap;margin-bottom:14px}.field{display:grid;gap:5px;min-width:210px;flex:1}.field span{color:var(--muted);font-size:12px}.field input,.field select,.action{min-height:42px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--text);padding:8px 11px}.action{cursor:pointer;flex:0}.action:hover{border-color:var(--accent)}
.evidence-status{margin:0 0 10px;color:var(--muted)}.finding{border-top:1px solid var(--line)}.finding:first-child{border-top:0}.finding>summary{display:grid;grid-template-columns:minmax(88px,.55fr) minmax(220px,2.5fr) minmax(120px,1fr) auto;gap:12px;align-items:center;padding:12px 2px;cursor:pointer}.finding-kind{color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.finding-value{overflow-wrap:anywhere}.badge{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 8px;color:var(--muted);font-size:12px}.badge.scope{color:var(--accent);border-color:var(--accent)}.finding-body{padding:0 2px 15px 100px}.metadata{display:grid;grid-template-columns:minmax(130px,.5fr) minmax(200px,2fr);gap:0;border:1px solid var(--line);border-radius:9px;overflow:hidden}.metadata dt,.metadata dd{margin:0;padding:8px 11px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.metadata dt{color:var(--muted);background:var(--soft)}.metadata dd{white-space:pre-wrap}.metadata dt:last-of-type,.metadata dd:last-of-type{border-bottom:0}
.graph-shell{position:relative;margin-top:14px;border:1px solid #294566;border-radius:18px;overflow:hidden;background:linear-gradient(145deg,#0d1e33,#0a1728);box-shadow:0 24px 70px rgba(0,0,0,.22)}
.graph-toolbar{display:grid;grid-template-columns:minmax(220px,1fr) auto;gap:12px;align-items:center;padding:14px;border-bottom:1px solid rgba(121,160,205,.2);background:rgba(8,20,35,.74);backdrop-filter:blur(16px)}.graph-search{position:relative;display:flex;align-items:center;max-width:460px}.graph-search::before{content:"⌕";position:absolute;left:13px;color:var(--blue);font-size:20px}.graph-search input{width:100%;height:42px;border:1px solid #315173;border-radius:11px;background:#071523;color:var(--text);padding:8px 38px 8px 38px}.graph-search input::placeholder{color:#7188a4}.graph-search-clear{position:absolute;right:6px;width:30px;height:30px;border:0;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer}.graph-search-clear:hover{background:var(--soft);color:var(--text)}
.graph-actions{display:flex;align-items:center;justify-content:flex-end;gap:7px;flex-wrap:wrap}.graph-action,.layout-button{height:38px;min-width:38px;border:1px solid #315173;border-radius:10px;background:#0b1a2b;color:var(--text);padding:0 11px;cursor:pointer}.graph-action:hover,.layout-button:hover,.layout-button[aria-pressed="true"]{border-color:var(--blue);background:#132a44;color:#fff}.graph-action:active,.layout-button:active{transform:translateY(1px)}.layout-switch{display:inline-flex;padding:3px;border:1px solid #294867;border-radius:11px;background:#071523}.layout-button{height:30px;border:0;background:transparent;color:var(--muted);padding:0 10px}.layout-button[aria-pressed="true"]{background:#1d4f7b;color:#fff}.zoom-range{width:96px;accent-color:var(--blue)}.zoom-value{min-width:46px;color:var(--muted);font-size:12px;text-align:center}
.graph-status-strip{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid rgba(121,160,205,.16);background:rgba(12,31,52,.65)}.graph-metric{display:inline-flex;align-items:center;gap:6px;border:1px solid rgba(112,176,255,.22);border-radius:999px;padding:4px 9px;color:var(--muted);font-size:12px}.graph-metric strong{color:var(--text)}.graph-selection-status{margin-left:auto;color:var(--blue);font-size:12px;overflow-wrap:anywhere}
.graph-layout{display:grid;grid-template-columns:minmax(0,1fr) 310px;min-height:680px}.graph-canvas{position:relative;min-width:0;height:680px;overflow:hidden;background:radial-gradient(circle at 18% 15%,rgba(37,91,142,.34),transparent 34%),radial-gradient(circle at 80% 75%,rgba(83,211,164,.12),transparent 30%),#071421;isolation:isolate}.graph-canvas::before{content:"";position:absolute;inset:0;pointer-events:none;background-image:radial-gradient(rgba(123,165,211,.22) 1px,transparent 1px);background-size:24px 24px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.8),transparent 94%)}#relationship-graph{position:relative;z-index:1;display:block;width:100%;height:680px;touch-action:none;cursor:grab;user-select:none}#relationship-graph.is-panning{cursor:grabbing}
.graph-help{position:absolute;z-index:2;left:14px;bottom:14px;max-width:520px;border:1px solid rgba(112,176,255,.2);border-radius:10px;background:rgba(5,15,26,.82);color:#94a9c1;padding:7px 10px;font-size:11px;pointer-events:none;backdrop-filter:blur(10px)}.graph-tooltip{position:absolute;z-index:6;display:none;width:min(300px,calc(100% - 24px));border:1px solid #41678e;border-radius:13px;background:rgba(8,21,36,.96);box-shadow:0 16px 45px rgba(0,0,0,.42);padding:12px;pointer-events:none;backdrop-filter:blur(14px)}.graph-tooltip.visible{display:block}.tooltip-kind{color:var(--blue);font-size:10px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.tooltip-title{margin-top:3px;color:#fff;font-weight:700;overflow-wrap:anywhere}.tooltip-meta{margin-top:7px;color:var(--muted);font-size:12px}
.graph-inspector{min-width:0;border-left:1px solid rgba(121,160,205,.2);background:linear-gradient(180deg,rgba(14,33,55,.96),rgba(8,21,36,.96));padding:18px;overflow:auto}.inspector-empty{display:grid;place-items:center;min-height:300px;text-align:center;color:var(--muted)}.inspector-empty-icon{display:grid;place-items:center;width:62px;height:62px;margin:0 auto 12px;border:1px dashed #426486;border-radius:18px;color:var(--blue);font-size:26px}.inspector-hero{display:flex;gap:12px;align-items:center;padding-bottom:15px;border-bottom:1px solid var(--line)}.inspector-icon{display:grid;place-items:center;flex:0 0 50px;height:50px;border-radius:15px;color:#fff;font-weight:800;box-shadow:inset 0 0 0 1px rgba(255,255,255,.2),0 9px 22px rgba(0,0,0,.24)}.inspector-title{min-width:0}.inspector-title h3{margin:0;overflow-wrap:anywhere}.inspector-title p{margin:3px 0 0;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.inspector-badges{display:flex;gap:6px;flex-wrap:wrap;margin:13px 0}.inspector-badge{border:1px solid var(--line);border-radius:999px;padding:3px 8px;color:var(--muted);font-size:11px}.inspector-badge.authorized{border-color:rgba(83,211,164,.55);color:var(--accent)}.inspector-block{margin-top:16px}.inspector-block h4{margin:0 0 8px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.12em}.source-list{display:flex;gap:5px;flex-wrap:wrap}.source-pill{border-radius:7px;background:#122a43;color:#b7c9dc;padding:4px 7px;font-size:11px}.relation-list{display:grid;gap:6px}.relation-item{display:grid;grid-template-columns:8px minmax(0,1fr);gap:8px;width:100%;border:1px solid transparent;border-radius:9px;background:#0a192a;color:var(--text);padding:8px;text-align:left;cursor:pointer}.relation-item:hover{border-color:#315b83;background:#10253d}.relation-dot{width:8px;height:8px;margin-top:5px;border-radius:50%}.relation-name{display:block;font-size:12px;overflow-wrap:anywhere}.relation-kind{display:block;margin-top:2px;color:var(--muted);font-size:10px}.inspector-facts{display:grid;grid-template-columns:auto 1fr;gap:6px 9px;margin:0}.inspector-facts dt{color:var(--muted);font-size:11px}.inspector-facts dd{margin:0;overflow-wrap:anywhere;font-size:12px}
.edge{fill:none;stroke:#42617e;stroke-width:1.35;opacity:.38;vector-effect:non-scaling-stroke;transition:opacity .18s,stroke .18s,stroke-width .18s}.edge.active{stroke:#78d8ff;stroke-width:2.8;opacity:1;filter:drop-shadow(0 0 5px rgba(112,176,255,.65))}.edge.dim,.edge.filtered{opacity:.035}.edge-label{fill:#d6e7f7;font-size:10px;font-weight:700;paint-order:stroke;stroke:#071421;stroke-width:4px;stroke-linejoin:round;pointer-events:none;opacity:0}.edge-label.active{opacity:1}.edge-label.filtered{display:none}
.node-card{cursor:pointer;outline:none;transition:opacity .18s}.node-card .node-position{transition:transform .45s cubic-bezier(.2,.8,.2,1)}.node-card.dim{opacity:.12}.node-card.filtered{display:none}.node-card.match .node-halo{opacity:.85;stroke-width:4}.node-card.active .node-halo{opacity:1;stroke:#fff;stroke-width:4;filter:drop-shadow(0 0 12px rgba(112,176,255,.9))}.node-card.related .node-halo{opacity:.78}.node-halo{fill:rgba(5,16,28,.9);stroke-width:2.5;opacity:.58;vector-effect:non-scaling-stroke;transition:all .18s}.node-core{stroke:rgba(255,255,255,.65);stroke-width:1.5;vector-effect:non-scaling-stroke}.node-icon{fill:#fff;font-size:11px;font-weight:900;text-anchor:middle;dominant-baseline:central;pointer-events:none}.node-info-bg{fill:rgba(9,25,42,.94);stroke:#345473;stroke-width:1;vector-effect:non-scaling-stroke;filter:drop-shadow(0 6px 8px rgba(0,0,0,.25))}.node-title{fill:#eff7ff;font-size:11px;font-weight:700}.node-meta{fill:#8fa8c2;font-size:8.5px;text-transform:uppercase}.node-scope{stroke:none}.node-card:hover .node-info-bg,.node-card:focus .node-info-bg{stroke:#70b0ff;stroke-width:1.8}.node-card:hover .node-halo{opacity:1}.zoomed-out .node-info{opacity:0;pointer-events:none}.zoomed-out .node-card.active .node-info,.zoomed-out .node-card.related .node-info,.zoomed-out .node-card.match .node-info{opacity:1}.cluster-label{fill:#9fb5ca;font-size:12px;font-weight:800;letter-spacing:.1em;text-anchor:middle;text-transform:uppercase;paint-order:stroke;stroke:#071421;stroke-width:5px}.cluster-orbit{fill:rgba(18,43,70,.18);stroke:rgba(112,176,255,.18);stroke-width:1.2;stroke-dasharray:4 8;vector-effect:non-scaling-stroke}
.legend{display:flex;gap:7px;flex-wrap:wrap;padding:12px 14px;border-top:1px solid rgba(121,160,205,.18);background:rgba(8,20,35,.78)}.legend-item{display:inline-flex;align-items:center;gap:7px;border:1px solid #294866;border-radius:999px;background:#0a192a;color:var(--muted);padding:5px 9px;cursor:pointer;font-size:11px}.legend-item:hover,.legend-item[aria-pressed="true"]{border-color:#70b0ff;background:#132a44;color:#fff}.legend-item[aria-pressed="false"]{opacity:.42}.legend-dot{width:10px;height:10px;border-radius:4px;box-shadow:0 0 10px currentColor}.graph-shell.is-expanded{position:fixed;z-index:1000;inset:10px;margin:0;background:#071421}.graph-shell.is-expanded .graph-canvas,.graph-shell.is-expanded #relationship-graph{height:calc(100vh - 190px)}.graph-shell.is-expanded .graph-layout{min-height:calc(100vh - 190px)}body.graph-expanded{overflow:hidden}
@media(max-width:900px){.graph-toolbar{grid-template-columns:1fr}.graph-actions{justify-content:flex-start}.graph-search{max-width:none}.graph-layout{grid-template-columns:1fr}.graph-inspector{border-left:0;border-top:1px solid var(--line);max-height:380px}.graph-selection-status{width:100%;margin-left:0}.graph-canvas,#relationship-graph{height:580px}.graph-layout{min-height:0}}
@media(max-width:760px){main{padding:20px 12px 44px}header{padding:22px 18px}.stat{min-width:calc(50% - 6px);flex:1}.finding>summary{grid-template-columns:85px 1fr}.finding-source,.finding>summary .badge{display:none}.finding-body{padding-left:2px}.metadata{grid-template-columns:1fr}.metadata dt{border-bottom:0}.graph-canvas,#relationship-graph{height:480px}.zoom-range,.zoom-value{display:none}.graph-help{right:12px}.graph-action,.layout-button{padding:0 8px}.graph-shell.is-expanded{inset:0;border-radius:0}.graph-shell.is-expanded .graph-canvas,.graph-shell.is-expanded #relationship-graph{height:calc(100vh - 235px)}}
@media(prefers-color-scheme:light){:root{--bg:#f5f8fc;--panel:#fff;--soft:#edf4fb;--line:#c8d5e4;--text:#102238;--muted:#526a83;--accent:#087a5b;--blue:#176fc1}header{background:linear-gradient(135deg,#e8f2ff,#f7fbff)}.callout{background:#eaf8f1}.graph-shell{background:#f7fbff;box-shadow:0 18px 50px rgba(56,90,122,.18)}.graph-toolbar,.graph-status-strip,.legend{background:rgba(240,247,253,.94)}.graph-search input,.graph-action,.layout-switch,.legend-item{background:#fff;color:var(--text)}.graph-canvas{background:radial-gradient(circle at 20% 10%,#d9ebfa,transparent 38%),#f7fbff}.graph-inspector{background:#f0f6fc}.graph-help,.graph-tooltip{background:rgba(255,255,255,.96);color:var(--muted)}.tooltip-title{color:var(--text)}.node-info-bg{fill:rgba(255,255,255,.97);stroke:#9bb4cc}.node-title{fill:#102238}.node-meta{fill:#526a83}.edge-label{fill:#284b6c;stroke:#f7fbff}.cluster-label{fill:#526a83;stroke:#f7fbff}.relation-item{background:#fff}.source-pill{background:#e1edf8;color:#34506b}}
.node-position{transition:none!important}.node-count-bg{fill:#071421;stroke:rgba(255,255,255,.8);stroke-width:1.2;vector-effect:non-scaling-stroke}.node-count{fill:#fff;font-size:7px;font-weight:900;text-anchor:middle;dominant-baseline:central;pointer-events:none}.zoomed-out .node-card.related .node-info{opacity:0}
@media(prefers-color-scheme:light){.zone-warning{background:#fff0f1;color:#8f2530}}
</style></head><body><main>
<header><div class="eyebrow">Passive-first reconnaissance</div><h1>Cachaza</h1><p>__DOMAINS__</p><p class="muted">Generated __GENERATED__ &middot; version __VERSION__</p><div class="stats" aria-label="Finding counts. Select a type to filter the evidence below.">__COUNTS__</div></header>
<div class="callout"><strong>Scope guard:</strong> __SCOPE_NOTE__</div>
<details class="section" open id="key-findings-section"><summary>Key findings</summary><div class="section-body"><p class="section-note">__SUBDOMAIN_NOTE__ Actionable subdomains are capped at 13 here; complete evidence remains in JSON/CSV.</p>__ZONE_WARNING____KEY_FINDINGS__</div></details>
<details class="section" open id="origin-discovery-section"><summary>Automatic Origin discovery</summary><div class="section-body"><p class="section-note">__ORIGIN_SUMMARY__</p>__ORIGIN_TABLE__</div></details>
<details class="section" open id="graph-section"><summary>Interactive relationship explorer</summary><div class="section-body"><p class="section-note">Explore correlations between domains, addresses, infrastructure, technologies and evidence. Search or filter to focus a dense graph.</p><div class="graph-shell" id="graph-shell"><div class="graph-toolbar"><label class="graph-search"><span class="sr-only">Search graph nodes</span><input id="graph-search" type="search" placeholder="Find a domain, IP, ASN, technology…" autocomplete="off"><button class="graph-search-clear" id="clear-graph-search" type="button" title="Clear graph search" aria-label="Clear graph search">×</button></label><div class="graph-actions" role="toolbar" aria-label="Graph controls"><div class="layout-switch" role="group" aria-label="Graph layout"><button class="layout-button" id="layout-network" type="button" aria-pressed="true">Network</button><button class="layout-button" id="layout-groups" type="button" aria-pressed="false">Groups</button></div><button class="graph-action" id="zoom-out" type="button" title="Zoom out" aria-label="Zoom out">&minus;</button><input class="zoom-range" id="graph-zoom" type="range" min="25" max="260" value="100" step="5" aria-label="Graph zoom"><output class="zoom-value" id="graph-zoom-value">100%</output><button class="graph-action" id="zoom-in" type="button" title="Zoom in" aria-label="Zoom in">+</button><button class="graph-action" id="fit-graph" type="button" title="Fit all visible nodes">Fit</button><button class="graph-action" id="fullscreen-graph" type="button" title="Expand graph" aria-label="Expand graph">&#x26F6;</button><button class="graph-action" id="reset-graph" type="button" title="Reset filters and layout">Reset</button></div></div><div class="graph-status-strip"><span class="graph-metric"><strong id="visible-node-count">0</strong> nodes</span><span class="graph-metric"><strong id="visible-edge-count">0</strong> relationships</span><span class="graph-metric"><strong id="visible-kind-count">0</strong> types</span><span class="graph-selection-status" id="graph-selection-status">Select a node to reveal its correlation path</span></div><div class="graph-layout"><div class="graph-canvas" id="graph-canvas"><svg id="relationship-graph" role="img" aria-labelledby="graph-title graph-description"><title id="graph-title">Reconnaissance relationship graph</title><desc id="graph-description">Interactive network of domains, addresses, infrastructure, technologies and evidence.</desc></svg><div class="graph-tooltip" id="graph-tooltip" role="tooltip"></div><div class="graph-help">Wheel or +/− to zoom · drag the background to pan · drag nodes to reorganize · double-click a node to focus</div></div><aside class="graph-inspector" id="graph-inspector" aria-live="polite"><div class="inspector-empty"><div><div class="inspector-empty-icon">◎</div><h3>Nothing selected</h3><p>Select a node to inspect its evidence and connected relationships.</p></div></div></aside></div><div class="legend" id="graph-legend" aria-label="Filter nodes by type"></div></div></div></details>
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

const svg=document.getElementById("relationship-graph"),shell=document.getElementById("graph-shell"),canvas=document.getElementById("graph-canvas"),tooltip=document.getElementById("graph-tooltip"),inspector=document.getElementById("graph-inspector"),graphSearch=document.getElementById("graph-search"),zoomSlider=document.getElementById("graph-zoom"),zoomOutput=document.getElementById("graph-zoom-value"),selectionStatus=document.getElementById("graph-selection-status");
const graph=report.graph||{nodes:[],edges:[]},nodes=Array.isArray(graph.nodes)?graph.nodes.map(node=>({...node})):[],byId=new Map(nodes.map(node=>[node.id,node])),edges=(Array.isArray(graph.edges)?graph.edges:[]).filter(edge=>byId.has(edge.source)&&byId.has(edge.target));
const order=["domain","url","api_endpoint","email","phone","address","waf","dns_zone_transfer","ip","cidr","asn","organization","network_registration","service","technology","whois","cloud_asset","cloud_provider","fingerprint"],present=[...new Set(nodes.map(node=>node.kind))];
present.sort((a,b)=>{const ai=order.indexOf(a),bi=order.indexOf(b);return(ai<0?999:ai)-(bi<0?999:bi)||a.localeCompare(b)});
const groups=new Map(present.map(kind=>[kind,nodes.filter(node=>node.kind===kind)])),activeKinds=new Set(present),adjacency=new Map(nodes.map(node=>[node.id,[]]));
edges.forEach(edge=>{adjacency.get(edge.source)?.push(edge);adjacency.get(edge.target)?.push(edge)});nodes.forEach(node=>node.degree=adjacency.get(node.id)?.length||0);
const styles={domain:{color:"#3ddc97",icon:"D"},url:{color:"#4da3ff",icon:"↗"},api_endpoint:{color:"#38bdf8",icon:"API"},email:{color:"#f0abfc",icon:"@"},phone:{color:"#fbbf24",icon:"T"},address:{color:"#a3e635",icon:"A"},waf:{color:"#fb7185",icon:"WAF"},dns_zone_transfer:{color:"#ef4444",icon:"AX"},ip:{color:"#b779ff",icon:"IP"},cidr:{color:"#ff9f43",icon:"/"},asn:{color:"#ff5d8f",icon:"AS"},organization:{color:"#f7c948",icon:"O"},network_registration:{color:"#35d0ba",icon:"R"},service:{color:"#fb7185",icon:":"},technology:{color:"#22d3ee",icon:"{}"},whois:{color:"#94a3b8",icon:"W"},cloud_asset:{color:"#8ee34d",icon:"☁"},cloud_provider:{color:"#5ee3a1",icon:"C"},fingerprint:{color:"#a78bfa",icon:"#"},other:{color:"#94a3b8",icon:"•"}},styleFor=kind=>styles[kind]||styles.other,kindName=kind=>String(kind||"finding").replaceAll("_"," ");
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
  const positions=new Map(),columns=Math.min(3,Math.max(1,Math.ceil(Math.sqrt(present.length)))),cellWidth=560,cellHeight=510;
  present.forEach((kind,groupIndex)=>{const group=[...(groups.get(kind)||[])].sort((a,b)=>b.degree-a.degree||a.label.localeCompare(b.label)),column=groupIndex%columns,row=Math.floor(groupIndex/columns),center={x:300+column*cellWidth,y:285+row*cellHeight};group.forEach((node,index)=>{if(index===0){positions.set(node.id,{...center});return}const angle=index*2.399963229728653,radius=52+Math.sqrt(index)*27;positions.set(node.id,{x:center.x+Math.cos(angle)*radius,y:center.y+Math.sin(angle)*radius})})});
  return positions
}
const networkPositions=networkLayout(),groupPositions=groupedLayout(),clusterGuides=[];
present.forEach(kind=>{const group=groups.get(kind)||[],points=group.map(node=>groupPositions.get(node.id)).filter(Boolean),center=points[0]||{x:width/2,y:height/2},radius=Math.max(82,...points.map(point=>Math.hypot(point.x-center.x,point.y-center.y)+38)),container=makeSvg("g",{display:"none"}),orbit=makeSvg("circle",{class:"cluster-orbit",cx:center.x,cy:center.y,r:radius}),label=makeSvg("text",{class:"cluster-label",x:center.x,y:center.y-radius-18});label.textContent=`${kindName(kind)} · ${group.length}`;container.append(orbit,label);orbitLayer.append(container);clusterGuides.push(container)});
nodes.forEach(node=>{const position=networkPositions.get(node.id)||{x:width/2,y:height/2};node.x=position.x;node.y=position.y});
const edgeElements=edges.map((edge,index)=>{const path=makeSvg("path",{class:"edge","data-source":edge.source,"data-target":edge.target,"marker-end":"url(#edge-arrow)"}),label=makeSvg("text",{class:"edge-label","text-anchor":"middle"}),title=makeSvg("title");title.textContent=edge.relationship;label.textContent=edge.relationship;path.append(title);edgeLayer.append(path);edgeLabelLayer.append(label);return{edge,path,label,index}}),nodeElements=new Map();
const short=(value,limit=22)=>String(value||"").length>limit?String(value).slice(0,limit-1)+"…":String(value||"-");
nodes.forEach(node=>{
  const visual=styleFor(node.kind),outer=makeSvg("g",{class:"node-card",role:"button",tabindex:"0","aria-label":`${kindName(node.kind)}: ${node.label}`}),position=makeSvg("g",{class:"node-position",transform:`translate(${node.x} ${node.y})`}),halo=makeSvg("circle",{class:"node-halo",r:"29",stroke:visual.color}),core=makeSvg("circle",{class:"node-core",r:"21",fill:visual.color}),icon=makeSvg("text",{class:"node-icon",x:"0",y:"1"}),info=makeSvg("g",{class:"node-info"}),infoBg=makeSvg("rect",{class:"node-info-bg",x:"31",y:"-24",width:"178",height:"48",rx:"10"}),scopeBar=makeSvg("rect",{class:"node-scope",x:"38",y:"-15",width:"4",height:"30",rx:"2",fill:node.in_scope?"#3ddc97":"#f6b94a"}),title=makeSvg("text",{class:"node-title",x:"49",y:"-5"}),meta=makeSvg("text",{class:"node-meta",x:"49",y:"12"}),nativeTitle=makeSvg("title");
  const countBg=makeSvg("circle",{class:"node-count-bg",cx:"17",cy:"-17",r:"9"}),countText=makeSvg("text",{class:"node-count",x:"17",y:"-17"});
  icon.textContent=visual.icon;countText.textContent=node.degree>99?"99+":String(node.degree||node.evidence_count||0);title.textContent=short(node.label);meta.textContent=`${kindName(node.kind)} · ${node.validation||`${node.evidence_count||0} evidence`} · ${node.degree} links`;nativeTitle.textContent=`${kindName(node.kind)}: ${node.label}`;info.append(infoBg,scopeBar,title,meta);position.append(halo,core,icon,countBg,countText,info,nativeTitle);outer.append(position);nodeLayer.append(outer);nodeElements.set(node.id,{outer,position})
});
function updateNode(node){nodeElements.get(node.id)?.position.setAttribute("transform",`translate(${node.x} ${node.y})`)}
function updateEdges(){edgeElements.forEach(({edge,path,label,index})=>{const source=byId.get(edge.source),target=byId.get(edge.target);if(!source||!target)return;const dx=target.x-source.x,dy=target.y-source.y,distance=Math.max(1,Math.hypot(dx,dy)),bend=((index%5)-2)*10+(hashNumber(edge.relationship)-.5)*18,nx=-dy/distance,ny=dx/distance,cx=(source.x+target.x)/2+nx*bend,cy=(source.y+target.y)/2+ny*bend;path.setAttribute("d",`M ${source.x} ${source.y} Q ${cx} ${cy} ${target.x} ${target.y}`);label.setAttribute("x",cx);label.setAttribute("y",cy-5)})}
let selectedNode=null,hoveredNode=null,query="",currentLayout="network",animationId=0,dragNode=null,dragMoved=false,panning=false,panMoved=false,lastPoint=null,view={x:0,y:0,scale:1};
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
  outer.addEventListener("pointerenter",event=>{hoveredNode=node;renderInspector(node);showTooltip(node,event);refreshHighlight()});
  outer.addEventListener("pointermove",positionTooltip);
  outer.addEventListener("pointerleave",()=>{hoveredNode=null;hideTooltip();if(selectedNode)renderInspector(selectedNode);else emptyInspector();refreshHighlight()});
  outer.addEventListener("click",event=>{event.stopPropagation();if(dragMoved){dragMoved=false;return}selectNode(node)});
  outer.addEventListener("dblclick",event=>{event.stopPropagation();selectNode(node);centerOn(node,Math.max(1.55,view.scale))});
  outer.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();selectNode(node);centerOn(node,Math.max(1.3,view.scale))}});
  outer.addEventListener("pointerdown",event=>{dragNode=node;dragMoved=false;outer.setPointerCapture(event.pointerId);event.stopPropagation()})
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
function setLayout(name,animate=true){
  currentLayout=name;document.getElementById("layout-network").setAttribute("aria-pressed",String(name==="network"));document.getElementById("layout-groups").setAttribute("aria-pressed",String(name==="groups"));clusterGuides.forEach(guide=>guide.setAttribute("display",name==="groups"?"":"none"));
  const targets=name==="groups"?groupPositions:networkPositions,starts=new Map(nodes.map(node=>[node.id,{x:node.x,y:node.y}])),token=++animationId;
  if(!animate){nodes.forEach(node=>{const target=targets.get(node.id);if(target){node.x=target.x;node.y=target.y;updateNode(node)}});updateEdges();fitGraph();return}
  const started=performance.now(),duration=520;
  function frame(now){if(token!==animationId)return;const progress=Math.min(1,(now-started)/duration),eased=1-Math.pow(1-progress,3);nodes.forEach(node=>{const start=starts.get(node.id),target=targets.get(node.id);if(!start||!target)return;node.x=start.x+(target.x-start.x)*eased;node.y=start.y+(target.y-start.y)*eased;updateNode(node)});updateEdges();if(progress<1)requestAnimationFrame(frame);else fitGraph()}
  requestAnimationFrame(frame)
}
function updateVisibility(){nodeElements.forEach(({outer},id)=>outer.classList.toggle("filtered",!visible(byId.get(id))));edgeElements.forEach(({edge,path,label})=>{const filtered=!visible(byId.get(edge.source))||!visible(byId.get(edge.target));path.classList.toggle("filtered",filtered);label.classList.toggle("filtered",filtered)});if(selectedNode&&!visible(selectedNode))clearSelection();updateMetrics();refreshHighlight()}
svg.addEventListener("pointerdown",event=>{if(event.target.closest?.(".node-card"))return;panning=true;panMoved=false;lastPoint=svgPoint(event);svg.classList.add("is-panning");svg.setPointerCapture(event.pointerId)});
svg.addEventListener("pointermove",event=>{if(dragNode){const point=graphPoint(event);if(Math.hypot(point.x-dragNode.x,point.y-dragNode.y)>3)dragMoved=true;dragNode.x=point.x;dragNode.y=point.y;updateNode(dragNode);updateEdges()}else if(panning){const point=svgPoint(event),dx=point.x-lastPoint.x,dy=point.y-lastPoint.y;if(Math.hypot(dx,dy)>1)panMoved=true;view.x+=dx;view.y+=dy;lastPoint=point;applyView()}});
function releasePointer(){dragNode=null;panning=false;lastPoint=null;svg.classList.remove("is-panning")}
svg.addEventListener("pointerup",releasePointer);svg.addEventListener("pointercancel",releasePointer);
svg.addEventListener("click",event=>{if(!event.target.closest?.(".node-card")&&!panMoved)clearSelection();panMoved=false});
svg.addEventListener("wheel",event=>{event.preventDefault();setZoom(view.scale*(event.deltaY<0?1.13:.885),svgPoint(event))},{passive:false});
const legend=document.getElementById("graph-legend");
present.forEach(kind=>{const item=document.createElement("button"),dot=document.createElement("span"),label=document.createElement("span");item.type="button";item.className="legend-item";item.setAttribute("aria-pressed","true");item.title=`Show or hide ${kindName(kind)} nodes`;dot.className="legend-dot";dot.style.background=styleFor(kind).color;dot.style.color=styleFor(kind).color;label.textContent=`${kindName(kind)} (${groups.get(kind).length})`;item.append(dot,label);item.addEventListener("click",()=>{if(activeKinds.has(kind)&&activeKinds.size>1){activeKinds.delete(kind);item.setAttribute("aria-pressed","false")}else{activeKinds.add(kind);item.setAttribute("aria-pressed","true")}updateVisibility();fitGraph()});legend.append(item)});
graphSearch.addEventListener("input",()=>{query=graphSearch.value.trim().toLowerCase();refreshHighlight()});
graphSearch.addEventListener("keydown",event=>{if(event.key!=="Enter")return;const first=nodes.find(node=>visible(node)&&matchesQuery(node));if(first){selectNode(first);centerOn(first,Math.max(1.1,view.scale))}});
document.getElementById("clear-graph-search").addEventListener("click",()=>{graphSearch.value="";query="";graphSearch.focus();refreshHighlight()});
document.getElementById("layout-network").addEventListener("click",()=>setLayout("network"));document.getElementById("layout-groups").addEventListener("click",()=>setLayout("groups"));
document.getElementById("zoom-in").addEventListener("click",()=>setZoom(view.scale*1.2));document.getElementById("zoom-out").addEventListener("click",()=>setZoom(view.scale/1.2));zoomSlider.addEventListener("input",()=>setZoom(Number(zoomSlider.value)/100));document.getElementById("fit-graph").addEventListener("click",fitGraph);
document.getElementById("fullscreen-graph").addEventListener("click",()=>{const expanded=shell.classList.toggle("is-expanded");document.body.classList.toggle("graph-expanded",expanded);document.getElementById("fullscreen-graph").title=expanded?"Exit expanded view":"Expand graph";setTimeout(fitGraph,80)});
document.addEventListener("keydown",event=>{if(event.key==="Escape"&&shell.classList.contains("is-expanded")){shell.classList.remove("is-expanded");document.body.classList.remove("graph-expanded");setTimeout(fitGraph,80)}});
document.getElementById("reset-graph").addEventListener("click",()=>{graphSearch.value="";query="";activeKinds.clear();present.forEach(kind=>activeKinds.add(kind));legend.querySelectorAll(".legend-item").forEach(item=>item.setAttribute("aria-pressed","true"));clearSelection();updateVisibility();setLayout("network")});
if(nodes.length){nodes.forEach(updateNode);updateEdges();updateVisibility();requestAnimationFrame(fitGraph)}else{const empty=makeSvg("text",{x:width/2,y:height/2,"text-anchor":"middle",class:"cluster-label"});empty.textContent="No relationship data was collected";viewport.append(empty);updateMetrics();applyView()}
})();
</script></body></html>"""
    template = template.replace(
        "Explore correlations between domains, addresses, infrastructure, technologies and evidence. Search or filter to focus a dense graph.",
        "Explore correlations between domains, addresses, infrastructure, technologies and evidence. Hover a node to preview it in the right panel; click to keep it selected.",
    ).replace(
        "Select a node to reveal its correlation path",
        "Hover or select a node to reveal its correlation path",
    ).replace(
        "Select a node to inspect its evidence and connected relationships.",
        "Hover or select a node to inspect its evidence and connected relationships.",
    )
    replacements = {
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
                f"Highest confidence: {origin.get('highest_confidence_candidate') or 'none'} ({origin.get('confidence_score', 0)}/100). "
                f"{origin.get('warning', '')}"
            ) if isinstance(origin, dict) and origin else "Automatic Origin discovery was not run."
        ),
        "__KEY_FINDINGS__": key_table,
        "__ZONE_WARNING__": zone_warning,
        **tables,
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)
    return template.replace("__REPORT_JSON__", report_json)
