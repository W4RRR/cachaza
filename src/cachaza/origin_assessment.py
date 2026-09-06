"""Deterministic origin attribution and remediation policy."""
from __future__ import annotations
from typing import Any

def _build_origin_trace(origin: dict[str, Any]) -> dict[str, Any]:
    """Explain how the leading Origin IP was reached without inflating certainty."""

    if not isinstance(origin, dict):
        return {}
    origin_ip = str(
        origin.get("origin_ip") or origin.get("highest_confidence_candidate") or ""
    ).strip()
    if not origin_ip:
        return {}
    primary_rows = origin.get("primary", [])
    primary = next(
        (
            item
            for item in primary_rows
            if isinstance(item, dict) and str(item.get("ip") or "") == origin_ip
        ),
        {},
    )
    evidence = [item for item in primary.get("evidence", []) if isinstance(item, dict)]
    source_families = sorted(
        {
            str(value)
            for value in primary.get("independent_source_families", [])
            if str(value).strip()
        }
        | {
            str(item.get("source_family"))
            for item in evidence
            if str(item.get("source_family") or "").strip()
        }
    )
    passive_evidence = [
        item
        for item in evidence
        if item.get("source_family")
        not in {"direct_validation", "correlation", "network_classification"}
    ]
    direct_evidence = [
        item for item in evidence if item.get("source_family") == "direct_validation"
    ]
    positive_direct = [
        item for item in direct_evidence if int(item.get("score", 0) or 0) > 0
    ]
    direct_requests = int(origin.get("direct_requests_performed", 0) or 0)
    classification = str(origin.get("classification") or "inconclusive")
    validation_status = str(primary.get("validation_status") or "not_validated")
    direct_family_present = "direct_validation" in source_families
    direct_match_present = bool(positive_direct)
    direct_path_validated = bool(
        direct_requests
        and direct_match_present
        and classification
        in {"high_confidence_origin", "probable_origin", "possible_origin"}
        and validation_status not in {"protected_origin", "not_matching", "not_directly_reachable", "inconclusive"}
    )
    protected = classification == "protected_origin" or validation_status == "protected_origin"
    cdn = origin.get("cdn_waf_detected", {})
    provider = str(cdn.get("provider") or "").casefold() if isinstance(cdn, dict) else ""
    boundary_observed = provider not in {"", "unknown", "no cdn detected", "none"}
    direct_reachable = direct_path_validated
    direct_path_validated = direct_reachable and boundary_observed
    if direct_reachable and not boundary_observed:
        status = "direct_reachable_no_boundary"
        status_label = "Direct application path validated; CDN/WAF boundary not established"
        severity = "information"
    elif direct_path_validated:
        status = "direct_path_validated"
        status_label = "CDN/WAF boundary bypass validated"
        severity = "critical"
    elif protected:
        status = "origin_protected"
        status_label = "Origin correlated; direct ingress remains protected"
        severity = "warning"
    elif direct_requests:
        status = "direct_validation_inconclusive"
        status_label = "Direct validation inconclusive"
        severity = "warning"
    else:
        status = "passive_correlation_only"
        status_label = "Likely origin; direct validation not performed"
        severity = "information"
    cdn = origin.get("cdn_waf_detected", {})
    cdn_provider = str(cdn.get("provider") or "Unknown") if isinstance(cdn, dict) else "Unknown"
    cdn_signals = [
        str(value)
        for value in (cdn.get("signals", []) if isinstance(cdn, dict) else [])
        if str(value).strip()
    ]
    passive_tools = sorted(
        {
            str(item.get("source") or item.get("source_family"))
            for item in passive_evidence
            if str(item.get("source") or item.get("source_family") or "").strip()
        }
        or {value for value in source_families if value != "direct_validation"}
    )
    validation_signals = [
        str(item.get("description") or item.get("code"))
        for item in positive_direct
        if str(item.get("description") or item.get("code") or "").strip()
    ]
    if direct_family_present and not validation_signals:
        validation_signals.append("Direct HTTP/TLS correlation recorded")
    passive_signals = [
        str(item.get("description") or item.get("code"))
        for item in passive_evidence
        if str(item.get("description") or item.get("code") or "").strip()
    ]
    probability = int(
        origin.get("origin_probability_percent", origin.get("confidence_score", 0)) or 0
    )
    steps = [
        {
            "number": 1,
            "tactic": "Establish reference",
            "technique": "Public edge baseline",
            "procedure": f"Captured the target's public DNS, HTTP and TLS posture. Edge assessment: {cdn_provider}.",
            "tools": ["DNS", "HTTP", "TLS"],
            "evidence": cdn_signals,
            "status": "completed",
            "relationship": "public baseline",
        },
        {
            "number": 2,
            "tactic": "Discover candidate infrastructure",
            "technique": "Passive origin correlation",
            "procedure": (
                "Collected historical/current resolution, certificate, scan-index and "
                "provider observations, then retained candidate public addresses."
            ),
            "tools": passive_tools or ["normalized OSINT evidence"],
            "evidence": passive_signals,
            "status": "completed",
            "relationship": "candidate discovery",
        },
        {
            "number": 3,
            "tactic": "Separate edge from origin",
            "technique": "CDN/WAF range exclusion and scoring",
            "procedure": (
                "Rejected known CDN, private, mail-only and clearly third-party infrastructure; "
                "deduplicated source families and applied the bounded correlation score."
            ),
            "tools": ["network classifier", "correlation engine"],
            "evidence": [
                f"{len(source_families)} independent source families",
                f"{origin.get('candidates_rejected_before_validation', 0)} candidates rejected before validation",
            ],
            "status": "completed",
            "relationship": "edge exclusion & scoring",
        },
        {
            "number": 4,
            "tactic": "Validate direct exposure",
            "technique": "Authorized direct-origin HTTP/TLS validation",
            "procedure": (
                "Connected to the candidate IP using only bounded HEAD/GET requests while "
                "preserving the target hostname in HTTP Host and TLS SNI, then compared "
                "certificates, redirects, content fingerprints, titles, cookies, headers and static assets."
            ),
            "tools": ["Cachaza Direct-origin validator"],
            "evidence": validation_signals,
            "status": (
                "validated" if direct_reachable else "protected" if protected
                else "inconclusive" if direct_requests else "not performed"
            ),
            "relationship": "direct validation",
        },
        {
            "number": 5,
            "tactic": "Conclude attribution",
            "technique": "Evidence-backed origin classification",
            "procedure": (
                f"Ranked {origin_ip} first with a {probability}/100 heuristic correlation score "
                f"and {origin.get('confidence_band', 'inconclusive')} confidence."
            ),
            "tools": ["Cachaza reporting engine"],
            "evidence": [classification, origin.get("probability_notice", "")],
            "status": "completed",
            "relationship": "attribution conclusion",
        },
    ]
    return {
        "status": status,
        "direct_validation": "positive" if direct_reachable else "protected" if protected else "inconclusive" if direct_requests else "not_performed",
        "boundary_observed": boundary_observed,
        "status_label": status_label,
        "severity": severity,
        "origin_ip": origin_ip,
        "origin_ips": [
            str(value) for value in origin.get("origin_ips", [origin_ip]) if str(value).strip()
        ] or [origin_ip],
        "origin_outcomes": [
            {
                "ip": str(item.get("ip") or ""),
                "probability_percent": int(item.get("origin_probability_percent", 0) or 0),
                "confidence_band": str(item.get("confidence_band") or "inconclusive"),
                "classification": str(item.get("classification") or "inconclusive"),
            }
            for item in origin.get("origins", []) if isinstance(item, dict) and item.get("ip")
        ],
        "cdn_waf_provider": cdn_provider,
        "probability_percent": max(0, min(100, probability)),
        "confidence_band": str(origin.get("confidence_band") or "inconclusive"),
        "classification": classification,
        "source_families": source_families,
        "passive_tools": passive_tools,
        "validation_signals": validation_signals,
        "direct_requests": direct_requests,
        "steps": steps,
        "summary": (
            f"{origin_ip} was reached through passive infrastructure correlation, CDN/WAF "
            f"range exclusion and bounded scoring"
            + (
                ", then validated as a directly reachable application path using the original Host/SNI."
                if direct_reachable else ". Direct reachability was not established."
            )
        ),
        "qualification": (
            "Direct reachability alone does not demonstrate a CDN/WAF bypass. A protected public boundary must also be established; ownership and business impact require separate evidence."
        ),
    }


def _build_origin_remediation(trace: dict[str, Any]) -> dict[str, Any]:
    """Return a vendor-neutral, verifiable plan for closing Origin exposure."""

    if not isinstance(trace, dict) or not trace.get("origin_ip"):
        return {}
    exposed = trace.get("status") == "direct_path_validated"
    provider = str(trace.get("cdn_waf_provider") or "the approved edge provider")
    if not trace.get("boundary_observed", True):
        return {
            "posture": "review_architecture",
            "title": "Review the intended public architecture",
            "objective": "A protected CDN/WAF boundary was not established. Confirm whether direct public hosting is intended before treating this as an exposure.",
            "context": "The correlation score and direct validation result are independent of whether an edge-only architecture is required.",
            "actions": [{
                "priority": "P2", "phase": "Validate architecture", "title": "Confirm intended ingress",
                "owner": "Application / network owner",
                "action": "Document the approved public ingress and whether an edge-only policy is required.",
                "verification": "Compare the observed direct path against the approved architecture and document the decision.",
            }],
        }
    origin_ip = str(trace.get("origin_ip"))
    posture = "urgent" if exposed else "precautionary"
    actions = [
        {
            "priority": "P0" if exposed else "P1",
            "phase": "Contain",
            "title": "Restrict public ingress to the Origin",
            "action": (
                f"Allow application ports on {origin_ip} only from the current official "
                f"egress ranges or authenticated private connectivity used by {provider}; "
                "deny every other Internet source at the cloud security group and host firewall."
            ),
            "owner": "Network / cloud operations",
            "verification": (
                "A direct connection to the IP with the production Host header and TLS SNI "
                "must time out, be refused, or return a deliberate deny response from every "
                "non-CDN test network."
            ),
        },
        {
            "priority": "P0" if exposed else "P1",
            "phase": "Authenticate",
            "title": "Require an authenticated edge-to-Origin path",
            "action": (
                "Enable authenticated Origin pulls, mutual TLS, a private tunnel, or an "
                "equivalent cryptographic control so source-IP allowlisting is not the only gate."
            ),
            "owner": "Platform engineering",
            "verification": (
                "Requests that preserve the production hostname but lack the edge credential "
                "must fail before reaching the application."
            ),
        },
        {
            "priority": "P1",
            "phase": "Remove exposure paths",
            "title": "Eliminate records that disclose or reach the Origin",
            "action": (
                "Proxy every public web hostname, remove stale or unproxied A/AAAA records, "
                "close alternate web ports, and review historical environment, staging, mail, "
                "certificate and scan-index correlations that point to the same address."
            ),
            "owner": "DNS / application owners",
            "verification": (
                "Current DNS and service inventories must expose only approved edge addresses; "
                "no alternate hostname or port may serve the production application directly."
            ),
        },
        {
            "priority": "P1",
            "phase": "Rotate and harden",
            "title": "Rotate the address after controls are effective",
            "action": (
                "If operationally possible, move the Origin to a new address only after ingress "
                "controls are active. Configure default virtual hosts to deny unknown Host/SNI "
                "values and minimize identifying banners."
            ),
            "owner": "Infrastructure / application security",
            "verification": (
                "The retired address must no longer expose the service, and the replacement "
                "address must be unreachable outside the authenticated edge path."
            ),
        },
        {
            "priority": "P2",
            "phase": "Retest and monitor",
            "title": "Prove closure and detect regression",
            "action": (
                "Repeat the same Host/SNI direct-origin validation from an external network, "
                "cover all discovered ports, and alert on denied direct requests or DNS changes."
            ),
            "owner": "Security operations",
            "verification": (
                "Document a failed direct-path retest, retain firewall evidence, and schedule "
                "continuous DNS and exposure monitoring."
            ),
        },
    ]
    return {
        "posture": posture,
        "title": "Origin exposure remediation plan",
        "objective": (
            "Make the application reachable only through the approved CDN/WAF path and remove "
            "the infrastructure signals that make direct-Origin rediscovery actionable."
        ),
        "context": (
            "The first control is reachability, not secrecy: historical intelligence can retain "
            "an old address indefinitely, so rotating an IP without enforcing ingress controls "
            "does not resolve the exposure."
        ),
        "actions": actions,
    }
