"""Normalize WAF observations from wafw00f, Nuclei, and Nmap."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from ..models import Finding, TargetSpec
from .common import clean_text, json_records, url_in_scope


UNKNOWN_WAF = "WAF detected (vendor unknown)"
NEGATIVE = re.compile(
    r"no waf|not behind (?:a )?waf|does not seem to be behind|could not detect|"
    r"no web application firewall",
    re.IGNORECASE,
)
VENDOR_PATTERNS = (
    re.compile(r"behind\s+(?:an?\s+)?(?P<vendor>.+?)\s+WAF\b", re.IGNORECASE),
    re.compile(r"is protected by\s+(?P<vendor>.+?)(?:\.|$)", re.IGNORECASE),
    re.compile(r"waf(?: detection| detected| product)?\s*[:=]\s*(?P<vendor>[^\r\n,;]+)", re.IGNORECASE),
)


def _vendor(text: str) -> str | None:
    cleaned = clean_text(text, 1_000)
    if not cleaned or NEGATIVE.search(cleaned):
        return None
    for pattern in VENDOR_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            value = match.group("vendor").strip()
            value = re.sub(r"\s+\([^)]*\)\s*$", "", value).strip(" .:-[]()")
            if value and value.lower() not in {"a", "the", "unknown"}:
                return value[:200]
    if re.search(r"\bwaf\b|web application firewall", cleaned, re.IGNORECASE):
        return UNKNOWN_WAF
    return None


def _finding(source: str, value: str, url: str, target: TargetSpec, raw: str) -> Finding:
    return Finding(
        "waf",
        source,
        "waf",
        value,
        url_in_scope(url, target),
        {
            "target": url,
            "confidence": "detected" if value != UNKNOWN_WAF else "candidate",
            "requires_manual_validation": value == UNKNOWN_WAF,
            "evidence": clean_text(raw, 1_000),
        },
    )


def parse_wafw00f(text: str, url: str, target: TargetSpec) -> list[Finding]:
    """Parse human or JSON wafw00f output without trusting terminal formatting."""
    findings: list[Finding] = []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    records = payload if isinstance(payload, list) else [payload] if isinstance(payload, dict) else []
    for row in records:
        if not isinstance(row, dict):
            continue
        detected = row.get("detected")
        raw_vendor = row.get("firewall") or row.get("waf") or row.get("manufacturer")
        if detected is False:
            continue
        if isinstance(raw_vendor, list):
            candidates = raw_vendor
        else:
            candidates = [raw_vendor]
        for candidate in candidates:
            value = clean_text(candidate, 200)
            if value:
                findings.append(_finding("wafw00f", value, url, target, json.dumps(row)))
    if findings:
        return findings
    for line in text.splitlines():
        value = _vendor(line)
        if value:
            findings.append(_finding("wafw00f", value, url, target, line))
    return findings


def parse_nuclei(text: str, url: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for row in json_records(text):
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        evidence = " ".join(
            str(value)
            for value in (
                info.get("name"),
                row.get("matcher-name") or row.get("matcher_name"),
                row.get("extracted-results") or row.get("extracted_results"),
            )
            if value
        )
        template_id = str(row.get("template-id") or row.get("template_id") or "")
        matcher = clean_text(row.get("matcher-name") or row.get("matcher_name"), 200)
        if template_id.endswith("waf-detect") and matcher:
            value = " ".join(part.upper() if part.lower() in {"aws", "f5"} else part.title() for part in matcher.split("-"))
        else:
            value = _vendor(evidence)
        if not value and template_id.endswith("waf-detect"):
            value = UNKNOWN_WAF
        if value:
            finding = _finding("nuclei/waf-detect", value, url, target, evidence)
            finding.metadata["template_id"] = template_id
            findings.append(finding)
    return findings


def parse_nmap_xml(text: str, url: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return findings
    for script in root.findall(".//script"):
        script_id = str(script.get("id") or "")
        if script_id not in {"http-waf-detect", "http-waf-fingerprint"}:
            continue
        evidence = str(script.get("output") or "")
        # http-waf-detect reports a positive observation followed by its test
        # URL. That URL is evidence, never the vendor name.
        value = UNKNOWN_WAF if script_id == "http-waf-detect" and not NEGATIVE.search(evidence) and re.search(r"\bWAF detected\b", evidence, re.I) else _vendor(evidence)
        if value:
            finding = _finding(f"nmap/{script_id}", value, url, target, evidence)
            finding.metadata["script"] = script_id
            findings.append(finding)
    return findings
