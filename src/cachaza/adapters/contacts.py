"""Extract public contact details from a small, explicit set of HTML pages."""

from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from typing import Any

from ..models import Finding, TargetSpec
from ..safety import domain_in_scope


EMAIL = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}(?![\w.-])", re.I)
PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s().-]*)?(?:\d[\s().-]*){7,15}\d(?!\w)")
STREET = re.compile(
    r"\b\d{1,6}\s+[A-Z0-9][A-Z0-9 .'-]{2,80}\s+"
    r"(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|loop|way|court|ct)\b"
    r"[^\n|<>]{0,100}",
    re.I,
)


def _decode_cfemail(value: str) -> str | None:
    try:
        raw = bytes.fromhex(value)
        key = raw[0]
        return "".join(chr(byte ^ key) for byte in raw[1:])
    except (ValueError, IndexError):
        return None


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[str] = []
        self.cfemails: list[str] = []
        self.json_ld: list[str] = []
        self._hidden = 0
        self._json = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() in {"script", "style", "noscript", "template"}:
            self._hidden += 1
        if tag.lower() == "script" and values.get("type", "").lower() == "application/ld+json":
            self._json = True
            self._hidden = max(0, self._hidden - 1)
        href = values.get("href", "")
        if href.lower().startswith(("mailto:", "tel:")):
            self.links.append(href)
        encoded = values.get("data-cfemail", "")
        if encoded:
            self.cfemails.append(encoded)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._json:
            self._json = False
            return
        if tag.lower() in {"script", "style", "noscript", "template"} and self._hidden:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        if self._json:
            self.json_ld.append(data)
        elif not self._hidden:
            self.parts.append(data)


def _json_addresses(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        if value.get("@type") == "PostalAddress" or "streetAddress" in value:
            pieces = [
                value.get(key)
                for key in ("streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry")
            ]
            rendered = ", ".join(str(piece).strip() for piece in pieces if str(piece or "").strip())
            if rendered:
                found.append(rendered)
        for child in value.values():
            found.extend(_json_addresses(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_json_addresses(child))
    return found


def parse_html(source_url: str, body: str, root: str, target: TargetSpec) -> list[Finding]:
    parser = _VisibleText()
    try:
        parser.feed(body)
    except (ValueError, AssertionError):
        pass
    visible = html.unescape("\n".join(parser.parts))
    candidates: list[tuple[str, str]] = []
    candidates.extend(("email", value.lower()) for value in EMAIL.findall(visible))
    for link in parser.links:
        scheme, value = link.split(":", 1)
        value = value.split("?", 1)[0].strip()
        candidates.append(("email" if scheme.lower() == "mailto" else "phone", value.lower()))
    for encoded in parser.cfemails:
        decoded = _decode_cfemail(encoded)
        if decoded and EMAIL.fullmatch(decoded):
            candidates.append(("email", decoded.lower()))
    for match in PHONE.finditer(visible):
        value = re.sub(r"\s+", " ", match.group(0)).strip(" .,-")
        digits = sum(character.isdigit() for character in value)
        if 8 <= digits <= 16:
            candidates.append(("phone", value))
    candidates.extend(("address", re.sub(r"\s+", " ", match.group(0)).strip(" .,")) for match in STREET.finditer(visible))
    for raw in parser.json_ld:
        try:
            candidates.extend(("address", value) for value in _json_addresses(json.loads(raw)))
        except (json.JSONDecodeError, TypeError):
            continue

    non_phones = [item for item in candidates if item[0] not in {"phone", "address"}]
    accepted_addresses: list[str] = []
    for item in sorted((item for item in candidates if item[0] == "address"), key=lambda item: len(item[1]), reverse=True):
        folded = item[1].casefold()
        if any(existing.casefold().startswith(folded) for existing in accepted_addresses):
            continue
        accepted_addresses.append(item[1])
        non_phones.append(item)
    phone_candidates = sorted(
        (item for item in candidates if item[0] == "phone"),
        key=lambda item: (sum(character.isdigit() for character in item[1]), item[1].startswith("+"), len(item[1])),
        reverse=True,
    )
    accepted_digits: list[str] = []
    for item in phone_candidates:
        digits = "".join(character for character in item[1] if character.isdigit())
        if re.fullmatch(r"\d{5}-\d{4}", item[1].strip()):
            continue
        if any(existing == digits or (existing.endswith(digits) and len(existing) - len(digits) <= 3) for existing in accepted_digits):
            continue
        accepted_digits.append(digits)
        non_phones.append(item)
    candidates = non_phones

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for kind, value in candidates:
        value = value.strip()
        key = (kind, value.casefold())
        if not value or key in seen:
            continue
        seen.add(key)
        in_scope = True
        if kind == "email":
            in_scope = domain_in_scope(value.rsplit("@", 1)[-1], target.domains, target.exclude_domains)
        findings.append(
            Finding(
                "harvester",
                "web-contact",
                kind,
                value,
                in_scope,
                {"root": root, "source_url": source_url, "public_page": True},
            )
        )
    return findings
