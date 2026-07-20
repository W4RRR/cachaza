"""Input validation and scope enforcement."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from .models import TargetSpec


DOMAIN_RE = re.compile(
    r"(?i)(?<![a-z0-9_-])(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?(?![a-z0-9_-])"
)
ASN_RE = re.compile(r"(?i)^(?:AS)?(\d{1,10})$")
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class ValidationError(ValueError):
    pass


def unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def normalize_domain(value: str) -> str:
    raw = ANSI_RE.sub("", value).strip().lower().rstrip(".")
    if "://" in raw:
        raw = urlsplit(raw).hostname or ""
    raw = raw.removeprefix("*.")
    if "/" in raw or "@" in raw or ":" in raw:
        raise ValidationError(f"invalid domain: {value!r}")
    try:
        ascii_name = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError(f"invalid domain: {value!r}") from exc
    if len(ascii_name) > 253 or "." not in ascii_name or not DOMAIN_RE.fullmatch(ascii_name):
        raise ValidationError(f"invalid domain: {value!r}")
    return ascii_name


def normalize_asn(value: str) -> str:
    match = ASN_RE.fullmatch(value.strip())
    if not match:
        raise ValidationError(f"invalid ASN: {value!r}")
    number = int(match.group(1))
    if not 0 < number <= 4_294_967_295:
        raise ValidationError(f"ASN out of range: {value!r}")
    return f"AS{number}"


def normalize_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValidationError(f"invalid CIDR: {value!r}") from exc


def domain_in_scope(name: str, roots: list[str], excludes: list[str] | None = None) -> bool:
    try:
        candidate = normalize_domain(name)
    except ValidationError:
        return False
    excluded = excludes or []
    if any(candidate == item or candidate.endswith("." + item) for item in excluded):
        return False
    return any(candidate == root or candidate.endswith("." + root) for root in roots)


def ip_in_scope(value: str, cidrs: list[str], excludes: list[str] | None = None) -> bool:
    try:
        address = ipaddress.ip_address(value)
        networks = [ipaddress.ip_network(item) for item in cidrs]
        denied = [ipaddress.ip_network(item) for item in (excludes or [])]
    except ValueError:
        return False
    if any(address.version == net.version and address in net for net in denied):
        return False
    return any(address.version == net.version and address in net for net in networks)


def extract_domains(text: str, roots: list[str] | None = None) -> list[str]:
    cleaned = ANSI_RE.sub("", text)
    results: list[str] = []
    for match in DOMAIN_RE.finditer(cleaned):
        try:
            domain = normalize_domain(match.group(0))
        except ValidationError:
            continue
        if roots and not domain_in_scope(domain, roots):
            continue
        results.append(domain)
    return sorted(set(results))


def _read_target_file(path: Path) -> dict[str, list[str]]:
    values = {"domains": [], "asns": [], "organizations": [], "cidrs": []}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        prefix, separator, payload = line.partition(":")
        if separator and prefix.lower() in {"domain", "asn", "org", "cidr"}:
            key = {"domain": "domains", "asn": "asns", "org": "organizations", "cidr": "cidrs"}[prefix.lower()]
            values[key].append(payload.strip())
            continue
        try:
            ipaddress.ip_network(line, strict=False)
            values["cidrs"].append(line)
        except ValueError:
            if ASN_RE.fullmatch(line):
                values["asns"].append(line)
            elif "." in line:
                values["domains"].append(line)
            else:
                raise ValidationError(f"ambiguous target type in {path}:{number}: {line!r}")
    return values


def build_target_spec(
    domains: list[str] | None = None,
    asns: list[str] | None = None,
    organizations: list[str] | None = None,
    cidrs: list[str] | None = None,
    target_files: list[str] | None = None,
    exclude_domains: list[str] | None = None,
    exclude_cidrs: list[str] | None = None,
) -> TargetSpec:
    collected = {
        "domains": list(domains or []),
        "asns": list(asns or []),
        "organizations": list(organizations or []),
        "cidrs": list(cidrs or []),
    }
    for filename in target_files or []:
        path = Path(filename).expanduser()
        if not path.is_file():
            raise ValidationError(f"target file does not exist: {path}")
        parsed = _read_target_file(path)
        for key, values in parsed.items():
            collected[key].extend(values)

    normalized_orgs = []
    for org in collected["organizations"]:
        clean = org.strip()
        if not clean or len(clean) > 200 or any(ord(char) < 32 for char in clean):
            raise ValidationError(f"invalid organization: {org!r}")
        normalized_orgs.append(clean)

    return TargetSpec(
        domains=unique([normalize_domain(item) for item in collected["domains"]]),
        asns=unique([normalize_asn(item) for item in collected["asns"]]),
        organizations=unique(normalized_orgs),
        cidrs=unique([normalize_cidr(item) for item in collected["cidrs"]]),
        exclude_domains=unique([normalize_domain(item) for item in (exclude_domains or [])]),
        exclude_cidrs=unique([normalize_cidr(item) for item in (exclude_cidrs or [])]),
    )


def active_address_count(cidrs: list[str], ceiling: int | None = None) -> int:
    total = 0
    for item in cidrs:
        total += ipaddress.ip_network(item).num_addresses
        if ceiling is not None and total > ceiling:
            return total
    return total
