"""Named pipeline profiles and their safety boundaries."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    name: str
    stages: tuple[str, ...]
    requires_active: bool
    description: str


PROFILES: dict[str, ProfileSpec] = {
    "passive": ProfileSpec(
        name="passive",
        stages=(
            "corporate",
            "asn",
            "tenant",
            "ct",
            "api",
            "subdomains",
            "shodan",
            "cloud",
            "gau",
        ),
        requires_active=False,
        description="passive sources and historical archives without direct target probing",
    ),
    "safe": ProfileSpec(
        name="safe",
        stages=(
            "corporate",
            "asn",
            "tenant",
            "ct",
            "api",
            "certificates",
            "subdomains",
            "dns",
            "shodan",
            "ports",
            "http",
            "cloud",
            "gau",
        ),
        requires_active=True,
        description="passive discovery followed by bounded DNS, port, certificate, and HTTP probes",
    ),
    "full": ProfileSpec(
        name="full",
        stages=(
            "corporate",
            "asn",
            "tenant",
            "ct",
            "api",
            "certificates",
            "subdomains",
            "dns",
            "shodan",
            "ports",
            "http",
            "cloud",
            "gau",
            "crawl",
            "js",
            "waf",
        ),
        requires_active=True,
        description=(
            "safe reconnaissance plus historical URL discovery, endpoint crawling, "
            "JavaScript endpoint mapping, and focused WAF fingerprinting"
        ),
    ),
}

DEFAULT_PROFILE = "passive"
DEFAULT_STAGES = list(PROFILES[DEFAULT_PROFILE].stages)
ACTIVE_STAGES = {
    "active",
    "certificates",
    "dns",
    "ports",
    "http",
    "bypass",
    "crawl",
    "js",
    "policies",
    "cve",
    "wappalyzer",
    "waf",
    "harvester",
    "blackwidow",
    "dns_enum",
}


def profile_stages(name: str) -> list[str]:
    try:
        return list(PROFILES[name].stages)
    except KeyError as exc:
        raise ValueError(f"unknown profile: {name}") from exc
