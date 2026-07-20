"""Core data models for findings, targets, and pipeline state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(slots=True)
class Finding:
    stage: str
    source: str
    kind: str
    value: str
    in_scope: bool
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StageStatus:
    name: str
    status: str = "pending"
    started_at: str | None = None
    finished_at: str | None = None
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TargetSpec:
    domains: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_cidrs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def empty(self) -> bool:
        return not (self.domains or self.asns or self.organizations or self.cidrs)


@dataclass(slots=True)
class OriginEvidence:
    """One explainable, deduplicated origin-correlation signal."""

    code: str
    description: str
    score: int
    source: str
    source_family: str
    strong: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    observed_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OriginNetwork:
    provider: str = "Unknown"
    organization: str = ""
    asn: str = ""
    is_public: bool = True
    is_private: bool = False
    is_known_cdn: bool = False
    is_cloud: bool = False
    is_shared_hosting: bool = False
    is_clearly_third_party: bool = False
    signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class OriginCandidate:
    ip: str
    hostnames: list[str] = field(default_factory=list)
    evidence: list[OriginEvidence] = field(default_factory=list)
    network: OriginNetwork = field(default_factory=OriginNetwork)
    classification: str = "related_infrastructure"
    initial_score: int = 0
    final_score: int = 0
    validation_status: str = "not_validated"
    validation_attempts: int = 0
    rejection_reasons: list[str] = field(default_factory=list)
    validation: dict[str, Any] = field(default_factory=dict)
    last_observed: str | None = None

    @property
    def independent_source_families(self) -> list[str]:
        return sorted({item.source_family for item in self.evidence if item.source_family})

    @property
    def independent_source_count(self) -> int:
        return len(self.independent_source_families)

    @property
    def has_strong_evidence(self) -> bool:
        return any(item.strong for item in self.evidence)

    @property
    def is_clearly_third_party(self) -> bool:
        return self.network.is_clearly_third_party

    @property
    def score(self) -> int:
        return self.final_score if self.validation_status != "not_validated" else self.initial_score

    def add_evidence(self, evidence: OriginEvidence) -> bool:
        # A signal can be corroborated by several tools, but its score is applied
        # once. Independent providers remain visible through source_family.
        key = (evidence.code, evidence.source_family)
        if any((item.code, item.source_family) == key for item in self.evidence):
            return False
        self.evidence.append(evidence)
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostnames": sorted(set(self.hostnames)),
            "evidence": [item.to_dict() for item in self.evidence],
            "network": self.network.to_dict(),
            "classification": self.classification,
            "initial_score": self.initial_score,
            "final_score": self.final_score,
            "validation_status": self.validation_status,
            "validation_attempts": self.validation_attempts,
            "rejection_reasons": list(self.rejection_reasons),
            "validation": self.validation,
            "last_observed": self.last_observed,
            "independent_source_families": self.independent_source_families,
            "independent_source_count": self.independent_source_count,
            "has_strong_evidence": self.has_strong_evidence,
        }


@dataclass(slots=True)
class OriginConfig:
    """Bounded configuration for automatic origin discovery and verification."""

    mode: str = "balanced"
    auto_verify: bool = True
    minimum_score: int = 50
    maximum_candidates: int = 10
    stop_score: int = 85
    continue_after_match: bool = False
    ports: list[int] = field(default_factory=lambda: [80, 443])
    deep_ports: list[int] = field(default_factory=lambda: [80, 443, 8000, 8080, 8443, 8888])
    maximum_total_requests: int = 40
    maximum_requests_per_ip: int = 6
    rate_limit_per_second: float = 1.0
    maximum_concurrency: int = 2
    connect_timeout: float = 5.0
    total_timeout: float = 12.0
    maximum_body_bytes: int = 2_097_152
    maximum_redirects: int = 5
    maximum_paths: int = 3
    paths: list[str] = field(default_factory=list)
    use_observed_paths: bool = False
    use_favicon: bool = True
    use_static_resources: bool = True
    tls: bool = True
    jarm: bool = False
    dns_permutations: bool = False
    maximum_permutations: int = 10_000
    historical_dns: bool = True
    maximum_history_results: int = 100
    query_engines: list[str] = field(
        default_factory=lambda: ["virustotal", "securitytrails", "censys", "shodan", "urlscan", "uncover"]
    )
    exclude_providers: list[str] = field(default_factory=list)
    exclude_cidr_file: str | None = None
    include_cidr_file: str | None = None
    save_bodies: bool = False
    direct_validation: bool = True
    authorized: bool = False

    @property
    def validation_ports(self) -> list[int]:
        return list(self.deep_ports if self.mode == "deep" else self.ports)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
