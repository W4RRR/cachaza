"""Shared adapter result model and normalization helpers."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding


@dataclass(slots=True)
class AdapterResult:
    findings: list[Finding] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    details: str = ""

