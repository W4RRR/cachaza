from __future__ import annotations

import json
import re
import shutil
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, StageStatus, TargetSpec, utc_now


def _slug(value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-.")
    return clean[:80] or "recon"


class RunWorkspace:
    def __init__(self, root: Path, *, resume: bool = False):
        self.root = root
        self.resume = resume
        self.root.mkdir(parents=True, exist_ok=True)
        self.rest = root / "rest"
        self.rest.mkdir(parents=True, exist_ok=True)
        self.stage_state = self.rest / "stages"
        self.stage_state.mkdir(parents=True, exist_ok=True)
        self.findings_path = self.rest / "findings.jsonl"
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, str, str]] = set()
        self.stages: list[StageStatus] = []
        if resume:
            legacy_findings = self.root / "findings.jsonl"
            if self.findings_path.is_file():
                self._load_findings(self.findings_path)
            elif legacy_findings.is_file():
                self._load_findings(legacy_findings)

    @classmethod
    def reset_verified(cls, root: Path, target: TargetSpec) -> None:
        """Clear only a recognizable Cachaza workspace with an identical scope."""
        resolved = root.expanduser().resolve()
        scope_path = resolved / "rest" / "scope.json"
        if not scope_path.is_file():
            legacy = resolved / "scope.json"
            scope_path = legacy if legacy.is_file() else scope_path
        if not scope_path.is_file():
            raise ValueError(f"refusing to reset a non-Cachaza directory: {resolved}")
        try:
            previous = json.loads(scope_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"refusing to reset workspace with invalid scope: {resolved}") from exc
        if previous != target.to_dict():
            raise ValueError("refusing to reset a workspace whose scope does not match")
        for child in resolved.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    @classmethod
    def create(cls, output: str | None, target: TargetSpec, resume: bool = False) -> "RunWorkspace":
        if output:
            requested = Path(output).expanduser()
            if not requested.is_absolute() and requested.parent == Path("."):
                root = (Path.cwd() / "output" / requested.name).resolve()
            else:
                root = requested.resolve()
        else:
            seed = (target.domains or target.asns or target.organizations or target.cidrs or ["recon"])[0]
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            root = (Path.cwd() / "output" / f"{_slug(seed)}-{stamp}").resolve()
        if root.exists() and not root.is_dir():
            raise FileExistsError(f"output path exists and is not a directory: {root}")
        if root.exists() and any(root.iterdir()) and not resume:
            raise FileExistsError(
                f"output directory is not empty and is not being resumed: {root}; choose another -o name"
            )
        return cls(root, resume=resume)

    def _load_findings(self, path: Path) -> None:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                finding = Finding(**data)
            except (json.JSONDecodeError, TypeError):
                continue
            self.findings.append(finding)
            self._seen.add((finding.source, finding.kind, finding.value))

    def add(self, finding: Finding) -> bool:
        key = (finding.source, finding.kind, finding.value)
        if key in self._seen:
            return False
        self._seen.add(key)
        self.findings.append(finding)
        with self.findings_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(finding.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")
        return True

    def checkpoint_matches(self, name: str, cache_key: str) -> bool:
        path = self.stage_state / f"{_slug(name)}.json"
        if not path.is_file():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return data.get("status") == "completed" and data.get("cache_key") == cache_key

    def write_checkpoint(self, name: str, cache_key: str, details: str) -> Path:
        path = self.stage_state / f"{_slug(name)}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {
                    "name": name,
                    "status": "completed",
                    "cache_key": cache_key,
                    "completed_at": utc_now(),
                    "details": details,
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
        return path

    def values(self, kind: str, *, in_scope: bool | None = None) -> list[str]:
        values = []
        for finding in self.findings:
            if finding.kind != kind or (in_scope is not None and finding.in_scope != in_scope):
                continue
            values.append(finding.value)
        return sorted(set(values))

    def write_json(self, name: str, value: Any) -> Path:
        path = self.artifact_path(name)
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def write_text(self, name: str, value: str) -> Path:
        path = self.artifact_path(name)
        path.write_text(value, encoding="utf-8", newline="\n")
        return path

    def artifact_path(self, name: str) -> Path:
        path = self.rest / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def write_report_json(self, name: str, value: Any) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def write_report_text(self, name: str, value: str) -> Path:
        path = self.root / name
        path.write_text(value, encoding="utf-8", newline="\n")
        return path

    def write_lines(self, name: str, values: Iterable[str]) -> Path:
        items = [str(item).rstrip("\n") for item in values if str(item).strip()]
        return self.write_text(name, "\n".join(items) + ("\n" if items else ""))

    def write_artifact_lists(self) -> None:
        mapping = {
            "domains.txt": ("domain", True),
            "related-domains.txt": ("domain", False),
            "subdomains.txt": ("domain", True),
            "asns.txt": ("asn", None),
            "organizations.txt": ("organization", None),
            "cidrs.txt": ("cidr", True),
            "candidate-cidrs.txt": ("cidr", False),
            "ips.txt": ("ip", True),
            "candidate-ips.txt": ("ip", False),
            "network-registrations.txt": ("network_registration", None),
            "urls.txt": ("url", True),
            "services.txt": ("service", True),
            "fingerprints.txt": ("fingerprint", None),
            "technologies.txt": ("technology", None),
            "security-findings.txt": ("security_finding", None),
            "policy-findings.txt": ("policy_finding", None),
            "cve-candidates.txt": ("cve_candidate", None),
            "wafs.txt": ("waf", None),
            "emails.txt": ("email", None),
            "phones.txt": ("phone", None),
            "addresses.txt": ("address", None),
            "api-endpoints.txt": ("api_endpoint", None),
            "api-key-candidates.txt": ("api_key_candidate", None),
            "zone-transfers.txt": ("dns_zone_transfer", None),
        }
        for filename, (kind, in_scope) in mapping.items():
            self.write_lines(filename, self.values(kind, in_scope=in_scope))

    def counts(self) -> dict[str, int]:
        return dict(sorted(Counter(item.kind for item in self.findings).items()))

    def write_manifest(
        self,
        target: TargetSpec,
        *,
        version: str,
        command_history: list[dict[str, object]],
        dry_run: bool,
        profile: str = "passive",
    ) -> None:
        self.write_json(
            "manifest.json",
            {
                "tool": "cachaza",
                "version": version,
                "generated_at": utc_now(),
                "dry_run": dry_run,
                "profile": profile,
                "scope": target.to_dict(),
                "counts": self.counts(),
                "stages": [stage.to_dict() for stage in self.stages],
                "external_commands": command_history,
            },
        )
