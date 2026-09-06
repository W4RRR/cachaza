"""Offline audit comparison, review state and evidence freshness.

Review decisions are operator annotations, never scanner confirmations.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .models import utc_now

STAGE_TTL_HOURS = {"dns": 1, "http": 1, "ports": 1, "origin": 1, "waf": 1,
                   "ct": 24, "api": 24, "subdomains": 24, "asn": 168, "cloud": 168}
REVIEW_STATES = ("pending", "confirmed", "dismissed", "resolved")


def age_hours(timestamp: str | None) -> float | None:
    try:
        stamp = datetime.fromisoformat(timestamp or "")
        if stamp.tzinfo is None:
            return None
        age = (datetime.now(UTC) - stamp).total_seconds() / 3600
        return age if age >= 0 else None
    except (ValueError, TypeError):
        return None


def finding_id(item: dict[str, Any]) -> str:
    metadata = item.get("metadata") or {}
    identity = [item.get("kind"), item.get("value"), metadata.get("target", ""), metadata.get("root", "")]
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]


def coverage(data: dict[str, Any]) -> dict[str, Any]:
    stages = []
    counts = Counter(f.get("stage") for f in data.get("findings", []))
    for stage in data.get("stages", []):
        name = stage["name"]
        timestamp = stage.get("evidence_at", stage.get("finished_at") if stage.get("status") == "completed" else None)
        age = age_hours(timestamp)
        ttl = stage.get("max_age_hours", STAGE_TTL_HOURS.get(name, 24))
        stages.append({**stage, "evidence_at": timestamp, "age_hours": round(age, 2) if age is not None else None,
                       "evidence_count": counts[name],
                       "freshness": "unknown" if age is None else "stale" if age > ttl else "fresh"})
    providers = [{"name": name, "group": group, **row}
                 for group in ("source_status", "provider_status")
                 for name, row in data.get(group, {}).items() if isinstance(row, dict)]
    return {"stages": stages, "providers": providers,
            "stage_counts": dict(Counter(s.get("status", "unknown") for s in stages)),
            "provider_counts": dict(Counter(p.get("status", "unknown") for p in providers)),
            "notice": "Completed means the stage returned, not that every provider succeeded. Missing evidence is not proof of absence. Cached timestamps refer to collection, not report generation."}


def review_queue(findings: list[dict[str, Any]], saved: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in findings:
        if item.get("stage") == "input":
            continue
        key = finding_id(item)
        row = grouped.setdefault(key, {"id": key, "kind": item["kind"], "value": item["value"],
                                      "sources": [], "state": "pending", "owner": "", "notes": "", "closure_test": ""})
        if item.get("source") not in row["sources"]:
            row["sources"].append(item.get("source"))
        annotation = saved.get(key, {})
        row.update({k: annotation[k] for k in ("state", "owner", "notes", "closure_test", "updated_at") if k in annotation})
    return sorted(grouped.values(), key=lambda row: (row["state"] != "pending", row["kind"], row["value"]))


def load_report(path: Path) -> dict[str, Any]:
    if path.is_dir():
        path = path / "report.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("scope"), dict) or not isinstance(data.get("findings"), list):
        raise ValueError("expected a report.json containing scope and findings")
    return data


def _inventory(data: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in data["findings"]:
        key = finding_id(item)
        row = result.setdefault(key, {"id": key, "kind": item["kind"], "value": item["value"], "observations": []})
        # Timestamps and counts are collection bookkeeping, not asset changes.
        metadata = {k: v for k, v in item.get("metadata", {}).items()
                    if k not in {"observed_at", "last_observed", "generated_at", "retrieved_at", "elapsed", "duration"}}
        observation = {"source": item.get("source"), "in_scope": item.get("in_scope"), "metadata": metadata}
        if observation not in row["observations"]:
            row["observations"].append(observation)
    for row in result.values():
        row["observations"].sort(key=lambda value: json.dumps(value, sort_keys=True))
    return result


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    normalize_scope = lambda scope: {k: sorted(v) if isinstance(v, list) else v for k, v in scope.items()}
    if normalize_scope(before["scope"]) != normalize_scope(after["scope"]):
        raise ValueError("cannot compare reports with different authorized scopes")
    old, new = _inventory(before), _inventory(after)
    return {"schema_version": 1, "before": before.get("generated_at"), "after": after.get("generated_at"),
            "added": [new[k] for k in sorted(new.keys() - old.keys())],
            "not_observed": [old[k] for k in sorted(old.keys() - new.keys())],
            "changed": [{"id": k, "before": old[k], "after": new[k]} for k in sorted(old.keys() & new.keys()) if old[k] != new[k]],
            "unchanged": sum(old[k] == new[k] for k in old.keys() & new.keys()),
            "coverage_before": coverage(before), "coverage_after": coverage(after),
            "issues_before": before.get("issues", []), "issues_after": after.get("issues", []),
            "notice": "Not observed does not mean resolved. Compare stage/provider coverage and evidence freshness before interpreting a disappearance."}


def update_review(root: Path, key: str, *, state: str | None = None, owner: str | None = None,
                  notes: str | None = None, closure_test: str | None = None) -> dict[str, Any]:
    scope = root / "rest" / "scope.json"
    if not scope.is_file():
        raise ValueError("review requires an existing workspace with rest/scope.json")
    findings = [json.loads(line) for line in (root / "rest" / "findings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    if key not in {finding_id(item) for item in findings}:
        raise ValueError("unknown finding ID; use review WORKSPACE to list IDs")
    path = root / "rest" / "review.json"
    saved = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    row = dict(saved.get(key, {}))
    if state is not None and state not in REVIEW_STATES:
        raise ValueError("invalid review state")
    row.update({k: v for k, v in {"state": state, "owner": owner, "notes": notes, "closure_test": closure_test}.items() if v is not None})
    if row.get("state") == "resolved" and not row.get("closure_test", "").strip():
        raise ValueError("resolved requires a documented closure test (-closure-test)")
    history = list(row.get("history", []))
    row["updated_at"] = utc_now()
    history.append({k: v for k, v in row.items() if k != "history"})
    row["history"] = history
    saved[key] = row
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(saved, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)
    return row
