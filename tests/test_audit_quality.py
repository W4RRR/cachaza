from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from cachaza.audit import age_hours, compare_reports, coverage, finding_id, update_review
from cachaza.cli import main
from cachaza.console import Console
from cachaza.models import Finding, TargetSpec
from cachaza.pipeline import Pipeline, RunOptions
from cachaza.reports import _build_origin_trace, _build_origin_remediation, build_key_findings, build_report_data
from cachaza.workspace import RunWorkspace


def report(value="https://example.com", status=200):
    return {"scope": {"domains": ["example.com"]}, "findings": [
        Finding("http", "httpx", "url", value, True, {"status_code": status}).to_dict()
    ], "stages": [], "provider_status": {}}


def test_diff_distinguishes_changes_and_disappearance_without_claiming_resolution():
    before, after = report(), report(status=403)
    assert len(compare_reports(before, after)["changed"]) == 1
    after["findings"] = []
    after["provider_status"] = {"example": {"status": "error"}}
    result = compare_reports(before, after)
    assert len(result["not_observed"]) == 1
    assert "resolved" not in result
    assert result["coverage_after"]["provider_counts"] == {"error": 1}


def test_diff_ignores_observation_time_and_order_but_rejects_scope_change():
    before, after = report(), report()
    after["findings"][0]["observed_at"] = "2030-01-01T00:00:00+00:00"
    assert compare_reports(before, after)["unchanged"] == 1
    after["scope"] = {"domains": ["other.example"]}
    with pytest.raises(ValueError, match="scope"):
        compare_reports(before, after)


def test_diff_cli_json_and_no_overwrite(tmp_path, capsys):
    for name in ("a", "b"):
        (tmp_path / name).write_text(json.dumps(report()), encoding="utf-8")
    assert main(["diff", str(tmp_path / "a"), str(tmp_path / "b"), "-json"]) == 0
    assert json.loads(capsys.readouterr().out)["unchanged"] == 1
    assert main(["diff", str(tmp_path / "a"), str(tmp_path / "b"), "-o", str(tmp_path / "a")]) == 2


def test_review_persists_without_altering_evidence_and_requires_closure(tmp_path):
    ws = RunWorkspace(tmp_path)
    target = TargetSpec(domains=["example.com"])
    ws.write_json("scope.json", target.to_dict())
    finding = Finding("http", "httpx", "url", "https://example.com", True)
    ws.add(finding)
    original = ws.findings_path.read_bytes()
    key = finding_id(finding.to_dict())
    with pytest.raises(ValueError, match="closure"):
        update_review(tmp_path, key, state="resolved")
    update_review(tmp_path, key, state="confirmed", owner="Ops", notes="<script>alert(1)</script>")
    update_review(tmp_path, key, state="resolved", closure_test="External retest denied; evidence retained by Ops.")
    data = build_report_data(ws, target, version="test", failures=[])
    assert data["review_queue"][0]["state"] == "resolved"
    assert data["review_queue"][0]["owner"] == "Ops"
    assert ws.findings_path.read_bytes() == original
    from cachaza.html_report import render_html
    assert "<script>alert(1)</script>" not in render_html(data)
    with pytest.raises(ValueError, match="unknown"):
        update_review(tmp_path, "does-not-exist", state="pending")


def test_offline_report_keeps_review_and_generates_html(tmp_path):
    ws = RunWorkspace(tmp_path)
    ws.write_json("scope.json", TargetSpec(domains=["example.com"]).to_dict())
    ws.add(Finding("http", "httpx", "url", "https://example.com", True))
    assert main(["report", str(tmp_path), "-format", "html", "-format", "json"]) == 0
    assert 'id="review-section"' in (tmp_path / "report.html").read_text(encoding="utf-8")
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["schema_version"] == 2


def test_cache_expiry_and_unknown_or_future_times(tmp_path):
    ws = RunWorkspace(tmp_path)
    path = ws.write_checkpoint("dns", "key", "ok")
    assert ws.checkpoint_matches("dns", "key")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["completed_at"] = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    path.write_text(json.dumps(data), encoding="utf-8")
    assert not ws.checkpoint_matches("dns", "key")
    assert ws.checkpoint_matches("dns", "key", 3)
    assert age_hours("garbage") is None
    assert age_hours((datetime.now(UTC) + timedelta(days=1)).isoformat()) is None


def test_cached_coverage_uses_collection_time_not_resume_time():
    old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    data = {"stages": [{"name": "dns", "status": "cached", "evidence_at": old,
                        "finished_at": datetime.now(UTC).isoformat(), "max_age_hours": 1}]}
    assert coverage(data)["stages"][0]["freshness"] == "stale"
    del data["stages"][0]["evidence_at"]
    assert coverage(data)["stages"][0]["freshness"] == "unknown"


def test_refresh_replaces_stage_evidence_and_invalidates_downstream(tmp_path):
    target = TargetSpec(domains=["example.com"])
    ws = RunWorkspace(tmp_path, resume=True)
    pipe = Pipeline(target, ws, RunOptions(refresh_stages=["dns"]), Console(silent=True))
    ws.add(Finding("dns", "dnsx", "domain", "old.example.com", True))
    for stage in ("dns", "http", "waf"):
        ws.write_checkpoint(stage, pipe._stage_cache_key(stage), "ok")
    pipe._run_stage("dns", lambda: ws.add(Finding("dns", "dnsx", "domain", "new.example.com", True)) and "ok")
    executed = []
    pipe._run_stage("http", lambda: executed.append(True) or "ok")
    assert executed == [True]
    assert not (ws.stage_state / "waf.json").exists()
    assert "old.example.com" not in ws.values("domain")
    assert "new.example.com" in ws.values("domain")
    assert list((ws.rest / "history").glob("dns-*.json"))


def test_failed_refresh_restores_previous_evidence_and_cannot_be_reused(tmp_path):
    ws = RunWorkspace(tmp_path, resume=True)
    pipe = Pipeline(TargetSpec(domains=["example.com"]), ws, RunOptions(refresh_stages=["dns"]), Console(silent=True))
    ws.add(Finding("dns", "dnsx", "domain", "old.example.com", True))
    ws.write_checkpoint("dns", pipe._stage_cache_key("dns"), "ok")
    def fail():
        ws.add(Finding("dns", "dnsx", "domain", "partial.example.com", True))
        raise RuntimeError("fixture failure")
    pipe._run_stage("dns", fail)
    assert "old.example.com" in ws.values("domain")
    assert "partial.example.com" not in ws.values("domain")
    assert ws.stages[-1].status == "failed"
    assert not ws.checkpoint_matches("dns", pipe._stage_cache_key("dns"))


def test_no_cdn_direct_match_is_not_a_boundary_bypass():
    trace = _build_origin_trace({"origin_ip": "203.0.113.10", "classification": "high_confidence_origin",
        "direct_requests_performed": 6, "cdn_waf_detected": {"provider": "No CDN detected"},
        "primary": [{"ip": "203.0.113.10", "validation_status": "validated", "evidence": [
            {"source_family": "direct_validation", "score": 30, "description": "Same application"}]}]})
    assert trace["status"] == "direct_reachable_no_boundary"
    assert trace["direct_validation"] == "positive"
    assert trace["steps"][3]["status"] == "validated"
    assert trace["severity"] != "critical"
    assert _build_origin_remediation(trace)["posture"] == "review_architecture"


def test_contact_regression_years_postcode_and_duplicate_formatting():
    values = ["+34 910 47 15 73", "+34910471573", "136 28006", "2015 20 20", "2015 2016 2017 2019", "2021 2023 2024 2025"]
    findings = [Finding("harvester", "fixture", "phone", value, True) for value in values]
    assert build_key_findings(findings)["phones"] == ["+34910471573"]


@pytest.mark.parametrize("ttl", ["-1", "nan", "inf"])
def test_invalid_ttl_rejected_without_workspace(tmp_path, ttl):
    root = tmp_path / "never-created"
    assert main(["run", "-d", "example.com", "-stages", "corporate", "-o", str(root), "-cache-max-age-hours", ttl, "-silent"]) == 2
    assert not root.exists()


def test_finalization_reports_completion_on_stderr_and_log(tmp_path, capsys):
    ws = RunWorkspace(tmp_path)
    console = Console(color=False)
    console.attach_log(ws.rest / "execution.log")
    pipe = Pipeline(TargetSpec(domains=["example.com"]), ws, RunOptions(), console)
    with patch("cachaza.pipeline.export_reports") as export:
        pipe.finalize()
    assert export.called
    captured = capsys.readouterr()
    assert "Finalizing run" in captured.err
    assert "Run finished" in captured.err
    assert "Run finished" in (ws.rest / "execution.log").read_text(encoding="utf-8")
