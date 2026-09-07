import json
import time
from concurrent.futures import ThreadPoolExecutor

from cachaza.console import Console
from cachaza.models import Finding, TargetSpec
from cachaza.pipeline import Pipeline, RunOptions
from cachaza.profiles import PROFILES
from cachaza.scheduler import dependencies
from cachaza.workspace import RunWorkspace


def fixture_run(root, jobs, *, resume=False, strict=False):
    ws = RunWorkspace(root, resume=resume)
    pipeline = Pipeline(TargetSpec(domains=["example.test"]), ws,
                        RunOptions(stages=list(PROFILES["full"].stages), jobs=jobs,
                                   dry_run=True, strict=strict), Console(silent=True))
    for stage in pipeline.options.stages:
        def work(name=stage):
            if name in {"ct", "api"}:
                time.sleep(.06 if name == "ct" else .02)
            ws.add(Finding(name, name, "domain", name + ".example.test", True,
                           observed_at="2026-01-01T00:00:00+00:00"))
            return name
        setattr(pipeline, "stage_" + stage, work)
    pipeline.finalize = lambda: None
    started = time.perf_counter()
    pipeline.execute()
    findings = [item.to_dict() for item in ws.findings if item.stage != "input"]
    return findings, [stage.name for stage in ws.stages], time.perf_counter() - started


def test_parallel_evidence_is_canonical_and_barriers_preserved(tmp_path):
    serial = fixture_run(tmp_path / "serial", 1)
    parallel = fixture_run(tmp_path / "parallel", 2)
    assert serial[:2] == parallel[:2]
    assert fixture_run(tmp_path / "strict", 2, strict=True)[:2] == serial[:2]
    assert fixture_run(tmp_path / "resume", 2, resume=True)[:2] == serial[:2]
    assert dependencies(["ct", "api", "dns", "gau"]) == {0: set(), 1: set(), 2: {0, 1}, 3: {0, 1, 2}}


def test_workspace_concurrent_dedup(tmp_path):
    workspace = RunWorkspace(tmp_path)
    finding = Finding("ct", "source", "domain", "example.test", True)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: workspace.add(finding), range(80)))
    assert sum(results) == 1
    assert len(workspace.findings_path.read_text().splitlines()) == 1


def test_metrics_optional_and_no_secret(tmp_path, monkeypatch):
    fixture_run(tmp_path / "default", 2)
    assert not (tmp_path / "default/rest/metrics.json").exists()
    monkeypatch.setenv("CACHAZA_METRICS", "1")
    fixture_run(tmp_path / "metrics", 2)
    metrics = json.loads((tmp_path / "metrics/rest/metrics.json").read_text())
    assert metrics["subprocesses"] == 0
    assert set(metrics["stage_seconds"]) == set(PROFILES["full"].stages)
