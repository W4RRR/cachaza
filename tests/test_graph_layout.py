import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


@pytest.mark.parametrize("mode", ["--network", "--groups"])
def test_large_graph_has_no_collisions(mode):
    node = os.environ.get("CACHAZA_TEST_NODE") or shutil.which("node")
    if not node:
        pytest.skip("Node is needed for the offline JavaScript layout regression")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([node, str(root / "tests/benchmark_graph.cjs"),
                             str(root / "src/cachaza/html_report.py"), "1200", mode],
                            capture_output=True, text=True, check=True, timeout=30)
    metrics = json.loads(result.stdout)
    assert metrics["nodes"] == 1200
    assert metrics["minimum"] >= 85 - 1e-6
