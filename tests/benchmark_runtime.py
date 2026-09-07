"""Offline, fixed-data benchmark. Run with Python; never contacts a target."""
import json
from pathlib import Path
from statistics import median
import tempfile
import time
from unittest.mock import patch

from test_scheduler import fixture_run
from cachaza.http import request_json
from cachaza.run_cache import RunCache


def measure():
    timings = {1: [], 2: []}
    with tempfile.TemporaryDirectory() as directory:
        reference = None
        for jobs in (1, 2):
            for attempt in range(5):
                findings, stages, duration = fixture_run(Path(directory) / f"{jobs}-{attempt}", jobs)
                normalized = (findings, stages)
                if reference is None:
                    reference = normalized
                assert reference == normalized
                timings[jobs].append(duration * 1000)
    requests = {}
    for enabled in (False, True):
        with RunCache(enabled=enabled).activate(), patch("cachaza.http.urllib.request.urlopen") as transport, patch("cachaza.http.GLOBAL_REQUEST_LIMITER.slot"):
            def payload():
                time.sleep(.01)
                return b'{"rows":[1,2,3]}'
            transport.return_value.__enter__.return_value.read.side_effect = payload
            started = time.perf_counter()
            values = [request_json("https://fixture.invalid/provider") for _ in range(12)]
            assert all(value == {"rows": [1, 2, 3]} for value in values)
            requests[str(enabled)] = {"transport_calls": transport.call_count,
                                      "milliseconds": (time.perf_counter() - started) * 1000}
    return {"full_fixture_ms_median": {str(k): median(v) for k, v in timings.items()},
            "repeated_provider": requests, "normalized_findings_equal": True}


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
