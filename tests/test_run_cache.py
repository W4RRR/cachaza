from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from unittest.mock import patch
import json
import time

import pytest

from cachaza.run_cache import RunCache, memoized
from cachaza.http import request_bytes, request_json, HttpError


def test_singleflight_isolation_ttl_and_secrets():
    calls = []
    @memoized("provider")
    def fetch(secret):
        calls.append(secret)
        time.sleep(.02)
        return {"rows": [1]}
    run = RunCache(ttl=.04)
    with run.activate(), ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(copy_context().run, fetch, "secret-token") for _ in range(2)]
        results = [future.result() for future in futures]
        assert len(calls) == 1
        results[0]["rows"].append(2)
        assert fetch("secret-token") == {"rows": [1]}
        assert "secret-token" not in repr(run._values) + json.dumps(run.snapshot())
        time.sleep(.05)
        fetch("secret-token")
        assert len(calls) == 2
    fetch("secret-token")
    assert len(calls) == 3


def test_failures_disabled_cache_and_eviction():
    run = RunCache(maximum_entries=1)
    def fail():
        raise TimeoutError()
    for _ in range(2):
        with pytest.raises(TimeoutError):
            run.get("dns", "host", fail)
    assert not run._values and not run._pending
    run.get("dns", "a", lambda: [1])
    run.get("dns", "b", lambda: [2])
    assert len(run._values) == 1
    run.enabled = False
    assert run.get("dns", "b", lambda: [3]) == [3]


def test_http_identity_errors_and_post_not_cached():
    with RunCache().activate(), patch("cachaza.http.urllib.request.urlopen") as open_url, patch("cachaza.http.GLOBAL_REQUEST_LIMITER.slot"):
        open_url.return_value.__enter__.return_value.read.return_value = b'{"ok":true}'
        for _ in range(2):
            assert request_json("https://example.test/", headers={"Authorization": "a"}) == {"ok": True}
        assert open_url.call_count == 1
        request_bytes("https://example.test/", headers={"Authorization": "b"})
        request_bytes("https://example.test/", method="POST")
        request_bytes("https://example.test/", method="POST")
        assert open_url.call_count == 4
        open_url.return_value.__enter__.return_value.read.return_value = b'invalid'
        with pytest.raises(HttpError):
            request_json("https://example.test/bad")
        open_url.return_value.__enter__.return_value.read.return_value = b'[]'
        assert request_json("https://example.test/bad") == []
