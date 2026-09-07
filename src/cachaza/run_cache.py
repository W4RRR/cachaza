"""Bounded, success-only memoization scoped to one execution, never persisted."""
from __future__ import annotations

import copy
import hashlib
import hmac
import inspect
import json
import secrets
import threading
import time
from collections import Counter, OrderedDict
from concurrent.futures import Future
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps


CURRENT_RUN: ContextVar[RunCache | None] = ContextVar("cachaza_run", default=None)


class RunCache:
    def __init__(self, *, enabled=True, ttl=60.0, maximum_entries=256):
        self.enabled = enabled
        self.ttl = ttl
        self.maximum_entries = maximum_entries
        self._salt = secrets.token_bytes(32)
        self._values = OrderedDict()
        self._pending = {}
        self._lock = threading.RLock()
        self.counters = Counter()
        self.stage_seconds = {}

    @contextmanager
    def activate(self):
        token = CURRENT_RUN.set(self)
        try:
            yield self
        finally:
            CURRENT_RUN.reset(token)

    def count(self, name, amount=1):
        with self._lock:
            self.counters[name] += amount

    def get(self, category, identity, compute, *, accept=lambda value: True):
        if not self.enabled:
            return compute()
        # Keyed hashes prevent credentials, URLs and low-entropy secrets appearing
        # in keys or metrics. Exact request parameters preserve Host/SNI semantics.
        encoded = json.dumps(identity, sort_keys=True, default=str).encode()
        key = (category, hmac.new(self._salt, encoded, hashlib.sha256).digest())
        with self._lock:
            item = self._values.get(key)
            if item is not None and time.monotonic() < item[0]:
                self._values.move_to_end(key)
                self.counters[category + "_cache_hits"] += 1
                return copy.deepcopy(item[1])
            self._values.pop(key, None)
            future = self._pending.get(key)
            owner = future is None
            if owner:
                future = self._pending[key] = Future()
            else:
                self.counters[category + "_coalesced"] += 1
        if not owner:
            return copy.deepcopy(future.result())
        try:
            self.count(category + "_cache_misses")
            value = compute()
            with self._lock:
                if accept(value):
                    self._values[key] = (time.monotonic() + self.ttl, copy.deepcopy(value))
                    while len(self._values) > self.maximum_entries:
                        self._values.popitem(last=False)
            future.set_result(value)
            return copy.deepcopy(value)
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self._lock:
                self._pending.pop(key, None)

    def snapshot(self):
        with self._lock:
            return {"counters": dict(sorted(self.counters.items())),
                    "stage_seconds": dict(sorted(self.stage_seconds.items()))}

    def discard(self, category):
        with self._lock:
            for key in list(self._values):
                if key[0] == category:
                    del self._values[key]


def count(name):
    run = CURRENT_RUN.get()
    if run is not None:
        run.count(name)


def memoized(category, *, accept=lambda value: bool(value)):
    """Optional injection through RunCache.activate(); standalone calls unchanged."""
    def decorate(function):
        signature = inspect.signature(function)

        @wraps(function)
        def wrapped(*args, **kwargs):
            run = CURRENT_RUN.get()
            if run is None:
                return function(*args, **kwargs)
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            if str(bound.arguments.get("method", "GET")).upper() not in {"GET", "HEAD"}:
                return function(*args, **kwargs)
            return run.get(category, bound.arguments,
                           lambda: function(*args, **kwargs), accept=accept)
        return wrapped
    return decorate


@memoized("dns")
def resolve_addresses(name):
    """Share the system resolver's raw successful answers across adapters."""
    import socket
    count("dns_requests")
    return socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
