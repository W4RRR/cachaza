"""Process-wide conservative network execution limits."""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


MAX_REQUESTS_PER_SECOND = 2
MAX_CONCURRENCY = 2
MIN_REQUEST_INTERVAL = 1.0 / MAX_REQUESTS_PER_SECOND


def capped(value: int | float, maximum: int | float = MAX_CONCURRENCY):
    """Return a positive value capped by the mandatory network policy."""
    return max(1, min(value, maximum))


class RequestLimiter:
    """Limit request starts and concurrent in-flight operations process-wide."""

    def __init__(
        self,
        *,
        requests_per_second: float = MAX_REQUESTS_PER_SECOND,
        concurrency: int = MAX_CONCURRENCY,
    ) -> None:
        self.requests_per_second = min(float(requests_per_second), MAX_REQUESTS_PER_SECOND)
        self.concurrency = min(int(concurrency), MAX_CONCURRENCY)
        self._semaphore = threading.BoundedSemaphore(self.concurrency)
        self._schedule_lock = threading.Lock()
        self._next_start = 0.0

    @contextmanager
    def slot(self) -> Iterator[None]:
        self._semaphore.acquire()
        try:
            with self._schedule_lock:
                now = time.monotonic()
                scheduled = max(now, self._next_start)
                self._next_start = scheduled + (1.0 / self.requests_per_second)
            delay = scheduled - now
            if delay > 0:
                time.sleep(delay)
            yield
        finally:
            self._semaphore.release()


GLOBAL_REQUEST_LIMITER = RequestLimiter()


def constrained_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Return a subprocess environment with common worker pools capped at two."""
    values = {**os.environ, **(overrides or {})}
    values.update(
        {
            "CACHAZA_MAX_REQUESTS_PER_SECOND": str(MAX_REQUESTS_PER_SECOND),
            "CACHAZA_MAX_CONCURRENCY": str(MAX_CONCURRENCY),
            "GOMAXPROCS": str(MAX_CONCURRENCY),
            "OMP_NUM_THREADS": str(MAX_CONCURRENCY),
            "OPENBLAS_NUM_THREADS": str(MAX_CONCURRENCY),
            "NUMEXPR_NUM_THREADS": str(MAX_CONCURRENCY),
            "RAYON_NUM_THREADS": str(MAX_CONCURRENCY),
            "UV_THREADPOOL_SIZE": str(MAX_CONCURRENCY),
        }
    )
    return values


def _tool_name(argv: list[str]) -> str:
    if not argv:
        return ""
    first = Path(argv[0]).name.casefold().removesuffix(".exe")
    is_interpreter = first in {"bash", "sh", "python", "python3"} or first.startswith(
        "python3."
    )
    candidate = argv[1] if is_interpreter and len(argv) > 1 else argv[0]
    return Path(candidate).name.casefold().removesuffix(".exe")


def _cap_flag(
    argv: list[str],
    aliases: tuple[str, ...],
    *,
    maximum: int,
    add_as: str | None = None,
) -> None:
    found = False
    for index, item in enumerate(argv[:-1]):
        if item not in aliases:
            continue
        found = True
        try:
            current = int(float(argv[index + 1]))
        except ValueError:
            current = maximum
        argv[index + 1] = str(max(1, min(current, maximum)))
    if not found and add_as:
        argv.extend([add_as, str(maximum)])


def enforce_tool_limits(argv: list[str]) -> list[str]:
    """Cap supported third-party network tools even when a call site forgets."""
    clean = [str(part) for part in argv]
    tool = _tool_name(clean)
    rate = MAX_REQUESTS_PER_SECOND
    workers = MAX_CONCURRENCY

    if tool == "subfinder":
        _cap_flag(clean, ("-rl", "-rate-limit"), maximum=rate, add_as="-rl")
        _cap_flag(clean, ("-t", "-threads"), maximum=workers, add_as="-t")
    elif tool == "dnsx":
        _cap_flag(clean, ("-rl", "-rate-limit"), maximum=rate, add_as="-rl")
        _cap_flag(clean, ("-t", "-threads"), maximum=workers, add_as="-t")
    elif tool == "nuclei":
        _cap_flag(clean, ("-rl", "-rate-limit"), maximum=rate, add_as="-rl")
        for aliases, preferred in (
            (("-bs", "-bulk-size"), "-bulk-size"),
            (("-c", "-concurrency"), "-c"),
            (("-hbs", "-headless-bulk-size"), "-hbs"),
            (("-headc", "-headless-concurrency"), "-headc"),
            (("-jsc", "-js-concurrency"), "-jsc"),
            (("-pc", "-payload-concurrency"), "-pc"),
            (("-prc", "-probe-concurrency"), "-prc"),
            (("-tlc", "-template-loading-concurrency"), "-tlc"),
        ):
            _cap_flag(clean, aliases, maximum=workers, add_as=preferred)
    elif tool == "katana":
        _cap_flag(clean, ("-rl", "-rate-limit"), maximum=rate, add_as="-rate-limit")
        _cap_flag(clean, ("-c", "-concurrency"), maximum=workers, add_as="-concurrency")
        _cap_flag(clean, ("-p", "-parallelism"), maximum=workers, add_as="-parallelism")
    elif tool == "httpx":
        _cap_flag(clean, ("-rl", "-rate-limit"), maximum=rate, add_as="-rl")
        _cap_flag(clean, ("-t", "-threads"), maximum=workers, add_as="-t")
    elif tool == "naabu":
        _cap_flag(clean, ("-rate",), maximum=rate, add_as="-rate")
        _cap_flag(clean, ("-c",), maximum=workers, add_as="-c")
    elif tool == "nmap":
        _cap_flag(clean, ("--max-rate",), maximum=rate, add_as="--max-rate")
        _cap_flag(
            clean,
            ("--max-parallelism",),
            maximum=workers,
            add_as="--max-parallelism",
        )
    elif tool in {"caduceus", "tlsx"}:
        _cap_flag(clean, ("-c", "-concurrency"), maximum=workers, add_as="-c")
    return clean
