"""Conservative version checks and an explicit self-update workflow."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import __version__
from .console import Console
from .network_policy import GLOBAL_REQUEST_LIMITER, constrained_environment


REPOSITORY = "https://github.com/W4RRR/cachaza"
LATEST_RELEASE_API = "https://api.github.com/repos/W4RRR/cachaza/releases/latest"
RAW_PROJECT = "https://raw.githubusercontent.com/W4RRR/cachaza/main/pyproject.toml"
CACHE_TTL = 24 * 60 * 60


def version_key(value: str) -> tuple[int, ...]:
    numbers = [int(part) for part in re.findall(r"\d+", value.split("+", 1)[0])]
    return tuple((numbers + [0, 0, 0])[:3])


def is_newer(latest: str, current: str = __version__) -> bool:
    return version_key(latest) > version_key(current)


def _cache_path() -> Path:
    return Path.home() / ".cache" / "cachaza" / "latest-version.json"


def _read_cached(path: Path, now: float) -> str | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if now - float(payload.get("checked_at", 0)) <= CACHE_TTL:
            return str(payload.get("version") or "").lstrip("v") or None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return None


def _write_cached(path: Path, version: str, now: float) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"checked_at": now, "version": version}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    except OSError:
        pass


def latest_version(*, timeout: float = 2.5, force: bool = False) -> str | None:
    """Return the newest public version, using a 24-hour cache when possible."""
    now = time.time()
    cache = _cache_path()
    if not force:
        cached = _read_cached(cache, now)
        if cached:
            return cached
    headers = {"Accept": "application/vnd.github+json", "User-Agent": f"cachaza/{__version__}"}
    versions: list[str] = []
    try:
        with GLOBAL_REQUEST_LIMITER.slot():
            with urlopen(Request(LATEST_RELEASE_API, headers=headers), timeout=timeout) as response:
                payload: Any = json.loads(response.read().decode("utf-8", "replace"))
        release_version = str(payload.get("tag_name") or "").lstrip("v") if isinstance(payload, dict) else ""
        if release_version:
            versions.append(release_version)
    except (OSError, ValueError, TypeError, json.JSONDecodeError, HTTPError, URLError):
        pass
    # Main can contain a newer tagged package version before a GitHub Release is
    # created. Query both sources so existing installations still learn about it.
    try:
        with GLOBAL_REQUEST_LIMITER.slot():
            with urlopen(Request(RAW_PROJECT, headers=headers), timeout=timeout) as response:
                project = response.read().decode("utf-8", "replace")
        match = re.search(r"(?m)^version\s*=\s*[\"']([^\"']+)", project)
        if match:
            versions.append(match.group(1))
    except (OSError, HTTPError, URLError):
        pass
    if not versions:
        return None
    version = max(versions, key=version_key)
    _write_cached(cache, version, now)
    return version


def _project_root() -> Path | None:
    candidates = [Path.cwd(), *Path(__file__).resolve().parents]
    seen: set[Path] = set()
    for start in candidates:
        for path in (start, *start.parents):
            if path in seen:
                continue
            seen.add(path)
            if (path / ".git").exists() and (path / "pyproject.toml").is_file():
                return path
    return None


def update_command() -> str:
    if _project_root():
        return "git pull --ff-only origin main && pipx install --force . && cachaza -version && cachaza doctor"
    return (
        "pipx install --force git+https://github.com/W4RRR/cachaza.git "
        "&& cachaza -version && cachaza doctor"
    )


def perform_update(console: Console) -> int:
    """Update from a checkout when available, otherwise reinstall from GitHub."""
    pipx = shutil.which("pipx")
    if not pipx:
        raise RuntimeError("pipx is required for -up; install it with: sudo apt install pipx")
    root = _project_root()
    commands: list[tuple[list[str], Path | None]] = []
    if root:
        git = shutil.which("git")
        if not git:
            raise RuntimeError("git is required to update this checkout")
        commands.extend(
            [
                ([git, "pull", "--ff-only", "origin", "main"], root),
                ([pipx, "install", "--force", "."], root),
            ]
        )
    else:
        commands.append(
            ([pipx, "install", "--force", "git+https://github.com/W4RRR/cachaza.git"], None)
        )
    environment = constrained_environment({"CACHAZA_SKIP_UPDATE_CHECK": "1"})
    for argv, cwd in commands:
        console.info("Running update step: " + " ".join(argv[1:] if len(argv) > 1 else argv))
        completed = subprocess.run(argv, cwd=cwd, env=environment, check=False)
        if completed.returncode:
            raise RuntimeError(f"update step failed with exit code {completed.returncode}")
    executable = shutil.which("cachaza")
    if executable:
        subprocess.run([executable, "-version"], env=environment, check=False)
        subprocess.run([executable, "doctor"], env=environment, check=False)
    else:
        console.warn("Update installed, but cachaza is not yet visible on PATH; open a new shell.")
    return 0


def offer_update(console: Console) -> int | None:
    """Offer an interactive update; return an updater status or None to continue."""
    if console.silent or os.getenv("CACHAZA_SKIP_UPDATE_CHECK"):
        return None
    latest = latest_version()
    if not latest or not is_newer(latest):
        return None
    console.warn(f"Cachaza {__version__} is outdated; version {latest} is available.")
    if sys.stdin.isatty() and sys.stderr.isatty():
        try:
            answer = input("Update now? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer in {"", "y", "yes", "s", "si", "sí"}:
            return perform_update(console)
    console.warn(f"Update later with: cachaza -up\n  or: {update_command()}")
    return None
