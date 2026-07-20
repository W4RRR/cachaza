"""Safe subprocess adapters and dependency checks."""

from __future__ import annotations

import importlib.util
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .console import Console
from .network_policy import (
    MAX_CONCURRENCY,
    MAX_REQUESTS_PER_SECOND,
    MIN_REQUEST_INTERVAL,
    constrained_environment,
    enforce_tool_limits,
)


TOOLS = (
    "asnmap",
    "tenant-domains.sh",
    "tenant-domains",
    "subfinder",
    "assetfinder",
    "bbot",
    "smap",
    "gungnir",
    "caduceus",
    "httpx",
    "naabu",
    "dnsx",
    "nuclei",
    "403jump",
    "gau",
    "katana",
    "cariddi",
    "JSMap-Inspector",
    "csp-stalker",
    "favicorn",
    "vulnx",
    "nmap",
    "whois",
    "wafw00f",
    "theHarvester",
    "dnsenum",
    "fierce",
    "blackwidow",
    "alterx",
    "puredns",
    "massdns",
    "uncover",
    "tlsx",
)


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False


def find_tool(name: str, explicit: str | None = None) -> str | None:
    if explicit:
        path = Path(explicit).expanduser()
        if path.is_file():
            return str(path)
        return shutil.which(explicit)
    resolved = shutil.which(name)
    if resolved:
        return resolved
    candidates = [Path.home() / ".local" / "bin" / name]
    if name == "blackwidow":
        candidates.append(Path.home() / ".local" / "share" / "cachaza" / "tools" / "BlackWidow" / "blackwidow")
    return next((str(path) for path in candidates if path.is_file()), None)


def display_command(argv: list[str]) -> str:
    return shlex.join(argv)


class CommandRunner:
    def __init__(self, console: Console, *, dry_run: bool = False, timeout: int = 300):
        self.console = console
        self.dry_run = dry_run
        self.timeout = timeout
        self.history: list[dict[str, object]] = []
        self._process_slots = threading.BoundedSemaphore(MAX_CONCURRENCY)
        self._start_lock = threading.Lock()
        self._next_start = 0.0

    def _pace_start(self) -> None:
        with self._start_lock:
            now = time.monotonic()
            scheduled = max(now, self._next_start)
            self._next_start = scheduled + MIN_REQUEST_INTERVAL
        delay = scheduled - now
        if delay > 0:
            time.sleep(delay)

    def run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        clean_argv = enforce_tool_limits([str(part) for part in argv])
        shown = display_command(clean_argv)
        self.console.debug(f"Running: {shown}")
        if self.dry_run:
            result = CommandResult(clean_argv, 0, "", "", skipped=True)
            self.history.append({"command": shown, "returncode": 0, "skipped": True})
            return result
        with self._process_slots:
            self._pace_start()
            if self.console.verbose and not self.console.silent:
                result = self._run_streaming(
                    clean_argv,
                    input_text=input_text,
                    timeout=timeout or self.timeout,
                    cwd=cwd,
                    env=env,
                )
            else:
                result = self._run_captured(
                    clean_argv,
                    input_text=input_text,
                    timeout=timeout or self.timeout,
                    cwd=cwd,
                    env=env,
                )
        self.history.append(
            {"command": shown, "returncode": result.returncode, "skipped": result.skipped}
        )
        return result

    def _run_captured(
        self,
        argv: list[str],
        *,
        input_text: str | None,
        timeout: int,
        cwd: Path | None,
        env: dict[str, str] | None,
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                argv,
                input=input_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                env=constrained_environment(env),
                shell=False,
                check=False,
            )
            return CommandResult(argv, completed.returncode, completed.stdout, completed.stderr)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return CommandResult(argv, 124, stdout, stderr + "\nCommand timed out")

    def _run_streaming(
        self,
        argv: list[str],
        *,
        input_text: str | None,
        timeout: int,
        cwd: Path | None,
        env: dict[str, str] | None,
    ) -> CommandResult:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(cwd) if cwd else None,
            env=constrained_environment(env),
            shell=False,
        )
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        tool = Path(argv[0]).name

        def drain(stream, bucket: list[str]) -> None:
            if stream is None:
                return
            for line in stream:
                bucket.append(line)
                self.console.stream(tool, line.rstrip("\r\n"))

        threads = [
            threading.Thread(target=drain, args=(process.stdout, stdout_lines), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr_lines), daemon=True),
        ]
        for thread in threads:
            thread.start()
        if input_text is not None and process.stdin is not None:
            try:
                process.stdin.write(input_text)
                process.stdin.close()
            except BrokenPipeError:
                pass
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            returncode = 124
            process.wait()
        for thread in threads:
            thread.join(timeout=2)
        if timed_out:
            stderr_lines.append("Command timed out\n")
            self.console.stream(tool, "Command timed out")
        return CommandResult(argv, returncode, "".join(stdout_lines), "".join(stderr_lines))


def doctor_rows(credentials: dict[str, str] | None = None) -> list[tuple[str, str, str]]:
    values = credentials if credentials is not None else dict(os.environ)
    rows: list[tuple[str, str, str]] = [
        (
            "network-policy",
            "ok",
            f"hard ceiling: {MAX_REQUESTS_PER_SECOND} request/packet starts per second; "
            f"{MAX_CONCURRENCY} network workers",
        )
    ]
    for tool in TOOLS:
        resolved = find_tool(tool)
        rows.append((tool, "ok" if resolved else "missing", resolved or "-"))
    for label, module in (
        ("origin-dns", "dns"),
        ("origin-tls", "cryptography"),
        ("origin-favicon-mmh3", "mmh3"),
    ):
        available = importlib.util.find_spec(module) is not None
        rows.append((label, "ok" if available else "missing", f"Python module: {module}"))
    for name, absent in (
        ("SHODAN_API_KEY", "missing"),
        ("PDCP_API_KEY", "missing"),
        ("CENSYS_API_KEY", "optional"),
        ("CENSYS_API_ID", "optional"),
        ("CENSYS_API_SECRET", "optional"),
        ("INTELX_API_KEY", "optional"),
        ("ZOOMEYE_API_KEY", "optional"),
        ("URLSCAN_API_KEY", "optional"),
        ("CERTSPOTTER_API_KEY", "optional"),
        ("VIRUSTOTAL_API_KEY", "optional"),
        ("VT_API_KEY", "optional"),
        ("SECURITYTRAILS_API_KEY", "optional"),
        ("DNSDB_API_KEY", "optional"),
        ("WHOISXML_API_KEY", "optional"),
    ):
        rows.append((name, "ok" if values.get(name, "").strip() else absent, "configuration (presence only)"))
    return rows
