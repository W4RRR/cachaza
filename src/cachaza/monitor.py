"""Certificate Transparency monitoring backends."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from .console import Console
from .external import find_tool
from .models import utc_now
from .network_policy import constrained_environment
from .safety import domain_in_scope, extract_domains
from .sources import certspotter_domains, crtsh_domains


def _record(handle, domain: str, source: str) -> None:
    event = {"observed_at": utc_now(), "source": source, "kind": "domain", "value": domain}
    handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
    handle.flush()
    print(domain, flush=True)


def monitor_gungnir(domains: list[str], output: Path, console: Console) -> int:
    binary = find_tool("gungnir")
    if not binary:
        raise RuntimeError("gungnir is not installed")
    roots_file = output / "roots.txt"
    roots_file.write_text("\n".join(domains) + "\n", encoding="utf-8")
    events_file = output / "monitor.jsonl"
    argv = [binary, "-r", str(roots_file), "-f"]
    console.info("CT monitor started with Gungnir; press Ctrl-C to stop")
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=constrained_environment(),
        shell=False,
    )
    seen: set[str] = set()
    try:
        with events_file.open("a", encoding="utf-8", newline="\n") as handle:
            assert process.stdout is not None
            for line in process.stdout:
                for domain in extract_domains(line, domains):
                    if domain in seen or not domain_in_scope(domain, domains):
                        continue
                    seen.add(domain)
                    _record(handle, domain, "gungnir")
    except KeyboardInterrupt:
        console.info("Stopping CT monitor")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        return 130
    return process.wait()


def monitor_crtsh(
    domains: list[str],
    output: Path,
    console: Console,
    *,
    interval: int,
    once: bool,
    timeout: int,
    retries: int,
) -> int:
    seen_file = output / "monitor-seen.txt"
    events_file = output / "monitor.jsonl"
    seen = set(seen_file.read_text(encoding="utf-8").splitlines()) if seen_file.is_file() else set()
    console.info("CT monitor started with Cert Spotter + crt.sh polling; press Ctrl-C to stop")
    try:
        while True:
            current: set[str] = set()
            evidence: dict[str, set[str]] = {}
            for root in domains:
                try:
                    names = certspotter_domains(root, timeout=timeout, retries=retries)
                except Exception as exc:
                    console.warn(f"Cert Spotter unavailable for {root}: {exc}")
                else:
                    current.update(names)
                    for name in names:
                        evidence.setdefault(name, set()).add("certspotter")
                try:
                    names = crtsh_domains(
                        root, timeout=min(timeout, 8), retries=0
                    )
                except Exception as exc:
                    console.warn(
                        f"crt.sh unavailable for {root}: {exc}. Continuing with Cert Spotter results."
                    )
                else:
                    current.update(names)
                    for name in names:
                        evidence.setdefault(name, set()).add("crt.sh")
            new_names = sorted(current - seen)
            with events_file.open("a", encoding="utf-8", newline="\n") as handle:
                for domain in new_names:
                    _record(handle, domain, ",".join(sorted(evidence.get(domain, {"ct"}))))
            seen.update(current)
            seen_file.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""), encoding="utf-8")
            if once:
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        console.info("CT monitor stopped")
        return 130
