"""Pinned and upstream user-space installers used by ``cachaza doctor``."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .network_policy import GLOBAL_REQUEST_LIMITER, constrained_environment


BLACKWIDOW_COMMIT = "c9eb24e238c390b03897a04c79e55cb17ec35b8c"
BLACKWIDOW_ARCHIVE = f"https://github.com/1N3/BlackWidow/archive/{BLACKWIDOW_COMMIT}.zip"
CSP_STALKER_COMMIT = "464808cb6cc5c340761583f7643b361780040d50"
CSP_STALKER_ARCHIVE = (
    f"https://github.com/0xakashk/CSP-Stalker/archive/{CSP_STALKER_COMMIT}.zip"
)

# These module paths are the installation commands published by their upstream
# projects. GOBIN is redirected to ~/.local/bin so Cachaza can find the result
# even when ~/go/bin is not present in PATH.
GO_TOOL_MODULES = {
    "asnmap": "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "403jump": "github.com/trap-bytes/403jump@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "cariddi": "github.com/edoardottt/cariddi/cmd/cariddi@latest",
    "vulnx": "github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest",
    "alterx": "github.com/projectdiscovery/alterx/cmd/alterx@latest",
    "puredns": "github.com/d3mondev/puredns/v2@latest",
    "uncover": "github.com/projectdiscovery/uncover/cmd/uncover@latest",
    "tlsx": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
}

PIPX_TOOL_PACKAGES = {
    "bbot": "bbot",
    "wafw00f": "wafw00f",
}


@dataclass(frozen=True, slots=True)
class InstallResult:
    name: str
    status: str
    detail: str


def managed_root() -> Path:
    return Path.home() / ".local" / "share" / "cachaza" / "tools"


def managed_blackwidow() -> Path:
    return managed_root() / "BlackWidow" / "blackwidow"


def managed_csp_stalker() -> Path:
    return Path.home() / ".local" / "bin" / "csp-stalker"


def managed_jsmap_inspector() -> Path:
    return Path.home() / ".local" / "bin" / "JSMap-Inspector"


def _download_archive(url: str, temporary: str, filename: str) -> Path:
    archive = Path(temporary) / filename
    request = urllib.request.Request(url, headers={"User-Agent": "cachaza-managed-installer"})
    with GLOBAL_REQUEST_LIMITER.slot():
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read(50_000_001)
    if len(payload) > 50_000_000:
        raise RuntimeError(f"{filename} exceeds the 50 MB safety limit")
    archive.write_bytes(payload)
    return archive


def _extract_single_directory(archive: Path, temporary: str, prefix: str) -> Path:
    with zipfile.ZipFile(archive) as package:
        extraction_root = Path(temporary).resolve()
        for member in package.infolist():
            target = (extraction_root / member.filename).resolve()
            if extraction_root not in target.parents and target != extraction_root:
                raise RuntimeError(f"unsafe path in {archive.name}")
        package.extractall(temporary)
    sources = [
        path
        for path in Path(temporary).iterdir()
        if path.is_dir() and path.name.casefold().startswith(prefix.casefold())
    ]
    if len(sources) != 1:
        raise RuntimeError(f"unexpected {archive.name} layout")
    return sources[0]


def _write_python_wrapper(path: Path, python: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{python}\n{body.rstrip()}\n", encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def install_jsmap_inspector() -> str:
    """Expose Cachaza's bounded source-map analyzer under the legacy tool name."""
    wrapper = managed_jsmap_inspector()
    _write_python_wrapper(
        wrapper,
        Path(sys.executable).resolve(),
        "from cachaza.jsmap_cli import main\nraise SystemExit(main())",
    )
    return str(wrapper)


def install_csp_stalker() -> str:
    """Install and rate-limit a pinned CSP-Stalker copy without sudo."""
    destination = managed_root() / "CSP-Stalker"
    script = destination / "cli_CSP_Stalker.py"
    marker = destination / ".cachaza-version"
    wrapper = managed_csp_stalker()
    if (
        script.is_file()
        and wrapper.is_file()
        and marker.is_file()
        and marker.read_text(encoding="utf-8", errors="replace").strip()
        == CSP_STALKER_COMMIT
    ):
        return str(wrapper)
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cachaza-csp-stalker-") as temporary:
        archive = _download_archive(CSP_STALKER_ARCHIVE, temporary, "csp-stalker.zip")
        source = _extract_single_directory(archive, temporary, "CSP-Stalker-")
        shutil.copytree(source, destination, dirs_exist_ok=False)

    if not script.is_file() or not (destination / "requirements.txt").is_file():
        raise RuntimeError("CSP-Stalker archive is missing its script or requirements")
    source_text = script.read_text(encoding="utf-8", errors="replace")
    limiter = '''

_cachaza_request_lock = threading.Lock()
_cachaza_next_request = 0.0


def _cachaza_request(call, *args, **kwargs):
    global _cachaza_next_request
    with _cachaza_request_lock:
        now = time.monotonic()
        scheduled = max(now, _cachaza_next_request)
        _cachaza_next_request = scheduled + 0.5
    if scheduled > now:
        time.sleep(scheduled - now)
    return call(*args, **kwargs)
'''
    if "import json" not in source_text:
        raise RuntimeError("CSP-Stalker source layout changed; refusing an unbounded install")
    source_text = source_text.replace(
        "import json",
        "import json\nimport threading\nimport time" + limiter,
        1,
    )
    source_text = source_text.replace("requests.head(", "_cachaza_request(requests.head, ")
    source_text = source_text.replace("requests.get(", "_cachaza_request(requests.get, ")
    if "requests.head(" in source_text or "requests.get(" in source_text:
        raise RuntimeError("could not apply the CSP-Stalker request-rate patch")
    script.write_text(source_text, encoding="utf-8", newline="\n")

    venv = destination / ".venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        env=constrained_environment(),
        check=True,
    )
    venv_python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "-r",
            str(destination / "requirements.txt"),
        ],
        env=constrained_environment(),
        check=True,
    )
    _write_python_wrapper(
        wrapper,
        venv_python,
        f"import runpy\nrunpy.run_path({str(script)!r}, run_name='__main__')",
    )
    marker.write_text(CSP_STALKER_COMMIT + "\n", encoding="utf-8")
    return str(wrapper)


def install_go_tool(name: str) -> str:
    module = GO_TOOL_MODULES.get(name)
    if not module:
        raise RuntimeError(f"no approved Go installation recipe for {name}")
    go = shutil.which("go")
    if not go:
        raise RuntimeError(
            f"cannot install {name}: Go is missing (install golang-go, then rerun doctor -install)"
        )
    bin_dir = Path.home() / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [go, "install", "-v", module],
        env=constrained_environment({"GOBIN": str(bin_dir)}),
        check=True,
    )
    executable = bin_dir / (f"{name}.exe" if os.name == "nt" else name)
    if not executable.is_file():
        raise RuntimeError(f"Go reported success but did not create {executable}")
    return str(executable)


def install_pipx_tool(name: str) -> str:
    package = PIPX_TOOL_PACKAGES.get(name)
    if not package:
        raise RuntimeError(f"no approved pipx installation recipe for {name}")
    pipx = shutil.which("pipx")
    if not pipx:
        raise RuntimeError(
            f"cannot install {name}: pipx is missing (install pipx, then rerun doctor -install)"
        )
    subprocess.run(
        [pipx, "install", package],
        env=constrained_environment(),
        check=True,
    )
    executable = Path.home() / ".local" / "bin" / name
    if os.name == "nt":
        executable = executable.with_suffix(".exe")
    if not executable.is_file():
        resolved = shutil.which(name)
        if resolved:
            return resolved
        raise RuntimeError(f"pipx reported success but {name} is still unavailable")
    return str(executable)


def install_missing_tools(
    finder: Callable[[str], str | None] | None = None,
) -> list[InstallResult]:
    """Install every absent tool for which Cachaza has a safe user-space recipe."""
    if finder is None:
        from .external import find_tool

        finder = find_tool
    installers: list[tuple[str, Callable[[], str]]] = [
        ("JSMap-Inspector", install_jsmap_inspector),
        ("csp-stalker", install_csp_stalker),
        ("blackwidow", install_blackwidow),
    ]
    installers.extend(
        (name, lambda selected=name: install_go_tool(selected))
        for name in GO_TOOL_MODULES
    )
    installers.extend(
        (name, lambda selected=name: install_pipx_tool(selected))
        for name in PIPX_TOOL_PACKAGES
    )
    results: list[InstallResult] = []
    for name, installer in installers:
        present = finder(name)
        if present:
            results.append(InstallResult(name, "ready", present))
            continue
        try:
            installed = installer()
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            results.append(InstallResult(name, "failed", str(exc)))
        else:
            results.append(InstallResult(name, "installed", installed))
    return results


def install_blackwidow() -> str:
    """Install a pinned BlackWidow copy and its Python dependencies without sudo."""
    destination = managed_root() / "BlackWidow"
    executable = destination / "blackwidow"
    marker = destination / ".cachaza-version"
    if executable.is_file() and marker.is_file() and marker.read_text(encoding="utf-8", errors="replace").strip() == BLACKWIDOW_COMMIT:
        return str(executable)
    if destination.exists():
        shutil.rmtree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cachaza-blackwidow-") as temporary:
        archive = Path(temporary) / "blackwidow.zip"
        request = urllib.request.Request(BLACKWIDOW_ARCHIVE, headers={"User-Agent": "cachaza-managed-installer"})
        with GLOBAL_REQUEST_LIMITER.slot():
            with urllib.request.urlopen(request, timeout=60) as response:
                payload = response.read(50_000_001)
        if len(payload) > 50_000_000:
            raise RuntimeError("BlackWidow archive exceeds the 50 MB safety limit")
        archive.write_bytes(payload)
        with zipfile.ZipFile(archive) as package:
            extraction_root = Path(temporary).resolve()
            for member in package.infolist():
                target = (extraction_root / member.filename).resolve()
                if extraction_root not in target.parents and target != extraction_root:
                    raise RuntimeError("unsafe path in BlackWidow archive")
            package.extractall(temporary)
        sources = [path for path in Path(temporary).iterdir() if path.is_dir() and path.name.lower().startswith("blackwidow-")]
        if len(sources) != 1:
            raise RuntimeError("unexpected BlackWidow archive layout")
        shutil.copytree(sources[0], destination, dirs_exist_ok=False)

    venv = destination / ".venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv)],
        env=constrained_environment(),
        check=True,
    )
    venv_python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--disable-pip-version-check", "requests", "beautifulsoup4", "lxml"],
        env=constrained_environment(),
        check=True,
    )
    for name in ("blackwidow", "injectx.py"):
        path = destination / name
        if not path.is_file():
            raise RuntimeError(f"BlackWidow archive is missing {name}")
        source = path.read_text(encoding="utf-8", errors="replace")
        source = re.sub(r"\A#![^\r\n]+", lambda _: f"#!{venv_python}", source, count=1)
        source = source.replace(
            "import requests, sys, os, atexit, optparse",
            "import requests, sys, os, atexit, optparse, subprocess",
        )
        if name == "blackwidow":
            helpers = f'''\n\ndef _cachaza_unique_dynamic(source_path, destination_path):
    representatives = {{}}
    try:
        with open(source_path, encoding="utf-8", errors="replace") as source_file:
            for candidate_url in source_file.read().splitlines():
                query = urlparse(candidate_url).query
                for pair in query.split("&"):
                    parameter = pair.partition("=")[0].strip()
                    if parameter:
                        representatives.setdefault(parameter, candidate_url)
        with open(destination_path, "w", encoding="utf-8") as destination_file:
            for candidate_url in sorted(representatives.values()):
                destination_file.write(candidate_url + "\\n")
    except OSError as exc:
        print(exc)


def _cachaza_run_injectx(source_path):
    try:
        with open(source_path, encoding="utf-8", errors="replace") as source_file:
            for candidate_url in source_file.read().splitlines():
                if candidate_url.strip():
                    subprocess.run([sys.executable, {str(destination / 'injectx.py')!r}, "-u", candidate_url.strip()], check=False)
    except OSError as exc:
        print(exc)
'''
            source = source.replace("def exit_handler():", helpers + "\n\ndef exit_handler():", 1)
            rewritten: list[str] = []
            for line in source.splitlines():
                indentation = line[: len(line) - len(line.lstrip())]
                if "os.system('for a in `cat '" in line and "-dynamic-sorted.txt" in line:
                    rewritten.append(indentation + "_cachaza_unique_dynamic(save_dir + domain + '_' + port + '-dynamic-sorted.txt', save_dir + domain + '_' + port + '-dynamic-unique.txt')")
                elif "os.system('for a in `cat '" in line and "/usr/bin/injectx.py" in line:
                    rewritten.append(indentation + "_cachaza_run_injectx(save_dir + domain + '_' + port + '-dynamic-unique.txt')")
                else:
                    rewritten.append(line)
            source = "\n".join(rewritten) + "\n"
            if "/usr/bin/injectx.py" in source or "-u $a" in source:
                raise RuntimeError("could not apply the BlackWidow shell-safety patch")
        source = source.replace(
            "'/usr/share/blackwidow/'",
            "os.environ.get('CACHAZA_BLACKWIDOW_OUTPUT', os.path.expanduser('~/.local/share/cachaza/blackwidow-output')) + '/'",
        )
        source = source.replace(
            '"/usr/share/blackwidow/"',
            "os.environ.get('CACHAZA_BLACKWIDOW_OUTPUT', os.path.expanduser('~/.local/share/cachaza/blackwidow-output')) + '/'",
        )
        path.write_text(source, encoding="utf-8", newline="\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    marker.write_text(BLACKWIDOW_COMMIT + "\n", encoding="utf-8")
    return str(executable)
