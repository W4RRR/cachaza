"""Load optional API credentials as data without executing configuration files."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


LINE = re.compile(r"^(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$")
PLACEHOLDERS = ("your_", "replace_", "changeme", "example", "<")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value.replace('\\"', '"').replace("\\'", "'").strip()


def load_credentials(path: str | Path | None = None) -> dict[str, str]:
    """Return environment plus safe KEY=value entries from an optional file."""
    values = dict(os.environ)
    if not path:
        return values
    source = Path(path).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"API configuration file does not exist: {source}")
    for raw in source.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LINE.fullmatch(line)
        if not match:
            continue
        value = _unquote(match.group(2))
        if value and not value.lower().startswith(PLACEHOLDERS):
            values[match.group(1)] = value
    return values


def _first(values: dict[str, str], *names: str) -> str:
    for name in names:
        value = values.get(name, "").strip()
        if value and not value.lower().startswith(PLACEHOLDERS):
            return value
    return ""


def _composite(values: dict[str, str], left: tuple[str, ...], right: tuple[str, ...]) -> str:
    first, second = _first(values, *left), _first(values, *right)
    return f"{first}:{second}" if first and second else ""


def subfinder_provider_values(values: dict[str, str]) -> dict[str, str]:
    intelx_key = _first(values, "INTELX_API_KEY")
    return {
        "bevigil": _first(values, "BEVIGIL_API_KEY"),
        "binaryedge": _first(values, "BINARYEDGE_API_KEY"),
        "builtwith": _first(values, "BUILTWITH_API_KEY"),
        "certspotter": _first(values, "CERTSPOTTER_API_KEY"),
        "censys": _composite(values, ("CENSYS_API_ID",), ("CENSYS_API_SECRET",)),
        "chaos": _first(values, "CHAOS_API_KEY", "PDCP_API_KEY"),
        "fofa": _composite(values, ("FOFA_EMAIL",), ("FOFA_API_KEY",)),
        "fullhunt": _first(values, "FULLHUNT_API_KEY"),
        "github": _first(values, "GITHUB_TOKEN"),
        "hunter": _first(values, "HUNTER_API_KEY"),
        "intelx": f"{_first(values, 'INTELX_HOST') or '2.intelx.io'}:{intelx_key}" if intelx_key else "",
        "passivetotal": _composite(
            values, ("PASSIVETOTAL_USERNAME",), ("PASSIVETOTAL_KEY",)
        ),
        "securitytrails": _first(values, "SECURITYTRAILS_API_KEY"),
        "shodan": _first(values, "SHODAN_API_KEY"),
        "virustotal": _first(values, "VT_API_KEY", "VIRUSTOTAL_API_KEY"),
        "whoisxmlapi": _first(values, "WHOISXML_API_KEY"),
        "zoomeyeapi": (
            f"{_first(values, 'ZOOMEYE_HOST') or 'zoomeye.hk'}:"
            f"{_first(values, 'ZOOMEYE_API_KEY')}"
            if _first(values, "ZOOMEYE_API_KEY")
            else ""
        ),
    }


@contextmanager
def temporary_subfinder_config(values: dict[str, str]) -> Iterator[str | None]:
    """Create a private provider config and remove it after Subfinder exits."""
    providers = subfinder_provider_values(values)
    if not any(providers.values()):
        yield None
        return
    handle = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".yaml", prefix="cachaza-subfinder-", delete=False
    )
    path = Path(handle.name)
    try:
        handle.write("# Temporary Cachaza provider configuration.\n")
        for name, value in sorted(providers.items()):
            if value:
                handle.write(f"{name}:\n")
                handle.write(f"  - {json.dumps(value, ensure_ascii=False)}\n")
            else:
                handle.write(f"{name}: []\n")
        handle.close()
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        yield str(path)
    finally:
        try:
            handle.close()
        except OSError:
            pass
        path.unlink(missing_ok=True)


def harvester_provider_values(values: dict[str, str]) -> dict[str, dict[str, str]]:
    """Translate Cachaza's flat environment format to theHarvester's YAML schema."""
    providers: dict[str, dict[str, str]] = {}

    def one(provider: str, field: str, *names: str) -> None:
        value = _first(values, *names)
        if value:
            providers.setdefault(provider, {})[field] = value

    one("bevigil", "key", "BEVIGIL_API_KEY")
    one("builtwith", "key", "BUILTWITH_API_KEY")
    one("certspotter", "key", "CERTSPOTTER_API_KEY")
    one("chaos", "key", "CHAOS_API_KEY", "PDCP_API_KEY")
    one("fullhunt", "key", "FULLHUNT_API_KEY")
    one("github", "key", "GITHUB_TOKEN")
    one("hunter", "key", "HUNTER_API_KEY")
    one("intelx", "key", "INTELX_API_KEY")
    one("projectDiscovery", "key", "PDCP_API_KEY")
    one("securityTrails", "key", "SECURITYTRAILS_API_KEY")
    one("shodan", "key", "SHODAN_API_KEY")
    one("tomba", "key", "TOMBA_API_KEY")
    one("urlscan", "key", "URLSCAN_API_KEY")
    one("virustotal", "key", "VT_API_KEY", "VIRUSTOTAL_API_KEY")
    one("whoisxml", "key", "WHOISXML_API_KEY")
    one("zoomeye", "key", "ZOOMEYE_API_KEY")
    # theHarvester's Censys module still uses an ID/secret pair. The native
    # Cachaza CENSYS_API_KEY is a Platform PAT and must not be put in either field.
    one("censys", "id", "CENSYS_API_ID")
    one("censys", "secret", "CENSYS_API_SECRET")
    return providers


@contextmanager
def temporary_harvester_home(values: dict[str, str]) -> Iterator[str]:
    """Overlay provider values in a private HOME without modifying user configuration."""
    with tempfile.TemporaryDirectory(prefix="cachaza-harvester-") as temporary:
        home = Path(temporary)
        destination = home / ".theHarvester"
        existing = Path.home() / ".theHarvester"
        if existing.is_dir():
            shutil.copytree(existing, destination)
        else:
            destination.mkdir(parents=True)
        config = destination / "api-keys.yaml"
        overlays = harvester_provider_values(values)
        if overlays:
            # JSON is valid YAML. A private HOME means the user's actual
            # api-keys.yaml is never overwritten or executed.
            config.write_text(
                json.dumps({"apikeys": overlays}, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        try:
            config.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        yield str(home)
