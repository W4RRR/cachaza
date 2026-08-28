"""Small terminal output helper used by Cachaza commands."""

from __future__ import annotations

import sys
import json
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any


COCKTAIL_ART = "\n".join(
    (
        ".-========-.",
        " \\   o   /",
        "  \\     /",
        "   `---'",
        "     ||",
        "     ||",
        "   __||__",
        "  /______\\",
    )
)

CACHAZA_WORDMARK = "\n".join(
    (
        "_________     _____  _________   ___ ___    _____  __________  _____",
        "\\_   ___ \\   /  _  \\ \\_   ___ \\ /   |   \\  /  _  \\ \\____    / /  _  \\",
        "/    \\  \\/  /  /_\\  \\/    \\  \\//    ~    \\/  /_\\  \\  /     / /  /_\\  \\",
        "\\     \\____/    |    \\     \\___\\    Y    /    |    \\/     /_/    |    \\",
        " \\______  /\\____|__  /\\______  /\\___|_  /\\____|__  /_______ \\____|__  /",
        "        \\/         \\/        \\/       \\/         \\/        \\/       \\/",
    )
)


@dataclass(slots=True)
class Console:
    verbose: int = 0
    silent: bool = False
    color: bool = True
    log_path: Path | None = None

    def attach_log(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path = path
        self.log("execution log opened")

    def log(self, message: str, *, source: str = "cachaza") -> None:
        if self.log_path is None:
            return
        stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} [{source}] {message}\n")

    def paint(self, text: str, code: str) -> str:
        return self._paint(text, code)

    def _paint(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def banner(self, version: str) -> None:
        if self.silent:
            return
        width = max(len(line) for line in CACHAZA_WORDMARK.splitlines())
        cocktail_lines = COCKTAIL_ART.splitlines()
        cocktail_width = max(len(line) for line in cocktail_lines)
        cocktail_indent = " " * max(0, (width - cocktail_width) // 2)
        cocktail = "\n".join(f"{cocktail_indent}{line}".rstrip() for line in cocktail_lines)
        art = f"{cocktail}\n\n{CACHAZA_WORDMARK}"
        print(self._paint(art, "36"), file=sys.stderr)
        attribution = "github.com/W4RRR/cachaza by W4RRR".center(width).rstrip()
        installed_version = f"v{version}".center(width).rstrip()
        print(self._paint(attribution, "1;33"), file=sys.stderr)
        print(self._paint(installed_version, "90"), file=sys.stderr)

    def info(self, message: str) -> None:
        self.log(message, source="INFO")
        if not self.silent:
            print(self._paint("[+]", "32") + f" {message}", file=sys.stderr)

    def debug(self, message: str) -> None:
        self.log(message, source="DEBUG")
        if not self.silent and self.verbose:
            print(self._paint("[*]", "36") + f" {message}", file=sys.stderr)

    def finding(
        self,
        *,
        source: str,
        kind: str,
        value: str,
        in_scope: bool,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Print every normalized finding at -v and its metadata at -vv."""
        scope = "authorized" if in_scope else "candidate"
        self.log(f"{kind}: {value} | source={source} | scope={scope}", source="FOUND")
        if self.silent or not self.verbose:
            return
        prefix = self._paint("[FOUND]", "36")
        print(
            f"{prefix} {kind}: {value} | source={source} | scope={scope}",
            file=sys.stderr,
        )
        if self.verbose > 1 and metadata:
            details = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
            print(self._paint("[META]", "90") + f" {details}", file=sys.stderr)

    def stream(self, source: str, line: str) -> None:
        """Relay an external tool's live output only in verbose mode."""
        if line:
            self.log(line, source=source)
        if self.silent or not self.verbose or not line:
            return
        print(self._paint(f"[{source}]", "90") + f" {line}", file=sys.stderr)

    def warn(self, message: str) -> None:
        self.log(message, source="WARNING")
        if not self.silent:
            print(self._paint("[!]", "33") + f" {message}", file=sys.stderr)

    def error(self, message: str) -> None:
        self.log(message, source="ERROR")
        print(self._paint("[-]", "31") + f" {message}", file=sys.stderr)
