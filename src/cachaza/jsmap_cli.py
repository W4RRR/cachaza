"""Bounded JavaScript source-map analyzer exposed as ``JSMap-Inspector``."""

from __future__ import annotations

import argparse
import base64
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .network_policy import GLOBAL_REQUEST_LIMITER


SOURCE_MAP_RE = re.compile(
    r"(?:\/\/[#@]|\/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>\\)\]]+", re.IGNORECASE)
REFERENCE_RE = re.compile(
    r"[\"']((?:https?://|/|\.\.?/)[^\"'\s<>]{1,2000})[\"']",
    re.IGNORECASE,
)
MAX_INPUTS = 200


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    return parsed.scheme.casefold(), (parsed.hostname or "").casefold(), parsed.port


class _SameOriginRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed: tuple[str, str, int | None]) -> None:
        super().__init__()
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        if _origin(newurl) != self.allowed:
            raise urllib.error.HTTPError(
                newurl,
                code,
                "cross-origin redirect blocked by Cachaza scope policy",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str, *, timeout: int, max_bytes: int) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only absolute HTTP(S) URLs are accepted")
    opener = urllib.request.build_opener(_SameOriginRedirects(_origin(url)))
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "cachaza-jsmap-inspector/1"},
    )
    with GLOBAL_REQUEST_LIMITER.slot():
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError(f"response exceeds the {max_bytes}-byte limit")
    return payload


def _inline_map(value: str, *, max_bytes: int) -> bytes:
    header, separator, payload = value.partition(",")
    if not separator or not header.casefold().startswith("data:application/json"):
        raise ValueError("unsupported inline source map")
    raw = base64.b64decode(payload, validate=True) if ";base64" in header.casefold() else urllib.parse.unquote_to_bytes(payload)
    if len(raw) > max_bytes:
        raise ValueError(f"inline source map exceeds the {max_bytes}-byte limit")
    return raw


def _map_reference(script_url: str, script: str) -> tuple[str, bool]:
    matches = SOURCE_MAP_RE.findall(script)
    if matches:
        reference = matches[-1].strip().rstrip("*/")
        if reference.casefold().startswith("data:"):
            return reference, True
        return urllib.parse.urljoin(script_url, reference), False
    return script_url + ".map", False


def _same_origin(first: str, second: str) -> bool:
    return _origin(first) == _origin(second)


def analyze_url(url: str, *, timeout: int = 20, max_bytes: int = 5_000_000) -> dict[str, object]:
    record: dict[str, object] = {"javascript_url": url}
    try:
        script_bytes = _fetch(url, timeout=timeout, max_bytes=max_bytes)
        script = script_bytes.decode("utf-8", "replace")
        reference, inline = _map_reference(url, script)
        if inline:
            map_bytes = _inline_map(reference, max_bytes=max_bytes)
            record["sourcemap_url"] = "inline:data:application/json"
        else:
            if not _same_origin(url, reference):
                raise ValueError("cross-origin source map blocked by Cachaza scope policy")
            map_bytes = _fetch(reference, timeout=timeout, max_bytes=max_bytes)
            record["sourcemap_url"] = reference
        source_map = json.loads(map_bytes.decode("utf-8", "replace"))
        if not isinstance(source_map, dict):
            raise ValueError("source map root is not a JSON object")
        sources = source_map.get("sources")
        contents = source_map.get("sourcesContent")
        source_names = sources if isinstance(sources, list) else []
        source_contents = contents if isinstance(contents, list) else []
        urls: set[str] = set()
        references: set[str] = set()
        for content in source_contents[:10_000]:
            if not isinstance(content, str):
                continue
            urls.update(URL_RE.findall(content))
            references.update(REFERENCE_RE.findall(content))
        record.update(
            {
                "source_count": len(source_names),
                "sources": [str(value)[:2_000] for value in source_names[:10_000]],
                "urls": sorted(urls)[:10_000],
                "references": sorted(references)[:10_000],
            }
        )
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
        record["error"] = str(exc)
    return record


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="JSMap-Inspector",
        description="Analyze same-origin JavaScript source maps with Cachaza's global 2 rps limit.",
    )
    parser.add_argument("-l", "--list", required=True, dest="input_file")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--max-bytes", type=int, default=5_000_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not 1 <= args.timeout <= 120:
        raise SystemExit("--timeout must be between 1 and 120 seconds")
    if not 1_024 <= args.max_bytes <= 50_000_000:
        raise SystemExit("--max-bytes must be between 1024 and 50000000")
    input_path = Path(args.input_file).expanduser()
    output_path = Path(args.output).expanduser()
    urls = list(
        dict.fromkeys(
            line.strip()
            for line in input_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        )
    )
    if len(urls) > MAX_INPUTS:
        raise SystemExit(f"input contains {len(urls)} URLs; maximum is {MAX_INPUTS}")
    records = [
        analyze_url(url, timeout=args.timeout, max_bytes=args.max_bytes)
        for url in urls
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
