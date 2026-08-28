from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import __version__
from .network_policy import GLOBAL_REQUEST_LIMITER


class HttpError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        transient: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.transient = transient


USER_AGENT = f"cachaza/{__version__} (+authorized-security-research)"


def request_bytes(
    url: str,
    *,
    timeout: int = 20,
    retries: int = 2,
    params: dict[str, str | int] | None = None,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: bytes | None = None,
) -> bytes:
    if params:
        query = urllib.parse.urlencode(params)
        url = f"{url}{'&' if '?' in url else '?'}{query}"
    safe_url = url.split("?", 1)[0]
    request_headers = {
        "Accept": "application/json,text/plain;q=0.9,*/*;q=0.1",
        "User-Agent": USER_AGENT,
    }
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers, data=data, method=method)
    last_error: Exception | None = None
    status_code: int | None = None
    transient = False
    provider_detail = ""
    for attempt in range(retries + 1):
        try:
            with GLOBAL_REQUEST_LIMITER.slot():
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    return response.read()
        except urllib.error.HTTPError as exc:
            last_error = exc
            status_code = exc.code
            provider_detail = ""
            try:
                raw_detail = exc.read(4096).decode("utf-8", errors="replace")
                parsed_detail = json.loads(raw_detail)
                if isinstance(parsed_detail, dict):
                    detail = parsed_detail.get("error") or parsed_detail.get("message") or parsed_detail.get("detail")
                    if isinstance(detail, dict):
                        detail = detail.get("message") or detail.get("code") or detail
                    if detail:
                        provider_detail = str(detail)[:800]
            except (OSError, ValueError, TypeError):
                pass
            transient = exc.code in {408, 425, 429} or exc.code >= 500
            if not transient:
                break
            if attempt < retries:
                time.sleep(min(2**attempt, 4))
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = exc
            transient = True
            if attempt < retries:
                time.sleep(min(2**attempt, 4))
    # Never echo query parameters: API keys (notably Shodan's) travel there.
    diagnostic = str(last_error)
    if provider_detail:
        diagnostic = f"{diagnostic}; provider detail: {provider_detail}"
    raise HttpError(
        f"HTTP request failed for {safe_url}: {diagnostic}",
        status_code=status_code,
        transient=transient,
    ) from last_error


def request_json(
    url: str,
    *,
    timeout: int = 20,
    retries: int = 2,
    params: dict[str, str | int] | None = None,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    json_body: Any | None = None,
) -> Any:
    request_headers = dict(headers or {})
    data: bytes | None = None
    if json_body is not None:
        data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    payload = request_bytes(
        url,
        timeout=timeout,
        retries=retries,
        params=params,
        headers=request_headers,
        method=method,
        data=data,
    )
    try:
        return json.loads(payload.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise HttpError(f"invalid JSON response from {url.split('?', 1)[0]}") from exc
