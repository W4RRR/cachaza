"""Automatic, bounded Origin discovery and Direct-origin validation.

This module correlates public evidence and performs only low-impact web checks
against candidates produced by Cachaza.  It deliberately contains no WAF
evasion, trust-header manipulation, fuzzing, POST requests, range expansion,
or vulnerability scanning.
"""

from __future__ import annotations

import csv
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from difflib import SequenceMatcher
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, Callable, Iterable

from .adapters.origin import (
    CandidateObservation,
    collect_resolved_names,
    collect_workspace_observations,
    resolve_host,
    run_dns_permutations,
    securitytrails_resolutions,
    virustotal_resolutions,
)
from .console import Console
from .external import CommandRunner, find_tool
from .http import USER_AGENT, HttpError, request_bytes
from .models import OriginCandidate, OriginConfig, OriginEvidence, OriginNetwork, TargetSpec, utc_now
from .safety import domain_in_scope
from .workspace import RunWorkspace


ORIGIN_WARNING = (
    "A high-confidence result indicates strong technical correlation. "
    "It does not prove administrative ownership, current production use or authorization "
    "to perform further testing against the IP."
)

FORBIDDEN_REQUEST_HEADERS = {
    "x-forwarded-host",
    "x-original-url",
    "x-rewrite-url",
    "true-client-ip",
    "cf-connecting-ip",
    "x-forwarded-for",
    "forwarded",
    "authorization",
    "proxy-authorization",
}

SENSITIVE_PATH_PARTS = {
    "login",
    "logout",
    "register",
    "reset",
    "password",
    "admin",
    "delete",
    "remove",
    "payment",
    "checkout",
    "upload",
    "webhook",
    "callback",
    "oauth",
    "sso",
}

SIGNIFICANT_LABELS = (
    "origin",
    "origin1",
    "origin2",
    "direct",
    "direct-connect",
    "backend",
    "backend-prod",
    "backend-production",
    "web",
    "web01",
    "web02",
    "www-origin",
    "prod",
    "production",
    "app",
    "api",
    "api-prod",
    "gateway",
    "edge-origin",
    "old",
    "legacy",
    "previous",
    "staging",
    "stage",
    "dev",
    "test",
)

KNOWN_PUBLIC_DNS = {
    "1.0.0.1",
    "1.1.1.1",
    "8.8.4.4",
    "8.8.8.8",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.220.220",
    "208.67.222.222",
    "2606:4700:4700::1001",
    "2606:4700:4700::1111",
    "2001:4860:4860::8844",
    "2001:4860:4860::8888",
}

# Offline fallback.  A cached copy from the two official Cloudflare endpoints
# replaces this list when available and remains valid for seven days.
CLOUDFLARE_FALLBACK = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
    "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)

CDN_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Cloudflare", ("cloudflare", "cf-ray", "__cf_bm")),
    ("Akamai", ("akamai", "akamaiedge", "akamaihd")),
    ("Fastly", ("fastly", "x-served-by", "x-cache-hits")),
    ("Amazon CloudFront", ("cloudfront", "x-amz-cf-id", "x-amz-cf-pop")),
    ("Imperva", ("imperva", "incapsula", "x-iinfo")),
    ("Sucuri", ("sucuri", "x-sucuri")),
    ("Azure Front Door", ("azurefd", "x-azure-ref")),
    ("Google Cloud CDN", ("google", "x-goog")),
    ("Bunny CDN", ("bunnycdn", "b-cdn")),
    ("KeyCDN", ("keycdn",)),
    ("StackPath", ("stackpath",)),
    ("Edgio", ("edgio", "limelight")),
    ("QUIC.cloud", ("quic.cloud",)),
    ("Vercel", ("vercel", "x-vercel")),
    ("Netlify", ("netlify", "x-nf-request-id")),
)

KNOWN_CDN_PROVIDER_NAMES = {
    provider.casefold() for provider, _patterns in CDN_PATTERNS
}

JARM_PATTERN = re.compile(r"(?<![0-9a-f])[0-9a-f]{62}(?![0-9a-f])", re.I)

SAFE_RESPONSE_HEADERS = {
    "cache-control", "content-encoding", "content-language", "content-type", "etag",
    "last-modified", "location", "server", "strict-transport-security", "vary", "via",
    "x-powered-by", "x-generator", "x-cache", "x-served-by", "cf-ray", "x-azure-ref",
    "x-amz-cf-id", "x-amz-cf-pop", "x-sucuri-id", "x-sucuri-cache",
}

ORIGIN_SCORE_WEIGHTS = {
    "historical_apex_dns": 30,
    "same_certificate": 25,
    "recent_historical_dns": 20,
    "independent_sources": 20,
    "html_similarity_95": 18,
    "valid_domain_certificate": 15,
    "multiple_scope_hostnames": 15,
    "html_similarity_85": 15,
    "urlscan_main_ip": 12,
    "same_favicon_sha256": 12,
    "same_static_resources": 10,
    "same_cookie_names": 10,
    "significant_hostname": 10,
    "certificate_search": 10,
    "same_favicon_mmh3": 8,
    "same_title": 8,
    "same_redirect_chain": 8,
    "same_framework": 8,
    "same_jarm": 7,
    "same_application_headers": 6,
    "public_repository": 5,
    "mail_relationship": 4,
    "known_cdn": -40,
    "other_domain_certificate": -30,
    "other_application": -30,
    "default_hosting_page": -25,
    "parked_domain": -25,
    "other_reverse_proxy": -20,
    "other_tenant": -20,
    "shared_hosting": -15,
    "old_history_only": -15,
    "no_web_response": -15,
    "residential_network": -12,
    "title_only": -10,
    "favicon_only": -10,
    "hostname_only": -10,
    "mail_only_penalty": -8,
}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _mmh3(value: bytes) -> int | None:
    try:
        import mmh3

        return int(mmh3.hash(value))
    except (ImportError, TypeError, ValueError):
        return None


def _safe_excerpt(value: bytes, limit: int = 180) -> str:
    text = value.decode("utf-8", errors="replace")
    text = re.sub(r"(?i)(token|secret|password|authorization)\s*[:=]\s*[^\s<]+", r"\1=[redacted]", text)
    text = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[email-redacted]", text, flags=re.I)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def normalize_html(value: bytes) -> str:
    text = value.decode("utf-8", errors="replace")
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.S)
    text = re.sub(
        r"(?i)(nonce|csrf(?:token)?|request[-_]?id|trace[-_]?id|session[-_]?id)\s*=\s*(['\"])[^'\"]+\2",
        r"\1=\2[dynamic]\2",
        text,
    )
    text = re.sub(r"\b20\d\d[-/:T]\d\d[-/:T]\d\d(?:[T ]\d\d:\d\d(?::\d\d)?)?Z?\b", "[timestamp]", text)
    text = re.sub(r"([?&](?:v|ver|version|cache|cb|_)=)[^&\"'<> ]+", r"\1[dynamic]", text, flags=re.I)
    text = re.sub(r"\s+", " ", text).strip().casefold()
    return text


def simhash(value: str) -> str:
    weights = [0] * 64
    for token in re.findall(r"[a-z0-9_./:-]{2,}", value):
        number = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if number & (1 << bit) else -1
    result = sum(1 << bit for bit, weight in enumerate(weights) if weight >= 0)
    return f"{result:016x}"


def _html_title(value: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", value)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:300] if match else ""


def _dom_structure_hash(html: str) -> str:
    tags = " ".join(
        match.group(1).casefold()
        for match in re.finditer(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9:-]*)\b", html)
    )
    return _sha256(tags.encode()) if tags else ""


def _meta_tag_names(html: str) -> list[str]:
    names: set[str] = set()
    for tag in re.findall(r"(?is)<meta\b[^>]*>", html):
        match = re.search(r"(?i)\b(?:name|property)\s*=\s*['\"]([^'\"]+)['\"]", tag)
        if match:
            names.add(match.group(1).strip().casefold()[:120])
    return sorted(names)


def _observed_paths(html: str, base_url: str) -> dict[str, list[str]]:
    output = {"favicon": [], "javascript": [], "css": []}
    for match in re.finditer(r"(?is)<(?:link|script)\b[^>]*(?:href|src)\s*=\s*['\"]([^'\"]+)['\"]", html):
        raw = match.group(1).strip()
        absolute = urllib.parse.urljoin(base_url, raw)
        parsed = urllib.parse.urlsplit(absolute)
        base = urllib.parse.urlsplit(base_url)
        if parsed.hostname != base.hostname or not parsed.path:
            continue
        path = parsed.path
        before = html[max(0, match.start() - 120):match.end() + 120].casefold()
        if "icon" in before:
            output["favicon"].append(path)
        elif path.casefold().endswith(".js") or "script" in before:
            output["javascript"].append(path)
        elif path.casefold().endswith(".css") or "stylesheet" in before:
            output["css"].append(path)
    for key in output:
        output[key] = list(dict.fromkeys(output[key]))
    return output


def _cookie_names(headers: Iterable[tuple[str, str]]) -> list[str]:
    names: set[str] = set()
    for key, value in headers:
        if key.casefold() != "set-cookie":
            continue
        try:
            parsed = SimpleCookie(value)
            names.update(parsed.keys())
        except Exception:
            raw = value.split("=", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", raw):
                names.add(raw)
    return sorted(names)


def _safe_headers(headers: Iterable[tuple[str, str]]) -> tuple[dict[str, str], list[str]]:
    rows = list(headers)
    result: dict[str, str] = {}
    for key, value in rows:
        clean = key.casefold()
        if clean in SAFE_RESPONSE_HEADERS:
            result[clean] = value[:1000]
    return result, _cookie_names(rows)


def _path_allowed(path: str) -> bool:
    parsed = urllib.parse.urlsplit(path)
    if parsed.query or parsed.fragment or not parsed.path.startswith("/"):
        return False
    parts = {part.casefold() for part in parsed.path.split("/") if part}
    return not bool(parts & SENSITIVE_PATH_PARTS)


def dns_inventory(domain: str, *, maximum_queries: int = 100) -> dict[str, Any]:
    """Collect bounded DNS evidence, including guarded SPF recursion."""
    records: dict[str, list[str]] = {}
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return {"records": records, "resolver": "socket-fallback"}
    resolver = dns.resolver.Resolver()
    queries = 0

    def query(name: str, record_type: str) -> list[str]:
        nonlocal queries
        key = f"{name.rstrip('.')}:{record_type}"
        if key in records or queries >= maximum_queries:
            return records.get(key, [])
        queries += 1
        try:
            answer = resolver.resolve(name, record_type, lifetime=5, raise_on_no_answer=False)
            values = [str(item).strip().strip('"') for item in answer] if answer.rrset else []
        except (dns.exception.DNSException, OSError):
            values = []
        records[key] = values
        return values

    for name in (domain, f"www.{domain}"):
        for record_type in ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV"):
            query(name, record_type)

    visited: set[str] = set()

    def walk_spf(name: str, depth: int) -> None:
        if depth > 5 or name in visited or queries >= maximum_queries:
            return
        visited.add(name)
        for text in query(name, "TXT"):
            if not text.casefold().startswith("v=spf1"):
                continue
            for token in text.split():
                clean = token.lstrip("+~-?")
                if clean.startswith("include:"):
                    child = clean.split(":", 1)[1].rstrip(".")
                    walk_spf(child, depth + 1)
                elif clean.startswith("redirect="):
                    walk_spf(clean.split("=", 1)[1].rstrip("."), depth + 1)
                elif clean == "a" or clean.startswith("a:"):
                    host = clean.split(":", 1)[1] if ":" in clean else name
                    query(host, "A")
                    query(host, "AAAA")
                elif clean == "mx" or clean.startswith("mx:"):
                    host = clean.split(":", 1)[1] if ":" in clean else name
                    query(host, "MX")

    walk_spf(domain, 0)
    return {"records": records, "resolver": "dnspython", "queries": queries, "spf_depth_limit": 5}


def resolve_cname(name: str) -> str:
    """Return the first CNAME without invoking a shell or following arbitrary data."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return ""
    try:
        answer = dns.resolver.resolve(name, "CNAME", lifetime=5, raise_on_no_answer=False)
    except (dns.exception.DNSException, OSError):
        return ""
    if not answer.rrset:
        return ""
    return str(next(iter(answer), "")).rstrip(".")[:253]


def dns_related_observations(inventory: dict[str, Any], root: str) -> list[CandidateObservation]:
    observations: list[CandidateObservation] = []
    records = inventory.get("records", {}) if isinstance(inventory, dict) else {}
    for key, values in records.items() if isinstance(records, dict) else []:
        name, _, record_type = key.rpartition(":")
        for raw in values if isinstance(values, list) else []:
            if record_type in {"A", "AAAA"}:
                try:
                    ip = str(ipaddress.ip_address(str(raw).split()[0]))
                except ValueError:
                    continue
                relationship = "current_dns" if domain_in_scope(name, [root]) else "mail_or_spf"
                observations.append(CandidateObservation(ip, "dns", "current_dns", name, relationship))
            elif record_type == "MX":
                host = str(raw).split()[-1].rstrip(".")
                for ip in resolve_host(host):
                    observations.append(CandidateObservation(ip, "dns-mx", "mail_dns", host, "mail_or_spf", metadata={"record_type": "MX"}))
            elif record_type == "TXT" and str(raw).casefold().startswith("v=spf1"):
                for token in str(raw).split():
                    clean = token.lstrip("+~-?")
                    if clean.startswith(("ip4:", "ip6:")):
                        try:
                            network = ipaddress.ip_network(clean.split(":", 1)[1], strict=False)
                        except ValueError:
                            continue
                        # Never expand an SPF range. A single host address is
                        # retained only as weak related-mail evidence.
                        if network.num_addresses == 1:
                            observations.append(CandidateObservation(str(network.network_address), "dns-spf", "mail_dns", name, "mail_or_spf", metadata={"record_type": "SPF"}))
    return observations


@dataclass(slots=True)
class HttpProbeResult:
    scheme: str
    candidate_ip: str
    hostname: str
    port: int
    path: str
    method: str
    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookie_names: list[str] = field(default_factory=list)
    body: bytes = b""
    body_truncated: bool = False
    error: str = ""
    elapsed_seconds: float = 0.0
    request_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self, *, include_body: bool = False) -> dict[str, Any]:
        output = {
            "scheme": self.scheme,
            "candidate_ip": self.candidate_ip,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "method": self.method,
            "status": self.status,
            "reason": self.reason,
            "headers": self.headers,
            "cookie_names": self.cookie_names,
            "body_sha256": _sha256(self.body) if self.body else "",
            "body_bytes": len(self.body),
            "body_truncated": self.body_truncated,
            "safe_excerpt": _safe_excerpt(self.body) if self.body else "",
            "error": self.error,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "request_headers": self.request_headers,
        }
        if include_body:
            output["body"] = self.body
        return output


@dataclass(slots=True)
class TLSProbeResult:
    candidate_ip: str
    hostname: str
    port: int
    handshake: str = "handshake_failed"
    certificate_trusted: bool = False
    certificate_name_match: bool = False
    certificate_sha256: str = ""
    spki_sha256: str = ""
    common_name: str = ""
    sans: list[str] = field(default_factory=list)
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    tls_version: str = ""
    cipher: str = ""
    error: str = ""
    server_hostname: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _socket_address(ip: str, port: int) -> tuple[Any, ...]:
    address = ipaddress.ip_address(ip)
    return (ip, port, 0, 0) if address.version == 6 else (ip, port)


def _certificate_details(der: bytes) -> dict[str, Any]:
    output: dict[str, Any] = {"certificate_sha256": _sha256(der) if der else ""}
    if not der:
        return output
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID

        certificate = x509.load_der_x509_certificate(der)
        common = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        output["common_name"] = common[0].value if common else ""
        try:
            output["sans"] = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            output["sans"] = []
        output["issuer"] = certificate.issuer.rfc4514_string()
        output["not_before"] = certificate.not_valid_before_utc.isoformat()
        output["not_after"] = certificate.not_valid_after_utc.isoformat()
        output["spki_sha256"] = _sha256(
            certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    except (ImportError, ValueError):
        pass
    return output


def _dns_name_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.casefold().rstrip(".")
    hostname = hostname.casefold().rstrip(".")
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")
    return False


def _tls_context(*, verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def probe_tls(ip: str, port: int, hostname: str, *, timeout: float) -> TLSProbeResult:
    """Perform a TLS handshake using the target hostname as SNI."""
    result = TLSProbeResult(candidate_ip=ip, hostname=hostname, port=port, server_hostname=hostname)
    verified = False
    try:
        raw = socket.create_connection(_socket_address(ip, port), timeout=timeout)
        with raw, _tls_context(verify=True).wrap_socket(raw, server_hostname=hostname) as wrapped:
            verified = True
            result.certificate_trusted = True
            result.certificate_name_match = True
            result.handshake = "certificate_trusted"
            result.tls_version = wrapped.version() or ""
            cipher = wrapped.cipher()
            result.cipher = cipher[0] if cipher else ""
            der = wrapped.getpeercert(binary_form=True) or b""
    except ssl.SSLCertVerificationError as exc:
        result.handshake = "certificate_untrusted"
        result.error = str(exc)[:500]
        der = b""
    except ssl.SSLError as exc:
        message = str(exc)
        result.handshake = (
            "client_certificate_required"
            if "certificate required" in message.casefold() or "unknown ca" in message.casefold()
            else "handshake_failed"
        )
        result.error = message[:500]
        return result
    except (TimeoutError, socket.timeout, OSError) as exc:
        result.error = str(exc)[:500]
        return result

    if not verified:
        try:
            raw = socket.create_connection(_socket_address(ip, port), timeout=timeout)
            with raw, _tls_context(verify=False).wrap_socket(raw, server_hostname=hostname) as wrapped:
                result.tls_version = wrapped.version() or ""
                cipher = wrapped.cipher()
                result.cipher = cipher[0] if cipher else ""
                der = wrapped.getpeercert(binary_form=True) or b""
        except ssl.SSLError as exc:
            message = str(exc)
            if "certificate required" in message.casefold() or "unknown ca" in message.casefold():
                result.handshake = "client_certificate_required"
            result.error = message[:500]
            return result
        except (TimeoutError, socket.timeout, OSError) as exc:
            result.error = str(exc)[:500]
            return result
    for key, value in _certificate_details(der).items():
        setattr(result, key, value)
    if result.handshake == "certificate_untrusted" and any(
        _dns_name_matches(name, hostname)
        for name in [result.common_name, *result.sans]
        if name
    ):
        result.certificate_name_match = True
    return result


def probe_jarm(
    ip: str,
    port: int,
    hostname: str,
    runner: CommandRunner,
    *,
    timeout: float,
    executable: str | None = None,
) -> str:
    """Collect one bounded TLSX JARM fingerprint with the exact target SNI.

    JARM is an optional deep-mode correlation signal.  TLSX performs the
    protocol's fixed handshake sequence against this single host and port;
    Cachaza disables retries and tool updates and never passes a CIDR.
    """
    binary = executable or find_tool("tlsx")
    if not binary:
        return ""
    seconds = max(1, min(30, int(round(timeout))))
    result = runner.run(
        [
            binary,
            "-u",
            f"{ip}:{port}",
            "-sni",
            hostname,
            "-jarm",
            "-json",
            "-silent",
            "-c",
            "1",
            "-retry",
            "0",
            "-timeout",
            str(seconds),
            "-duc",
        ],
        timeout=max(2, seconds),
    )
    if result.skipped or result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            for key in ("jarm_hash", "jarm", "jarm_fingerprint", "jarm-fingerprint"):
                value = str(payload.get(key) or "")
                match = JARM_PATTERN.fullmatch(value)
                if match:
                    return match.group(0).casefold()
        match = JARM_PATTERN.search(line)
        if match:
            return match.group(0).casefold()
    return ""


def direct_http_request(
    ip: str,
    hostname: str,
    port: int,
    *,
    scheme: str,
    method: str,
    path: str,
    connect_timeout: float,
    total_timeout: float,
    body_limit: int,
) -> HttpProbeResult:
    """Send one HTTP request to an IP while preserving Host and TLS SNI."""
    method = method.upper()
    if method not in {"HEAD", "GET"}:
        raise ValueError("Direct-origin validation permits only HEAD and GET")
    if scheme not in {"http", "https"}:
        raise ValueError("Direct-origin validation permits only HTTP and HTTPS")
    if not re.fullmatch(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", hostname):
        raise ValueError("invalid target hostname for Host/SNI")
    if not _path_allowed(path):
        raise ValueError(f"unsafe or unobserved origin path: {path!r}")
    host_header = hostname
    default_port = 443 if scheme == "https" else 80
    if port != default_port:
        host_header = f"{hostname}:{port}"
    request_headers = {
        "Host": host_header,
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.1",
        "Connection": "close",
    }
    if method == "GET" and body_limit > 0:
        request_headers["Range"] = f"bytes=0-{body_limit - 1}"
    if any(key.casefold() in FORBIDDEN_REQUEST_HEADERS for key in request_headers):
        raise RuntimeError("forbidden origin request header")
    result = HttpProbeResult(
        scheme=scheme,
        candidate_ip=ip,
        hostname=hostname,
        port=port,
        path=path,
        method=method,
        request_headers=request_headers,
    )
    started = time.monotonic()
    raw: socket.socket | ssl.SSLSocket | None = None
    try:
        raw = socket.create_connection(_socket_address(ip, port), timeout=connect_timeout)
        raw.settimeout(total_timeout)
        if scheme == "https":
            raw = _tls_context(verify=False).wrap_socket(raw, server_hostname=hostname)
        request_path = urllib.parse.quote(path, safe="/%:@!$&'()*+,;=-._~")
        lines = [f"{method} {request_path} HTTP/1.1"] + [f"{key}: {value}" for key, value in request_headers.items()]
        raw.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii", errors="strict"))
        response = http.client.HTTPResponse(raw)
        response.begin()
        result.status = response.status
        result.reason = response.reason or ""
        result.headers, result.cookie_names = _safe_headers(response.getheaders())
        if method == "GET":
            body = response.read(body_limit + 1)
            result.body_truncated = len(body) > body_limit
            result.body = body[:body_limit]
    except (TimeoutError, socket.timeout) as exc:
        result.error = f"timeout: {exc}"[:500]
    except (ssl.SSLError, OSError, http.client.HTTPException) as exc:
        result.error = str(exc)[:500]
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass
        result.elapsed_seconds = time.monotonic() - started
    return result


class OriginBudget:
    """Thread-safe central request budget with persisted consumption."""

    def __init__(
        self,
        config: OriginConfig,
        *,
        previous: dict[str, Any] | None = None,
        on_change: Callable[["OriginBudget"], None] | None = None,
    ):
        self.config = config
        previous = previous or {}
        self.consumed = min(int(previous.get("consumed", 0)), config.maximum_total_requests)
        self.per_ip = {
            str(key): min(int(value), config.maximum_requests_per_ip)
            for key, value in dict(previous.get("per_ip", {})).items()
        }
        self.history: list[dict[str, Any]] = list(previous.get("history", []))[-500:]
        self._last_action = 0.0
        self._lock = threading.Lock()
        self._on_change = on_change

    def can_consume(self, ip: str, amount: int = 1) -> bool:
        return (
            self.consumed + amount <= self.config.maximum_total_requests
            and self.per_ip.get(ip, 0) + amount <= self.config.maximum_requests_per_ip
        )

    def consume(self, *, action: str, candidate_ip: str, amount: int = 1) -> None:
        with self._lock:
            if not self.can_consume(candidate_ip, amount):
                raise RuntimeError("Origin validation request budget exhausted.")
            interval = 1.0 / self.config.rate_limit_per_second
            delay = interval - (time.monotonic() - self._last_action)
            if delay > 0:
                time.sleep(delay)
            self.consumed += amount
            self.per_ip[candidate_ip] = self.per_ip.get(candidate_ip, 0) + amount
            self._last_action = time.monotonic()
            self.history.append(
                {"action": action, "candidate_ip": candidate_ip, "amount": amount, "at": utc_now()}
            )
        if self._on_change is not None:
            # Persist before the network action begins.  An interrupted action
            # therefore remains conservatively charged on resume.
            self._on_change(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "maximum_candidates": self.config.maximum_candidates,
            "maximum_total_requests": self.config.maximum_total_requests,
            "maximum_requests_per_ip": self.config.maximum_requests_per_ip,
            "maximum_concurrency": self.config.maximum_concurrency,
            "rate_limit_per_second": self.config.rate_limit_per_second,
            "maximum_body_bytes": self.config.maximum_body_bytes,
            "maximum_paths": self.config.maximum_paths,
            "consumed": self.consumed,
            "remaining": max(0, self.config.maximum_total_requests - self.consumed),
            "per_ip": dict(sorted(self.per_ip.items())),
            "history": self.history,
            "exhausted": self.consumed >= self.config.maximum_total_requests,
        }


def _read_cidr_file(path: str | None) -> list[ipaddress._BaseNetwork]:
    if not path:
        return []
    source = Path(path).expanduser()
    if not source.is_file():
        raise ValueError(f"origin CIDR file does not exist: {source}")
    values: list[ipaddress._BaseNetwork] = []
    for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        clean = line.split("#", 1)[0].strip()
        if not clean:
            continue
        try:
            values.append(ipaddress.ip_network(clean, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid CIDR in {source}:{number}: {clean}") from exc
    return values


def _in_networks(address: ipaddress._BaseAddress, networks: Iterable[ipaddress._BaseNetwork]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def load_cloudflare_networks(*, timeout: int, retries: int) -> list[ipaddress._BaseNetwork]:
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "cachaza" / "provider-ranges"
    cache = base / "cloudflare.json"
    try:
        if cache.is_file():
            payload = json.loads(cache.read_text(encoding="utf-8"))
            lifetime = timedelta(days=1 if payload.get("fallback") else 7)
            if datetime.fromtimestamp(cache.stat().st_mtime, UTC) > datetime.now(UTC) - lifetime:
                return [ipaddress.ip_network(value) for value in payload.get("prefixes", [])]
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    prefixes: list[str] = []
    try:
        for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
            text = request_bytes(url, timeout=timeout, retries=retries).decode("ascii", errors="ignore")
            prefixes.extend(line.strip() for line in text.splitlines() if line.strip())
        networks = [ipaddress.ip_network(value) for value in prefixes]
        base.mkdir(parents=True, exist_ok=True)
        cache.write_text(
            json.dumps({"source": "official Cloudflare IP endpoints", "updated_at": utc_now(), "prefixes": prefixes}, indent=2) + "\n",
            encoding="utf-8",
        )
        return networks
    except (HttpError, OSError, ValueError):
        try:
            base.mkdir(parents=True, exist_ok=True)
            cache.write_text(
                json.dumps(
                    {
                        "source": "bundled Cloudflare fallback after refresh failure",
                        "updated_at": utc_now(),
                        "prefixes": list(CLOUDFLARE_FALLBACK),
                        "fallback": True,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass
        return [ipaddress.ip_network(value) for value in CLOUDFLARE_FALLBACK]


def detect_cdn(baseline: dict[str, Any], cloudflare: list[ipaddress._BaseNetwork]) -> dict[str, Any]:
    signals: dict[str, list[str]] = {}
    generic_signals: list[str] = []
    for endpoint in baseline.get("endpoints", []):
        cname = str(endpoint.get("cname") or "").casefold()
        header_values = " ".join(
            f"{key}:{value}" for key, value in endpoint.get("headers", {}).items()
        ).casefold()
        cookie_values = " ".join(endpoint.get("cookie_names", [])).casefold()
        for header in ("via", "x-cache", "x-served-by"):
            if endpoint.get("headers", {}).get(header):
                generic_signals.append(f"{header} response header")
        for provider, patterns in CDN_PATTERNS:
            for pattern in patterns:
                clean = pattern.casefold()
                if clean in cname:
                    signals.setdefault(provider, []).append(f"CNAME matched {pattern}")
                if clean in header_values:
                    signals.setdefault(provider, []).append(f"header matched {pattern}")
                if clean in cookie_values:
                    signals.setdefault(provider, []).append(f"cookie name matched {pattern}")
        for raw_ip in endpoint.get("addresses", []):
            try:
                address = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue
            if _in_networks(address, cloudflare):
                signals.setdefault("Cloudflare", []).append("IP belongs to official Cloudflare prefix")
    if not signals:
        if len(set(generic_signals)) >= 2:
            return {
                "provider": "Generic reverse proxy",
                "confidence": 60,
                "signals": sorted(set(generic_signals)),
            }
        return {"provider": "No CDN detected", "confidence": 40, "signals": []}
    eligible = {
        provider: values
        for provider, values in signals.items()
        if len(set(values)) >= 2
        or any("official" in value or value.startswith("CNAME") for value in values)
    }
    if not eligible:
        return {
            "provider": "Unknown",
            "confidence": 30,
            "signals": sorted({value for values in signals.values() for value in values}),
        }
    provider, provider_signals = max(eligible.items(), key=lambda item: len(set(item[1])))
    unique = sorted(set(provider_signals))
    # An isolated header is intentionally insufficient for high confidence.
    confidence = min(99, 45 + 20 * len(unique))
    return {"provider": provider, "confidence": confidence, "signals": unique}


class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    def __init__(self) -> None:
        super().__init__()
        self.chain: list[dict[str, Any]] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        self.chain.append({"status": code, "location": newurl})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _public_http(url: str, *, timeout: float, body_limit: int, maximum_redirects: int) -> dict[str, Any]:
    recorder = _RedirectRecorder()
    opener = urllib.request.build_opener(recorder)
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,*/*;q=0.2",
            "Range": f"bytes=0-{body_limit - 1}",
        },
        method="GET",
    )
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        body = response.read(body_limit + 1)
        rows = list(response.headers.items())
        headers, cookie_names = _safe_headers(rows)
        final_url = response.geturl()
        status = getattr(response, "status", getattr(response, "code", None))
    if len(recorder.chain) > maximum_redirects:
        recorder.chain = recorder.chain[:maximum_redirects]
    body = body[:body_limit]
    html = body.decode("utf-8", errors="replace")
    normalized = normalize_html(body)
    paths = _observed_paths(html, final_url)
    technologies = sorted(
        {
            value
            for value in (
                headers.get("server", ""),
                headers.get("x-powered-by", ""),
                headers.get("x-generator", ""),
            )
            if value
        }
    )
    return {
        "url": url,
        "final_url": final_url,
        "status": status,
        "redirect_chain": recorder.chain,
        "headers": headers,
        "cookie_names": cookie_names,
        "content_type": headers.get("content-type", ""),
        "length": len(body),
        "safe_excerpt": _safe_excerpt(body),
        "body_sha256": _sha256(body),
        "normalized_body_sha256": _sha256(normalized.encode()),
        "simhash": simhash(normalized),
        "dom_structure_sha256": _dom_structure_hash(html),
        "meta_tag_names": _meta_tag_names(html),
        "_normalized_body": normalized,
        "title": _html_title(html),
        "server": headers.get("server", ""),
        "technologies": technologies,
        "asn": "",
        "javascript": paths["javascript"],
        "css": paths["css"],
        "favicon_paths": paths["favicon"] or ["/favicon.ico"],
        "body_truncated": len(body) >= body_limit,
        "_body": body,
    }


def capture_public_baseline(
    domain: str,
    config: OriginConfig,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    names = [domain]
    www = f"www.{domain}"
    if resolve_host(www):
        names.append(www)
    endpoints: list[dict[str, Any]] = []
    for name in names:
        addresses = resolve_host(name)
        if not addresses:
            continue
        for scheme in ("http", "https"):
            url = f"{scheme}://{name}/"
            try:
                endpoint = _public_http(
                    url,
                    timeout=config.total_timeout,
                    body_limit=config.maximum_body_bytes,
                    maximum_redirects=config.maximum_redirects,
                )
            except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
                endpoints.append({"url": url, "addresses": addresses, "error": str(exc)[:500]})
                continue
            endpoint["addresses"] = addresses
            endpoint["hostname"] = name
            endpoint["cname"] = resolve_cname(name)
            if scheme == "https" and config.tls:
                endpoint["tls"] = probe_tls(addresses[0], 443, name, timeout=config.connect_timeout).to_dict()
                endpoint["jarm"] = ""
                tlsx = find_tool("tlsx") if config.jarm and runner is not None else None
                if tlsx:
                    endpoint["jarm"] = probe_jarm(
                        addresses[0],
                        443,
                        name,
                        runner,
                        timeout=config.total_timeout,
                        executable=tlsx,
                    )
            resources: dict[str, Any] = {}
            observed = endpoint["favicon_paths"][:1]
            if config.use_static_resources:
                observed += endpoint["javascript"][:1] + endpoint["css"][:1]
            for path in observed[: max(0, config.maximum_paths - 1)]:
                if not _path_allowed(path):
                    continue
                try:
                    item = _public_http(
                        urllib.parse.urljoin(endpoint["final_url"], path),
                        timeout=config.total_timeout,
                        body_limit=config.maximum_body_bytes,
                        maximum_redirects=config.maximum_redirects,
                    )
                except (urllib.error.URLError, TimeoutError, OSError):
                    continue
                raw = item.pop("_body", b"")
                resources[path] = {
                    "sha256": _sha256(raw),
                    "mmh3": _mmh3(raw),
                    "size": len(raw),
                    "content_type": item.get("content_type", ""),
                }
            endpoint["resources"] = resources
            favicon_path = next((path for path in endpoint["favicon_paths"] if path in resources), "")
            endpoint["favicon"] = (
                {"path": favicon_path, **resources[favicon_path]} if favicon_path else {}
            )
            endpoints.append(endpoint)
    for endpoint in endpoints:
        endpoint.pop("_body", None)
    return {"domain": domain, "captured_at": utc_now(), "endpoints": endpoints}


def score_candidate(candidate: OriginCandidate) -> int:
    by_code: dict[str, int] = {}
    for evidence in candidate.evidence:
        current = by_code.get(evidence.code)
        if current is None or abs(evidence.score) > abs(current):
            by_code[evidence.code] = evidence.score
    return max(0, min(100, sum(by_code.values())))


def _metadata_strings(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if str(item)]
    return [str(value)] if value else []


def should_auto_validate(candidate: OriginCandidate, config: OriginConfig) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if candidate.initial_score < config.minimum_score:
        reasons.append("score_below_threshold")
    if candidate.network.is_known_cdn:
        reasons.append("known_cdn_range")
    if candidate.network.is_private or not candidate.network.is_public:
        reasons.append("non_public_address")
    if candidate.classification != "origin_candidate":
        reasons.append("not_classified_as_origin_candidate")
    if candidate.independent_source_count < 2 and not candidate.has_strong_evidence:
        reasons.append("insufficient_independent_evidence")
    if candidate.is_clearly_third_party:
        reasons.append("third_party_infrastructure")
    if candidate.validation_attempts >= config.maximum_requests_per_ip:
        reasons.append("attempt_limit_reached")
    return not reasons, reasons


def _classification_for_score(score: int) -> str:
    if score >= 80:
        return "high_confidence_origin"
    if score >= 65:
        return "probable_origin"
    if score >= 50:
        return "possible_origin"
    return "related_infrastructure"


def _is_recent_observation(value: str | None) -> bool:
    if not value:
        return False
    try:
        observed = datetime.fromtimestamp(int(value), UTC)
    except (ValueError, TypeError, OSError):
        try:
            observed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=UTC)
        except ValueError:
            return False
    return observed >= datetime.now(UTC) - timedelta(days=730)


def _observation_evidence(observation: CandidateObservation, root: str) -> list[OriginEvidence]:
    output: list[OriginEvidence] = []
    hostname = observation.hostname.casefold()
    if observation.relationship == "mail_or_spf":
        output.append(OriginEvidence("mail_relationship", "Related through MX/SPF/mail infrastructure", 4, observation.source, observation.source_family, False, observation.metadata))
        output.append(OriginEvidence("mail_only_penalty", "Evidence is only from MX/SPF/mail", -8, observation.source, observation.source_family, False, observation.metadata))
    elif observation.relationship == "historical_dns" and hostname == root:
        output.append(OriginEvidence("historical_apex_dns", "Historical apex A/AAAA record", 30, observation.source, observation.source_family, True, observation.metadata))
        if _is_recent_observation(observation.last_seen):
            output.append(OriginEvidence("recent_historical_dns", "Recent historical resolution", 20, observation.source, observation.source_family, False, {"last_seen": observation.last_seen}))
        elif observation.last_seen:
            output.append(OriginEvidence("old_history_only", "Only an old historical resolution was observed", -15, observation.source, observation.source_family, False, {"last_seen": observation.last_seen}))
    elif observation.relationship == "urlscan_main_document":
        output.append(OriginEvidence("urlscan_main_ip", "Main-document IP observed by urlscan", 12, observation.source, observation.source_family, True, observation.metadata))
    elif observation.relationship == "current_dns" and hostname == root:
        output.append(OriginEvidence("exact_apex_dns", "Exact current apex A/AAAA record", 30, observation.source, observation.source_family, True, observation.metadata))
    elif hostname:
        label = hostname.removesuffix("." + root).split(".")[-1]
        if label in SIGNIFICANT_LABELS:
            output.append(OriginEvidence("significant_hostname", f"Significant in-scope hostname {hostname}", 10, observation.source, observation.source_family, False, observation.metadata))
        else:
            output.append(OriginEvidence("scope_hostname", f"In-scope hostname {hostname}", 5, observation.source, observation.source_family, False, observation.metadata))
    else:
        output.append(OriginEvidence("provider_correlation", "Provider result correlated with target", 5, observation.source, observation.source_family, False, observation.metadata))
    if observation.metadata.get("certificate_fingerprints"):
        output.append(OriginEvidence("certificate_search", "Candidate found through certificate correlation", 10, observation.source, observation.source_family, True, {"fingerprints": observation.metadata["certificate_fingerprints"]}))
    return output


class OriginEngine:
    def __init__(
        self,
        target: TargetSpec,
        workspace: RunWorkspace,
        config: OriginConfig,
        console: Console,
        runner: CommandRunner,
        credentials: dict[str, str],
        *,
        timeout: int,
        retries: int,
        add_finding: Callable[[str, str, str, str, bool, dict[str, Any]], bool],
        dry_run: bool = False,
    ) -> None:
        self.target = target
        self.workspace = workspace
        self.config = config
        self.console = console
        self.runner = runner
        self.credentials = credentials
        self.timeout = timeout
        self.retries = retries
        self.add_finding = add_finding
        self.dry_run = dry_run
        self.directory = workspace.artifact_path("origin")
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / "raw").mkdir(exist_ok=True)
        if config.save_bodies:
            (self.directory / "bodies").mkdir(exist_ok=True)
        self.cloudflare: list[ipaddress._BaseNetwork] = []
        self.include_networks = _read_cidr_file(config.include_cidr_file)
        self.exclude_networks = _read_cidr_file(config.exclude_cidr_file)

    def _log(self, message: str) -> None:
        self.console.info(f"[ORIGIN] {message}")

    def _write_jsonl(self, name: str, values: Iterable[dict[str, Any]]) -> Path:
        path = self.directory / name
        path.write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in values), encoding="utf-8")
        return path

    def _dry_run(self, root: str) -> str:
        direct = self.config.direct_validation and self.config.mode != "passive"
        lines = [
            "Automatic origin discovery plan", "", f"Target: {root}",
            f"Authorization acknowledged: {'yes' if self.config.authorized else 'no'}",
            f"Mode: {self.config.mode}", "", "Passive sources:",
            "- Current DNS", "- Certificate Transparency", "- Configured historical DNS",
            "- Censys, Shodan, urlscan and Uncover evidence already collected by Cachaza", "",
            "Active actions:" if direct else "Direct-origin validation: disabled",
        ]
        if direct:
            lines.extend([
                "- DNS resolution and limited permutations" if self.config.dns_permutations else "- Controlled DNS resolution",
                f"- Automatic validation of up to {self.config.maximum_candidates} candidates",
                f"- TCP connect ports {','.join(map(str, self.config.validation_ports))}",
                f"- TLS handshake with SNI {root}", "- HTTP HEAD /", "- Limited HTTP GET when required",
                "- Favicon comparison" if self.config.use_favicon else "- Favicon comparison disabled",
                "- One bounded JARM correlation per eligible TLS candidate (TLSX)" if self.config.jarm else "- JARM correlation disabled",
                f"- Maximum {self.config.maximum_total_requests} requests",
                f"- Rate limit {self.config.rate_limit_per_second:g} request/second",
                f"- Concurrency {self.config.maximum_concurrency}",
            ])
        lines.extend(["", "No manual IP input is required.", "Only automatically correlated candidates will be contacted."])
        plan = "\n".join(lines) + "\n"
        (self.directory / "plan.txt").write_text(plan, encoding="utf-8")
        self.workspace.write_json("origin/public-baseline.json", {"status": "planned", "target": root})
        for name in ("all-candidates.jsonl", "selected-candidates.jsonl", "rejected-candidates.jsonl", "validation-results.jsonl", "network-classification.jsonl", "evidence.jsonl"):
            (self.directory / name).write_text("", encoding="utf-8")
        budget = OriginBudget(self.config)
        self.workspace.write_json("origin/request-budget.json", budget.to_dict())
        ranking = self._ranking(root, [], [], budget, {"provider": "Unknown", "confidence": 0, "signals": []}, status="planned")
        self.workspace.write_json("origin/final-ranking.json", ranking)
        self._write_ranking_csv(ranking)
        if not self.console.silent:
            print(plan, end="")
        return "automatic Origin discovery dry-run plan written; no candidate IP input required"

    def _historical_observations(self, root: str) -> list[CandidateObservation]:
        if not self.config.historical_dns:
            return []
        output: list[CandidateObservation] = []
        engines = {item.casefold() for item in self.config.query_engines}
        providers: list[tuple[str, str, Callable[..., tuple[list[CandidateObservation], dict[str, Any]]]]] = []
        vt_key = (
            self.credentials.get("VIRUSTOTAL_API_KEY", "")
            or self.credentials.get("VT_API_KEY", "")
        ).strip()
        if "virustotal" in engines and vt_key:
            providers.append(("virustotal", vt_key, virustotal_resolutions))
        securitytrails_key = self.credentials.get("SECURITYTRAILS_API_KEY", "").strip()
        if "securitytrails" in engines and securitytrails_key:
            providers.append(("securitytrails", securitytrails_key, securitytrails_resolutions))
        for provider, key, fetcher in providers:
            cache = self.directory / "raw" / f"{provider}-{root}.json"
            if self.workspace.resume and cache.is_file():
                try:
                    payload = json.loads(cache.read_text(encoding="utf-8"))
                    if provider == "virustotal":
                        rows = payload.get("data", []) if isinstance(payload, dict) else []
                        for row in rows[: self.config.maximum_history_results] if isinstance(rows, list) else []:
                            attributes = row.get("attributes", {}) if isinstance(row, dict) else {}
                            raw_ip = str(attributes.get("ip_address") or row.get("id") or "")
                            try:
                                ip = str(ipaddress.ip_address(raw_ip))
                            except ValueError:
                                continue
                            output.append(CandidateObservation(ip, "virustotal", "virustotal", root, "historical_dns", True, last_seen=str(attributes.get("date") or "") or None, metadata={"historical": True}))
                        continue
                    if provider == "securitytrails" and isinstance(payload, dict):
                        for record_type, family_payload in payload.items():
                            rows = family_payload.get("records", []) if isinstance(family_payload, dict) else []
                            for row in rows if isinstance(rows, list) else []:
                                values = row.get("values", []) if isinstance(row, dict) else []
                                for value in values if isinstance(values, list) else []:
                                    raw_ip = value.get("ip") if isinstance(value, dict) else value
                                    try:
                                        ip = str(ipaddress.ip_address(str(raw_ip)))
                                    except ValueError:
                                        continue
                                    output.append(CandidateObservation(ip, "securitytrails", "securitytrails", root, "historical_dns", True, last_seen=str(row.get("last_seen") or "") or None, metadata={"historical": True, "record_type": str(record_type).upper()}))
                        continue
                except (OSError, json.JSONDecodeError):
                    pass
            try:
                observations, payload = fetcher(
                    root,
                    api_key=key,
                    maximum=self.config.maximum_history_results,
                    timeout=self.timeout,
                    retries=self.retries,
                )
                cache.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                output.extend(observations)
            except (HttpError, OSError, ValueError) as exc:
                self.console.warn(f"[ORIGIN] {provider} historical DNS unavailable: {exc}")
        return output[: self.config.maximum_history_results]

    def _classify_network(self, ip: str, baseline_ips: set[str], edge_provider: str = "Detected public edge") -> OriginNetwork:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return OriginNetwork(is_public=False, is_private=True, signals=["invalid_address"])
        private = not address.is_global
        network = OriginNetwork(is_public=address.is_global, is_private=private)
        if _in_networks(address, self.cloudflare):
            network.provider = "Cloudflare"
            network.is_known_cdn = True
            network.signals.append("official_cloudflare_prefix")
        elif ip in baseline_ips:
            network.provider = edge_provider
            network.is_known_cdn = True
            network.signals.append("current_public_endpoint_ip")
        if ip in KNOWN_PUBLIC_DNS:
            network.is_clearly_third_party = True
            network.provider = "Public DNS resolver"
            network.signals.append("known_public_dns")
        excluded = {item.casefold() for item in self.config.exclude_providers}
        if network.provider.casefold() in excluded:
            network.is_clearly_third_party = True
            network.signals.append("excluded_provider")
        if _in_networks(address, self.exclude_networks):
            network.is_clearly_third_party = True
            network.signals.append("excluded_cidr")
        if self.include_networks and not _in_networks(address, self.include_networks):
            network.is_clearly_third_party = True
            network.signals.append("outside_include_cidr")
        return network

    def _build_candidates(
        self,
        root: str,
        observations: list[CandidateObservation],
        baseline_ips: set[str],
        edge_provider: str = "Detected public edge",
    ) -> list[OriginCandidate]:
        by_ip: dict[str, OriginCandidate] = {}
        for observation in observations:
            candidate = by_ip.setdefault(observation.ip, OriginCandidate(ip=observation.ip))
            if observation.hostname:
                candidate.hostnames.append(observation.hostname)
            candidate.last_observed = observation.last_seen or candidate.last_observed
            for evidence in _observation_evidence(observation, root):
                candidate.add_evidence(evidence)
        for candidate in by_ip.values():
            candidate.network = self._classify_network(candidate.ip, baseline_ips, edge_provider)
            cloud_providers = sorted(
                {
                    str(provider)
                    for evidence in candidate.evidence
                    for provider in evidence.metadata.get("cloud_providers", [])
                }
            )
            asns = sorted(
                {
                    str(asn)
                    for evidence in candidate.evidence
                    for asn in _metadata_strings(
                        evidence.metadata.get("asns") or evidence.metadata.get("asn")
                    )
                    if str(asn)
                }
            )
            organizations = sorted(
                {
                    str(organization)
                    for evidence in candidate.evidence
                    for organization in _metadata_strings(
                        evidence.metadata.get("organizations")
                        or evidence.metadata.get("organization")
                        or evidence.metadata.get("as_name")
                    )
                    if str(organization)
                }
            )
            if asns:
                candidate.network.asn = ", ".join(asns)
            if organizations:
                candidate.network.organization = ", ".join(organizations)
            if cloud_providers and candidate.network.provider == "Unknown":
                candidate.network.provider = ", ".join(cloud_providers)
                candidate.network.is_cloud = True
                candidate.network.signals.append("cloud_range_classification")
            if any(
                provider.casefold() in KNOWN_CDN_PROVIDER_NAMES
                for provider in cloud_providers
            ):
                candidate.network.is_known_cdn = True
                candidate.network.signals.append("known_cdn_provider_classification")
            excluded = {provider.casefold() for provider in self.config.exclude_providers}
            if candidate.network.provider.casefold() in excluded:
                candidate.network.is_clearly_third_party = True
                candidate.network.signals.append("excluded_provider")
            if any(evidence.metadata.get("shared_hosting") for evidence in candidate.evidence):
                candidate.network.is_shared_hosting = True
                candidate.network.signals.append("shared_hosting")
                candidate.add_evidence(OriginEvidence("shared_hosting", "Massively shared hosting", -15, "network-classifier", "network_classification"))
            families = candidate.independent_source_families
            if len(families) >= 2:
                candidate.add_evidence(OriginEvidence("independent_sources", "Seen by two or more independent providers", 20, "correlation-engine", "correlation", True, {"families": families}))
            web_names = sorted({name for name in candidate.hostnames if domain_in_scope(name, self.target.domains) and not any(label in name.casefold() for label in ("mail", "smtp", "imap", "pop", "webmail"))})
            if len(web_names) >= 2:
                candidate.add_evidence(OriginEvidence("multiple_scope_hostnames", "IP used by multiple in-scope web hostnames", 15, "dns-correlation", "current_dns", True, {"hostnames": web_names}))
            if candidate.network.is_known_cdn:
                candidate.add_evidence(OriginEvidence("known_cdn", "IP belongs to a known CDN or current edge", -40, "network-classifier", "network_classification"))
                candidate.classification = "cdn_edge"
                candidate.rejection_reasons.append("known_cdn_range")
            elif not candidate.network.is_public:
                candidate.classification = "rejected"
                candidate.rejection_reasons.append("non_public_address")
            elif candidate.network.is_clearly_third_party:
                candidate.classification = "third_party_service"
                candidate.rejection_reasons.extend(candidate.network.signals)
            candidate.initial_score = score_candidate(candidate)
            candidate.final_score = candidate.initial_score
            if candidate.classification not in {"cdn_edge", "rejected", "third_party_service"}:
                evidence_codes = {item.code for item in candidate.evidence}
                if evidence_codes and evidence_codes <= {"mail_relationship", "mail_only_penalty", "independent_sources"}:
                    candidate.classification = "mail_infrastructure"
                    candidate.rejection_reasons.append("mail_only_evidence")
                elif candidate.initial_score >= self.config.minimum_score:
                    candidate.classification = "origin_candidate"
                elif candidate.network.is_shared_hosting:
                    candidate.classification = "shared_hosting"
                    candidate.rejection_reasons.append("shared_hosting")
                elif candidate.network.is_cloud:
                    candidate.classification = "cloud_platform"
                    candidate.rejection_reasons.append("weak_generic_cloud_evidence")
                elif evidence_codes and evidence_codes <= {
                    "historical_apex_dns", "recent_historical_dns", "independent_sources"
                }:
                    candidate.classification = "historical_only"
                    candidate.rejection_reasons.append("historical_only")
                elif candidate.initial_score >= 30:
                    candidate.classification = "related_infrastructure"
                    candidate.rejection_reasons.append("score_below_threshold")
                else:
                    candidate.classification = "rejected"
                    candidate.rejection_reasons.append("score_below_threshold")
        return sorted(
            by_ip.values(),
            key=lambda item: (-item.initial_score, -item.independent_source_count, item.ip),
        )

    def _paths(self, baseline: dict[str, Any]) -> list[str]:
        paths = ["/"] + [path for path in self.config.paths if _path_allowed(path)]
        endpoint = next((item for item in baseline.get("endpoints", []) if not item.get("error") and item.get("hostname") == baseline.get("domain")), None)
        if endpoint:
            if self.config.use_favicon:
                paths += endpoint.get("favicon_paths", [])[:1]
            if self.config.use_static_resources:
                count = 2 if self.config.mode == "deep" else 1
                paths += endpoint.get("javascript", [])[:count] + endpoint.get("css", [])[:count]
            if self.config.use_observed_paths:
                paths += list(endpoint.get("resources", {}).keys())
        return list(dict.fromkeys(path for path in paths if _path_allowed(path)))[: self.config.maximum_paths]

    def _baseline_endpoint(self, baseline: dict[str, Any]) -> dict[str, Any]:
        preferred = [item for item in baseline.get("endpoints", []) if item.get("hostname") == baseline.get("domain") and item.get("url", "").startswith("https://") and not item.get("error")]
        if preferred:
            return preferred[0]
        return next((item for item in baseline.get("endpoints", []) if not item.get("error")), {})

    def _compare_root(self, candidate: OriginCandidate, response: HttpProbeResult, baseline: dict[str, Any]) -> dict[str, Any]:
        reference = self._baseline_endpoint(baseline)
        if not reference or not response.body:
            return {}
        normalized = normalize_html(response.body)
        reference_hash = str(reference.get("normalized_body_sha256") or "")
        candidate_hash = _sha256(normalized.encode())
        reference_text = ""
        # The normalized reference body is intentionally not persisted. An exact
        # hash remains strong; textual similarity is available during capture only
        # when tests/embedders supply the normalized text.
        if reference.get("_normalized_body"):
            reference_text = str(reference["_normalized_body"])
        similarity = 100.0 if reference_hash and reference_hash == candidate_hash else (
            SequenceMatcher(None, reference_text, normalized).ratio() * 100 if reference_text else 0.0
        )
        candidate_title = _html_title(response.body.decode("utf-8", errors="replace"))
        candidate_html = response.body.decode("utf-8", errors="replace")
        candidate_dom = _dom_structure_hash(candidate_html)
        candidate_meta = _meta_tag_names(candidate_html)
        if similarity >= 95:
            candidate.add_evidence(OriginEvidence("html_similarity_95", f"Normalized HTML similarity {similarity:.1f}%", 18, "direct-origin-validation", "direct_validation"))
        elif similarity >= 85:
            candidate.add_evidence(OriginEvidence("html_similarity_85", f"Normalized HTML similarity {similarity:.1f}%", 15, "direct-origin-validation", "direct_validation"))
        elif reference_text and similarity < 50:
            candidate.add_evidence(OriginEvidence("other_application", "Content corresponds to a different application", -30, "direct-origin-validation", "direct_validation"))
        if any(marker in normalized for marker in ("apache2 ubuntu default page", "welcome to nginx", "default web site page")):
            candidate.add_evidence(OriginEvidence("default_hosting_page", "Default hosting page", -25, "direct-origin-validation", "direct_validation"))
        if any(marker in normalized for marker in ("domain is parked", "parked domain", "buy this domain")):
            candidate.add_evidence(OriginEvidence("parked_domain", "Parked domain response", -25, "direct-origin-validation", "direct_validation"))
        if candidate_title and candidate_title.casefold() == str(reference.get("title") or "").casefold():
            candidate.add_evidence(OriginEvidence("same_title", "Same normalized page title", 8, "direct-origin-validation", "direct_validation"))
        reference_cookies = set(reference.get("cookie_names", []))
        if reference_cookies and reference_cookies == set(response.cookie_names):
            candidate.add_evidence(OriginEvidence("same_cookie_names", "Same application cookie names", 10, "direct-origin-validation", "direct_validation"))
        common_headers = {
            key for key in ("content-type", "server", "x-powered-by", "x-generator")
            if response.headers.get(key) and response.headers.get(key) == reference.get("headers", {}).get(key)
        }
        if common_headers:
            candidate.add_evidence(OriginEvidence("same_application_headers", "Same stable application headers", 6, "direct-origin-validation", "direct_validation", metadata={"headers": sorted(common_headers)}))
        candidate_technologies = {
            response.headers.get(key, "")
            for key in ("server", "x-powered-by", "x-generator")
            if response.headers.get(key)
        }
        technology_matches = candidate_technologies & set(reference.get("technologies", []))
        if technology_matches:
            candidate.add_evidence(OriginEvidence("same_framework", "Same framework or apparent application technology", 8, "direct-origin-validation", "direct_validation", metadata={"technologies": sorted(technology_matches)}))
        return {
            "normalized_similarity": round(similarity, 2),
            "normalized_hash_match": bool(reference_hash and reference_hash == candidate_hash),
            "title_match": bool(candidate_title and candidate_title.casefold() == str(reference.get("title") or "").casefold()),
            "cookie_names_match": bool(reference_cookies and reference_cookies == set(response.cookie_names)),
            "stable_headers_match": sorted(common_headers),
            "technology_matches": sorted(technology_matches),
            "dom_structure_match": bool(candidate_dom and candidate_dom == reference.get("dom_structure_sha256")),
            "meta_tag_names_match": bool(candidate_meta and candidate_meta == reference.get("meta_tag_names", [])),
        }

    def _compare_tls(self, candidate: OriginCandidate, tls: TLSProbeResult, baseline: dict[str, Any], root: str) -> None:
        public_tls = self._baseline_endpoint(baseline).get("tls", {})
        if (
            tls.certificate_sha256
            and tls.certificate_sha256 == public_tls.get("certificate_sha256")
        ) or (
            tls.spki_sha256 and tls.spki_sha256 == public_tls.get("spki_sha256")
        ):
            candidate.add_evidence(OriginEvidence("same_certificate", "Same certificate SHA-256 or SPKI as public reference", 25, "direct-origin-validation", "direct_validation", True))
        elif tls.certificate_name_match or any(
            _dns_name_matches(name, root)
            for name in [tls.common_name, *tls.sans]
            if name
        ):
            candidate.add_evidence(OriginEvidence("valid_domain_certificate", "Certificate is valid for the target domain", 15, "direct-origin-validation", "direct_validation", True))
        elif tls.common_name and root not in tls.common_name and not any(name == root or name.endswith("." + root) for name in tls.sans):
            candidate.add_evidence(OriginEvidence("other_domain_certificate", "Certificate belongs clearly to another domain", -30, "direct-origin-validation", "direct_validation"))

    def _validate_candidate(self, candidate: OriginCandidate, root: str, baseline: dict[str, Any], budget: OriginBudget) -> dict[str, Any]:
        started_score = candidate.initial_score
        result: dict[str, Any] = {"ip": candidate.ip, "validated_at": utc_now(), "tcp": {}, "tls": {}, "jarm": "", "http": [], "comparisons": {}, "validation_requests": 0}
        open_ports: list[int] = []
        validation_ports = list(dict.fromkeys(self.config.validation_ports))
        if self.config.mode == "deep":
            standard_ports = [port for port in validation_ports if port in {80, 443}]
            additional_ports = [port for port in validation_ports if port not in {80, 443}]
            port_phases = [standard_ports, additional_ports]
        else:
            port_phases = [validation_ports]
        for phase_index, ports in enumerate(port_phases):
            # Deep ports are a fallback escalation, not an unconditional scan.
            if phase_index and open_ports:
                break
            for port in ports:
                if not budget.can_consume(candidate.ip):
                    break
                budget.consume(action="tcp_connect", candidate_ip=candidate.ip)
                candidate.validation_attempts += 1
                result["validation_requests"] += 1
                try:
                    with socket.create_connection(_socket_address(candidate.ip, port), timeout=self.config.connect_timeout):
                        result["tcp"][str(port)] = "open"
                        open_ports.append(port)
                except (TimeoutError, socket.timeout):
                    result["tcp"][str(port)] = "timeout"
                except OSError as exc:
                    result["tcp"][str(port)] = "refused" if getattr(exc, "errno", None) in {61, 10061, 111} else "unreachable"
        preferred = next((port for port in (443, 8443, 80, 8080, 8000, 8888) if port in open_ports), None)
        if preferred is not None and preferred in {443, 8443} and self.config.tls and budget.can_consume(candidate.ip):
            budget.consume(action="tls_handshake", candidate_ip=candidate.ip)
            candidate.validation_attempts += 1
            result["validation_requests"] += 1
            tls = probe_tls(candidate.ip, preferred, root, timeout=self.config.connect_timeout)
            result["tls"] = tls.to_dict()
            self._compare_tls(candidate, tls, baseline, root)
            candidate.final_score = score_candidate(candidate)
        if preferred is not None:
            scheme = "https" if preferred in {443, 8443} else "http"
            if budget.can_consume(candidate.ip):
                budget.consume(action=f"{scheme}_head", candidate_ip=candidate.ip)
                candidate.validation_attempts += 1
                result["validation_requests"] += 1
                head = direct_http_request(candidate.ip, root, preferred, scheme=scheme, method="HEAD", path="/", connect_timeout=self.config.connect_timeout, total_timeout=self.config.total_timeout, body_limit=0)
                result["http"].append(head.to_dict())
            if budget.can_consume(candidate.ip):
                budget.consume(action=f"{scheme}_get", candidate_ip=candidate.ip)
                candidate.validation_attempts += 1
                result["validation_requests"] += 1
                response = direct_http_request(candidate.ip, root, preferred, scheme=scheme, method="GET", path="/", connect_timeout=self.config.connect_timeout, total_timeout=self.config.total_timeout, body_limit=self.config.maximum_body_bytes)
                result["http"].append(response.to_dict())
                redirect_chain: list[dict[str, Any]] = []
                for _ in range(self.config.maximum_redirects):
                    if response.status not in {301, 302, 303, 307, 308}:
                        break
                    location = response.headers.get("location", "")
                    parsed = urllib.parse.urlsplit(
                        urllib.parse.urljoin(f"{scheme}://{root}/", location)
                    )
                    if parsed.hostname != root or parsed.scheme != scheme or not _path_allowed(parsed.path or "/"):
                        break
                    if not budget.can_consume(candidate.ip):
                        break
                    redirect_chain.append({"status": response.status, "location": location})
                    budget.consume(action=f"{scheme}_get_redirect", candidate_ip=candidate.ip)
                    candidate.validation_attempts += 1
                    result["validation_requests"] += 1
                    response = direct_http_request(
                        candidate.ip,
                        root,
                        preferred,
                        scheme=scheme,
                        method="GET",
                        path=parsed.path or "/",
                        connect_timeout=self.config.connect_timeout,
                        total_timeout=self.config.total_timeout,
                        body_limit=self.config.maximum_body_bytes,
                    )
                    result["http"].append(response.to_dict())
                result["redirect_chain"] = redirect_chain
                result["comparisons"]["/"] = self._compare_root(candidate, response, baseline)
                candidate.final_score = score_candidate(candidate)
                public_redirects = self._baseline_endpoint(baseline).get("redirect_chain", [])
                if redirect_chain and [item.get("location") for item in redirect_chain] == [item.get("location") for item in public_redirects[: len(redirect_chain)]]:
                    candidate.add_evidence(OriginEvidence("same_redirect_chain", "Same relevant redirect chain", 8, "direct-origin-validation", "direct_validation"))
                    candidate.final_score = score_candidate(candidate)
                if self.config.save_bodies and response.body:
                    safe_name = candidate.ip.replace(":", "_") + "-root.bin"
                    (self.directory / "bodies" / safe_name).write_bytes(response.body)
            tlsx = find_tool("tlsx") if self.config.jarm else None
            if (
                tlsx
                and budget.can_consume(candidate.ip)
                and (candidate.final_score < self.config.stop_score or self.config.continue_after_match)
                and preferred in {443, 8443}
            ):
                budget.consume(action="jarm", candidate_ip=candidate.ip)
                candidate.validation_attempts += 1
                result["validation_requests"] += 1
                result["jarm"] = probe_jarm(
                    candidate.ip,
                    preferred,
                    root,
                    self.runner,
                    timeout=self.config.total_timeout,
                    executable=tlsx,
                )
                public_jarm = str(self._baseline_endpoint(baseline).get("jarm") or "")
                result["comparisons"]["jarm"] = {
                    "candidate": result["jarm"],
                    "public": public_jarm,
                    "match": bool(result["jarm"] and result["jarm"] == public_jarm),
                }
                if result["jarm"] and result["jarm"] == public_jarm:
                    candidate.add_evidence(OriginEvidence("same_jarm", "Same JARM fingerprint", 7, "direct-origin-validation", "direct_validation"))
                    candidate.final_score = score_candidate(candidate)
            reference = self._baseline_endpoint(baseline)
            for path in self._paths(baseline)[1:]:
                if not budget.can_consume(candidate.ip) or candidate.final_score >= self.config.stop_score:
                    break
                budget.consume(action=f"{scheme}_get", candidate_ip=candidate.ip)
                candidate.validation_attempts += 1
                result["validation_requests"] += 1
                response = direct_http_request(candidate.ip, root, preferred, scheme=scheme, method="GET", path=path, connect_timeout=self.config.connect_timeout, total_timeout=self.config.total_timeout, body_limit=self.config.maximum_body_bytes)
                result["http"].append(response.to_dict())
                expected = reference.get("resources", {}).get(path, {})
                if response.body and expected.get("sha256") == _sha256(response.body):
                    code = "same_favicon_sha256" if path in reference.get("favicon_paths", []) else "same_static_resources"
                    points = 12 if code == "same_favicon_sha256" else 10
                    description = "Same favicon SHA-256" if points == 12 else "Same observed static resource"
                    candidate.add_evidence(OriginEvidence(code, description, points, "direct-origin-validation", "direct_validation", metadata={"path": path}))
                    result["comparisons"][path] = {"hash_match": True, "size": len(response.body)}
                    candidate.final_score = score_candidate(candidate)
                elif (
                    response.body
                    and path in reference.get("favicon_paths", [])
                    and expected.get("mmh3") is not None
                    and expected.get("mmh3") == _mmh3(response.body)
                ):
                    candidate.add_evidence(OriginEvidence("same_favicon_mmh3", "Same favicon MMH3", 8, "direct-origin-validation", "direct_validation", metadata={"path": path}))
                    result["comparisons"][path] = {"mmh3_match": True, "size": len(response.body)}
                    candidate.final_score = score_candidate(candidate)
        candidate.final_score = score_candidate(candidate)
        tls_state = str(result.get("tls", {}).get("handshake") or "")
        statuses = [item.get("status") for item in result["http"]]
        errors = [item.get("error") for item in result["http"] if item.get("error")]
        root_comparison = result["comparisons"].get("/", {})
        root_similarity = root_comparison.get("normalized_similarity", 0)
        if tls_state == "client_certificate_required" or (403 in statuses and candidate.has_strong_evidence):
            candidate.validation_status = "protected_origin"
            result["direct_validation"] = "not_directly_verifiable"
        elif preferred is None:
            candidate.validation_status = "inconclusive" if candidate.has_strong_evidence else "not_directly_reachable"
            result["direct_validation"] = "not_directly_verifiable" if candidate.has_strong_evidence else "not_reachable"
        elif errors and not any(statuses):
            candidate.validation_status = "inconclusive"
        elif "normalized_similarity" in root_comparison and root_similarity < 50 and candidate.final_score < 65:
            candidate.validation_status = "not_matching"
        else:
            candidate.validation_status = _classification_for_score(candidate.final_score)
        candidate.classification = candidate.validation_status
        candidate.validation = result
        result.update({"initial_score": started_score, "final_score": candidate.final_score, "classification": candidate.validation_status, "evidence": [item.to_dict() for item in candidate.evidence]})
        return result

    def _ranking(self, root: str, candidates: list[OriginCandidate], selected: list[OriginCandidate], budget: OriginBudget, cdn: dict[str, Any], *, status: str = "completed") -> dict[str, Any]:
        ranked = sorted(candidates, key=lambda item: (-item.final_score, -item.independent_source_count, item.ip))
        probable = [item for item in ranked if item.validation_status in {"high_confidence_origin", "probable_origin", "possible_origin", "protected_origin"} or (self.config.mode == "passive" and item.initial_score >= self.config.minimum_score and item.classification == "origin_candidate")]
        primary = probable[:1]
        additional = probable[1:]
        historical = [item for item in ranked if item.classification == "historical_only"]
        rejected = [item for item in ranked if item.classification in {"rejected", "cdn_edge", "third_party_service", "related_infrastructure", "not_matching"}]
        highest = primary[0] if primary else (ranked[0] if ranked else None)
        message = ""
        if not primary:
            message = "No publicly reachable origin identified. Architecture may use a private origin, tunnel or strict ingress controls."
        return {
            "status": status,
            "automatic_origin_discovery": status,
            "target": root,
            "mode": self.config.mode,
            "cdn_waf_detected": cdn,
            "candidates_collected": len(candidates),
            "candidates_rejected_before_validation": len([item for item in candidates if item not in selected]),
            "candidates_actively_validated": len([item for item in selected if item.validation_status != "not_validated"]),
            "direct_requests_performed": budget.consumed,
            "highest_confidence_candidate": highest.ip if highest else None,
            "confidence_score": highest.final_score if highest else 0,
            "classification": highest.classification if highest else "inconclusive",
            "manual_confirmation_recommended": True,
            "primary": [item.to_dict() for item in primary],
            "additional": [item.to_dict() for item in additional],
            "historical": [item.to_dict() for item in historical],
            "related_infrastructure": [item.to_dict() for item in rejected],
            "message": message,
            "warning": ORIGIN_WARNING,
        }

    def _cached_validations(self) -> dict[str, dict[str, Any]]:
        if not self.workspace.resume:
            return {}
        path = self.directory / "validation-results.jsonl"
        if not path.is_file():
            return {}
        output: dict[str, dict[str, Any]] = {}
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict) or not item.get("ip"):
                continue
            classification = str(item.get("classification") or "")
            if classification not in {
                "high_confidence_origin", "probable_origin", "possible_origin",
                "protected_origin", "not_matching", "related_infrastructure",
            }:
                continue
            try:
                observed = datetime.fromisoformat(str(item.get("validated_at") or ""))
                if observed.tzinfo is None:
                    observed = observed.replace(tzinfo=UTC)
            except ValueError:
                continue
            if observed < datetime.now(UTC) - timedelta(hours=24):
                continue
            output[str(item["ip"])] = item
        return output

    def _reuse_validation(self, candidate: OriginCandidate, cached: dict[str, Any]) -> None:
        for raw in cached.get("evidence", []):
            if not isinstance(raw, dict) or raw.get("source_family") != "direct_validation":
                continue
            try:
                candidate.add_evidence(OriginEvidence(**raw))
            except TypeError:
                continue
        candidate.final_score = score_candidate(candidate)
        candidate.validation_status = str(cached.get("classification") or "inconclusive")
        candidate.classification = candidate.validation_status
        candidate.validation = dict(cached)
        candidate.validation["cache_reused"] = True

    def _write_ranking_csv(self, ranking: dict[str, Any]) -> None:
        path = self.directory / "final-ranking.csv"
        fields = ["ip", "initial_score", "final_score", "classification", "asn", "organization", "historical_dns", "certificate_evidence", "content_similarity", "favicon_match", "tls_result", "http_result", "last_observed", "validation_requests", "rejection_reason"]
        rows = ranking.get("primary", []) + ranking.get("additional", []) + ranking.get("historical", []) + ranking.get("related_infrastructure", [])
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for item in rows:
                evidence = item.get("evidence", [])
                validation = item.get("validation", {})
                writer.writerow({
                    "ip": item.get("ip"), "initial_score": item.get("initial_score"), "final_score": item.get("final_score"), "classification": item.get("classification"),
                    "asn": item.get("network", {}).get("asn", ""), "organization": item.get("network", {}).get("organization", ""),
                    "historical_dns": any(entry.get("code") == "historical_apex_dns" for entry in evidence),
                    "certificate_evidence": ",".join(entry.get("code", "") for entry in evidence if "certificate" in entry.get("code", "")),
                    "content_similarity": validation.get("comparisons", {}).get("/", {}).get("normalized_similarity", ""),
                    "favicon_match": any(entry.get("code") == "same_favicon_sha256" for entry in evidence),
                    "tls_result": validation.get("tls", {}).get("handshake", ""),
                    "http_result": ",".join(str(entry.get("status") or entry.get("error") or "") for entry in validation.get("http", [])),
                    "last_observed": item.get("last_observed") or "", "validation_requests": validation.get("validation_requests", 0),
                    "rejection_reason": ",".join(item.get("rejection_reasons", [])),
                })

    def run(self) -> str:
        if not self.target.domains:
            raise ValueError("Automatic Origin discovery requires at least one domain")
        root = self.target.domains[0]
        if self.dry_run:
            return self._dry_run(root)
        self._log(f"Capturing public baseline for {root}")
        baseline = capture_public_baseline(root, self.config, self.runner)
        inventory = dns_inventory(root)
        baseline["dns"] = inventory
        dns_records = inventory.get("records", {})
        for endpoint in baseline.get("endpoints", []):
            hostname = endpoint.get("hostname")
            cnames = dns_records.get(f"{hostname}:CNAME", []) if hostname else []
            endpoint["cname"] = cnames[0] if cnames else endpoint.get("cname", "")
        self.cloudflare = load_cloudflare_networks(timeout=self.timeout, retries=self.retries)
        cdn = detect_cdn(baseline, self.cloudflare)
        baseline["cdn_waf"] = cdn
        serializable_baseline = json.loads(
            json.dumps(baseline, default=lambda value: None, ensure_ascii=False)
        )
        for endpoint in serializable_baseline.get("endpoints", []):
            endpoint.pop("_normalized_body", None)
        self.workspace.write_json("origin/public-baseline.json", serializable_baseline)
        names = {root, f"www.{root}"}
        names.update(self.workspace.values("domain", in_scope=True))
        if self.config.mode in {"balanced", "deep"}:
            labels = SIGNIFICANT_LABELS if self.config.mode == "deep" else SIGNIFICANT_LABELS[:16]
            names.update(f"{label}.{root}" for label in labels)
        observations = collect_workspace_observations(self.workspace.findings, self.target.domains)
        configured_engines = {item.casefold() for item in self.config.query_engines}
        provider_families = {
            "censys": "censys",
            "shodan": "shodan",
            "urlscan": "urlscan",
            "infrastructure_search": "uncover",
            "virustotal": "virustotal",
        }
        observations = [
            item
            for item in observations
            if item.source_family not in provider_families
            or provider_families[item.source_family] in configured_engines
        ]
        observations.extend(dns_related_observations(inventory, root))
        observations.extend(collect_resolved_names(names, self.target.domains))
        observations.extend(self._historical_observations(root))
        if self.config.dns_permutations and self.config.mode != "passive":
            observations.extend(run_dns_permutations(names, self.target.domains, maximum=self.config.maximum_permutations, runner=self.runner, raw_directory=self.directory / "raw"))
        all_baseline_ips = {
            ip for endpoint in baseline.get("endpoints", []) for ip in endpoint.get("addresses", [])
        }
        baseline_ips = all_baseline_ips if cdn.get("provider") != "No CDN detected" else set()
        candidates = self._build_candidates(
            root, observations, baseline_ips, str(cdn.get("provider") or "Detected public edge")
        )
        if cdn.get("provider") == "No CDN detected":
            for candidate in candidates:
                if candidate.ip not in all_baseline_ips or candidate.classification in {"rejected", "third_party_service"}:
                    continue
                candidate.add_evidence(
                    OriginEvidence(
                        "public_direct_endpoint",
                        "Address directly serves the current public domain without a detected CDN",
                        25,
                        "public-baseline",
                        "public_baseline",
                        True,
                    )
                )
                candidate.initial_score = score_candidate(candidate)
                candidate.final_score = candidate.initial_score
                if candidate.initial_score >= self.config.minimum_score:
                    candidate.classification = "origin_candidate"
            candidates.sort(
                key=lambda item: (-item.initial_score, -item.independent_source_count, item.ip)
            )
        for candidate in candidates:
            self._log(f"Collected candidate {candidate.ip}; score {candidate.initial_score}")
        selected: list[OriginCandidate] = []
        rejected: list[OriginCandidate] = []
        for candidate in candidates:
            allowed, reasons = should_auto_validate(candidate, self.config)
            if allowed and len(selected) < self.config.maximum_candidates:
                selected.append(candidate)
                self._log(f"Candidate {candidate.ip} selected automatically for validation")
            else:
                candidate.rejection_reasons = list(dict.fromkeys(candidate.rejection_reasons + reasons + (["candidate_limit_reached"] if allowed else [])))
                rejected.append(candidate)
        self._write_jsonl("all-candidates.jsonl", (item.to_dict() for item in candidates))
        self._write_jsonl("selected-candidates.jsonl", (item.to_dict() for item in selected))
        self._write_jsonl("rejected-candidates.jsonl", (item.to_dict() for item in rejected))
        previous_budget: dict[str, Any] = {}
        budget_path = self.directory / "request-budget.json"
        if self.workspace.resume and budget_path.is_file():
            try:
                previous_budget = json.loads(budget_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
        budget = OriginBudget(
            self.config,
            previous=previous_budget,
            on_change=lambda current: self.workspace.write_json(
                "origin/request-budget.json", current.to_dict()
            ),
        )
        validation_results: list[dict[str, Any]] = []

        def persist_validation_results() -> None:
            self._write_jsonl("validation-results.jsonl", validation_results)

        cached_validations = self._cached_validations()
        if self.config.mode != "passive" and self.config.direct_validation and self.config.auto_verify:
            for candidate in selected:
                cached = cached_validations.get(candidate.ip)
                if cached:
                    self._reuse_validation(candidate, cached)
                    reused = dict(cached)
                    reused["cache_reused"] = True
                    validation_results.append(reused)
                    persist_validation_results()
                    self._log(f"Reused fresh successful validation for {candidate.ip}")
                    if candidate.final_score >= self.config.stop_score and not self.config.continue_after_match:
                        self._log("Stop threshold reached")
                        break
                    continue
                if not budget.can_consume(candidate.ip):
                    self._log("Origin validation request budget exhausted. Remaining candidates were not contacted.")
                    break
                before = candidate.initial_score
                try:
                    validation_results.append(self._validate_candidate(candidate, root, baseline, budget))
                    persist_validation_results()
                except RuntimeError as exc:
                    if "budget exhausted" in str(exc).casefold():
                        self._log("Origin validation request budget exhausted. Remaining candidates were not contacted.")
                        break
                    raise
                self._log(f"Candidate score updated: {before} -> {candidate.final_score}")
                if candidate.final_score >= self.config.stop_score and not self.config.continue_after_match:
                    self._log("Stop threshold reached")
                    break
        persist_validation_results()
        self.workspace.write_json("origin/request-budget.json", budget.to_dict())
        self._write_jsonl("network-classification.jsonl", ({"ip": item.ip, **item.network.to_dict()} for item in candidates))
        self._write_jsonl("evidence.jsonl", ({"ip": item.ip, **evidence.to_dict()} for item in candidates for evidence in item.evidence))
        ranking = self._ranking(root, candidates, selected, budget, cdn)
        self.workspace.write_json("origin/final-ranking.json", ranking)
        self._write_ranking_csv(ranking)
        for item in ranking["primary"] + ranking["additional"]:
            self.add_finding("origin", "origin-correlation", "origin_candidate", item["ip"], False, {"root": root, "ip": item["ip"], "score": item["final_score"], "classification": item["classification"], "relationship": "Origin correlation", "manual_confirmation_recommended": True})
        for item in rejected:
            self.add_finding("origin", "origin-network-classifier", "origin_rejected", item.ip, False, {"root": root, "ip": item.ip, "score": item.final_score, "classification": item.classification, "reasons": item.rejection_reasons})
        highest = ranking.get("highest_confidence_candidate") or "none"
        return f"Automatic Origin discovery completed in {self.config.mode} mode; {len(candidates)} candidates, {len(selected)} selected, highest {highest}"


def render_origin_summary(ranking: dict[str, Any]) -> str:
    highest = ranking.get("highest_confidence_candidate") or "none"
    return "\n".join([
        f"Automatic origin discovery: {ranking.get('status', 'unknown')}",
        f"Mode: {ranking.get('mode', 'unknown')}",
        f"CDN/WAF detected: {ranking.get('cdn_waf_detected', {}).get('provider', 'Unknown')}",
        f"Candidates collected: {ranking.get('candidates_collected', 0)}",
        f"Candidates rejected before validation: {ranking.get('candidates_rejected_before_validation', 0)}",
        f"Candidates actively validated: {ranking.get('candidates_actively_validated', 0)}",
        f"Direct requests performed: {ranking.get('direct_requests_performed', 0)}",
        f"Highest-confidence candidate: {highest}",
        f"Confidence score: {ranking.get('confidence_score', 0)}/100",
        f"Classification: {ranking.get('classification', 'inconclusive')}",
        "Manual confirmation recommended: yes",
        ranking.get("message", ""),
        ORIGIN_WARNING,
    ]).strip()


__all__ = [
    "FORBIDDEN_REQUEST_HEADERS",
    "HttpProbeResult",
    "OriginBudget",
    "OriginEngine",
    "TLSProbeResult",
    "capture_public_baseline",
    "direct_http_request",
    "normalize_html",
    "probe_jarm",
    "probe_tls",
    "render_origin_summary",
    "score_candidate",
    "should_auto_validate",
]
