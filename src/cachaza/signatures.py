"""Reproducible Shodan signature generation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from .safety import normalize_domain


FINGERPRINT_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){19}[0-9a-f]{2}\b|\b[0-9a-f]{40}\b")


@dataclass(frozen=True, slots=True)
class Signature:
    name: str
    query: str

    @property
    def identifier(self) -> str:
        return hashlib.sha1(f"{self.name}\0{self.query}".encode()).hexdigest()[:12]

    def as_line(self) -> str:
        return f"{self.name}::{self.query}"


def normalize_fingerprint(value: str) -> str | None:
    match = FINGERPRINT_RE.search(value)
    if not match:
        return None
    return match.group(0).replace(":", "").lower()


def generate_signatures(
    domains: list[str],
    organizations: list[str] | None = None,
    fingerprints: list[str] | None = None,
) -> list[Signature]:
    signatures: list[Signature] = []
    for raw in fingerprints or []:
        fingerprint = normalize_fingerprint(raw)
        if fingerprint:
            signatures.append(
                Signature(f"ssl_SHA1_{fingerprint}", f'ssl.cert.fingerprint:"{fingerprint}"')
            )

    cdn_exclusions = '"-AkamaiGHost" "-GHost" "-Cloudflare" "-Cloudfront"'
    for raw_domain in domains:
        domain = normalize_domain(raw_domain)
        key = domain.replace(".", "_")
        signatures.extend(
            [
                Signature(f"SSL_Domain_{key}", f'ssl:"{domain}"'),
                Signature(f"Hostname_Domain_{key}", f'hostname:"{domain}"'),
                Signature(f"SSL_Issuer_{key}", f'ssl.cert.issuer.cn:"{domain}"'),
                Signature(f"SSL_Subject_{key}", f'ssl.cert.subject.cn:"{domain}"'),
                Signature(
                    f"SSL_Expired_{key}", f'ssl.cert.expired:true hostname:"*.{domain}"'
                ),
                Signature(
                    f"SSL_SubjectCN_{key}", f'ssl.cert.subject.commonName:"*.{domain}"'
                ),
                Signature(
                    f"Ignored_by_CDNs_SSL_{key}", f'ssl:"{domain}" {cdn_exclusions}'
                ),
                Signature(
                    f"Ignored_by_CDNs_hostname_{key}",
                    f'hostname:"*.{domain}" {cdn_exclusions}',
                ),
                Signature(
                    f"Directory_Listing_hostname_{key}",
                    f'http.title:"Directory Listing" hostname:"*.{domain}"',
                ),
                Signature(
                    f"Directory_Listing_subject_{key}",
                    f'http.title:"Directory Listing" ssl.cert.subject.cn:"{domain}"',
                ),
                Signature(
                    f"Indexing_Hostname_{key}",
                    f'http.title:"Index of /" hostname:"*.{domain}"',
                ),
                Signature(
                    f"Indexing_SSL_{key}",
                    f'http.title:"Index of /" ssl.cert.subject.cn:"{domain}"',
                ),
                Signature(
                    f"phpinfo_hostname_{key}", f'http.title:"phpinfo()" hostname:"*.{domain}"'
                ),
            ]
        )
    for organization in organizations or []:
        clean = organization.strip()
        if clean:
            key = re.sub(r"[^A-Za-z0-9]+", "_", clean).strip("_") or "org"
            signatures.append(Signature(f"Org_Domain_{key}", f'org:"{clean}"'))
    return list(dict.fromkeys(signatures))
