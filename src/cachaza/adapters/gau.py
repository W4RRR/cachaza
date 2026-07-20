"""GAU historical URL adapter."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Finding, TargetSpec
from .common import url_in_scope


SENSITIVE = re.compile(
    r"\.(?:xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|"
    r"log|cache|secret|db|backup|ya?ml|config|csv|md5?|p12|pem|key|crt|csr|sh|pl|py|"
    r"java|class|jar|war|ear|sqlite(?:db|3)?|dbf|db3|accdb|mdb|env|ini|conf|properties|"
    r"plist|cfg)(?:$|[?#])",
    re.IGNORECASE,
)
API_HINT = re.compile(r"/(?:api|v\d+|graphql|swagger|openapi)(?:/|\b)", re.IGNORECASE)


def build_argv(binary: str) -> list[str]:
    return [binary, "--subs"]


def parse_output(text: str, target: TargetSpec) -> list[Finding]:
    findings: list[Finding] = []
    for value in sorted({line.strip() for line in text.splitlines() if line.strip()}):
        if not value.startswith(("http://", "https://")):
            continue
        sensitive = bool(SENSITIVE.search(urlsplit(value).path))
        endpoint = bool(API_HINT.search(urlsplit(value).path))
        findings.append(
            Finding(
                "gau",
                "gau",
                "url",
                value,
                url_in_scope(value, target),
                {
                    "historical": True,
                    "sensitive_candidate": sensitive,
                    "confidence": "candidate" if sensitive else "observed",
                    "requires_manual_validation": sensitive,
                    "endpoint": endpoint,
                },
            )
        )
    return findings
