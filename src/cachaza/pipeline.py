from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from . import __version__
from .console import Console
from .credentials import load_credentials, temporary_harvester_home, temporary_subfinder_config
from .cloud import RangeIndex
from .external import CommandRunner, find_tool
from .http import HttpError, request_bytes
from .managed_tools import install_blackwidow, managed_blackwidow
from .models import Finding, OriginConfig, StageStatus, TargetSpec, utc_now
from .network_policy import MAX_CONCURRENCY, MAX_REQUESTS_PER_SECOND
from .origin import OriginEngine
from .profiles import DEFAULT_PROFILE, DEFAULT_STAGES
from .reports import export_reports
from .safety import (
    ValidationError,
    active_address_count,
    domain_in_scope,
    extract_domains,
    ip_in_scope,
    normalize_asn,
    normalize_cidr,
    normalize_domain,
)
from .signatures import generate_signatures, normalize_fingerprint
from .sources import (
    CLOUD_PROVIDERS,
    arin_rdap_ip,
    bgp_he_domain,
    certspotter_domains,
    censys_search,
    classify_cloud_value,
    crtsh_domains,
    fetch_cloud_ranges,
    load_fingerprint_file,
    intelx_phonebook,
    manual_osint_markdown,
    parse_json_lines,
    resolve_domain_ips,
    ripe_as_overview,
    ripe_network_info,
    ripe_prefixes,
    shodan_request,
    urlscan_search,
)
from .workspace import RunWorkspace
from .adapters import (
    blackwidow,
    cariddi,
    csp_stalker,
    dns_enum,
    dnsx,
    favicorn,
    gau,
    harvester,
    contacts,
    jsmap,
    jump403,
    katana,
    nuclei,
    smap,
    vulnx,
    waf,
)


@dataclass(slots=True)
class RunOptions:
    stages: list[str] = field(default_factory=lambda: list(DEFAULT_STAGES))
    profile: str = DEFAULT_PROFILE
    timeout: int = 20
    retries: int = 2
    jobs: int = MAX_CONCURRENCY
    dry_run: bool = False
    strict: bool = False
    recursive_subdomains: bool = False
    subdomain_tools: list[str] = field(default_factory=lambda: ["auto"])
    subdomain_rate_limit: int = 1
    subdomain_threads: int = 1
    tenant_script: str | None = None
    fingerprints_file: str | None = None
    shodan_mode: str = "count"
    shodan_pages: int = 1
    shodan_max_queries: int = 40
    cloud_providers: list[str] = field(default_factory=lambda: list(CLOUD_PROVIDERS))
    active: bool = False
    active_tools: list[str] = field(default_factory=lambda: ["httpx", "naabu", "caduceus"])
    ports: str = "80,443,8080,8443"
    rate_limit: int = MAX_REQUESTS_PER_SECOND
    max_active_hosts: int = 4096
    allow_large_ranges: bool = False
    report_formats: list[str] = field(default_factory=lambda: ["json", "txt"])
    report_color: bool = True
    whois: bool = False
    wappalyzer: bool = False
    api_config: str | None = None
    port_tools: list[str] = field(default_factory=lambda: ["naabu", "smap"])
    crawl_tools: list[str] = field(default_factory=lambda: ["auto"])
    nuclei_severities: str = "info,low,medium,high,critical"
    nuclei_tags: str = "waf,cors,login,misconfig,exposure"
    nuclei_rate_limit: int = MAX_REQUESTS_PER_SECOND
    nuclei_concurrency: int = MAX_CONCURRENCY
    max_crawl_urls: int = 50
    jsmap_path: str | None = None
    csp_stalker_path: str | None = None
    waf_tools: list[str] = field(default_factory=lambda: ["wafw00f", "nuclei", "nmap"])
    harvester_source: str = "all"
    harvester_limit: int = 500
    harvester_dns_server: str | None = None
    dns_enum_tools: list[str] = field(default_factory=lambda: ["dnsenum", "fierce"])
    blackwidow_depth: int | None = None
    blackwidow_path: str | None = None
    origin: OriginConfig | None = None


class Pipeline:
    def __init__(
        self,
        target: TargetSpec,
        workspace: RunWorkspace,
        options: RunOptions,
        console: Console,
    ) -> None:
        self.target = target
        self.workspace = workspace
        self.options = options
        self.console = console
        self.runner = CommandRunner(
            console,
            dry_run=options.dry_run,
            timeout=max(300, options.timeout * 20),
        )
        self.failures: list[str] = []
        self._wappalyzer_executed = False
        self.credentials = load_credentials(options.api_config)
        self._seed_scope()

    def _stage_cache_key(self, name: str) -> str:
        options = asdict(self.options)
        # Stage selection and presentation do not change a completed stage's
        # evidence. Excluding them lets an operator extend a resumed run while
        # retaining valid checkpoints from the shorter profile.
        for key in (
            "stages",
            "profile",
            "report_formats",
            "report_color",
            "strict",
            "dry_run",
        ):
            options.pop(key, None)
        payload = json.dumps(
            {
                "stage": name,
                "scope": self.target.to_dict(),
                "options": options,
                "implementation_version": __version__,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _seed_scope(self) -> None:
        for domain in self.target.domains:
            self._add("input", "scope", "domain", domain, True, {"root": True})
        for asn in self.target.asns:
            self._add("input", "scope", "asn", asn, True, {"explicit": True})
        for organization in self.target.organizations:
            self._add("input", "scope", "organization", organization, True, {"explicit": True})
        for cidr in self.target.cidrs:
            self._add("input", "scope", "cidr", cidr, True, {"explicit": True})
        self.workspace.write_json("scope.json", self.target.to_dict())

    def _add(
        self,
        stage: str,
        source: str,
        kind: str,
        value: str,
        in_scope: bool,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        finding = Finding(
            stage=stage,
            source=source,
            kind=kind,
            value=value,
            in_scope=in_scope,
            metadata=metadata or {},
        )
        added = self.workspace.add(finding)
        if added:
            self.console.finding(
                source=source,
                kind=kind,
                value=value,
                in_scope=in_scope,
                metadata=finding.metadata,
            )
        return added

    def _ingest_findings(self, findings: list[Finding]) -> int:
        added = 0
        for finding in findings:
            if self._add(
                finding.stage,
                finding.source,
                finding.kind,
                finding.value,
                finding.in_scope,
                finding.metadata,
            ):
                added += 1
        return added

    def _run_stage(self, name: str, function: Callable[[], str | None]) -> None:
        cache_key = self._stage_cache_key(name)
        if self.workspace.resume and self.workspace.checkpoint_matches(name, cache_key):
            now = utc_now()
            status = StageStatus(
                name=name,
                status="cached",
                started_at=now,
                finished_at=now,
                details="completed stage reused from a compatible workspace",
            )
            self.workspace.stages.append(status)
            self.console.info(f"Stage: {name} (cached)")
            return
        status = StageStatus(name=name, status="running", started_at=utc_now())
        self.workspace.stages.append(status)
        self.console.info(f"Stage: {name}")
        try:
            details = function()
            status.status = "completed"
            status.details = details or ""
            if not self.options.dry_run:
                self.workspace.write_checkpoint(name, cache_key, status.details)
            self.console.debug(f"Completed {name}: {status.details or 'no additional details'}")
        except KeyboardInterrupt:
            status.status = "interrupted"
            status.details = "interrupted by the user"
            raise
        except Exception as exc:  # stages are fault-isolated unless -strict
            status.status = "failed"
            status.details = str(exc)
            self.failures.append(f"{name}: {exc}")
            self.console.warn(f"{name}: {exc}")
            if self.options.strict:
                raise
        finally:
            status.finished_at = utc_now()

    def execute(self) -> Path:
        stage_map: dict[str, Callable[[], str | None]] = {
            "corporate": self.stage_corporate,
            "asn": self.stage_asn,
            "tenant": self.stage_tenant,
            "ct": self.stage_ct,
            "api": self.stage_api,
            "certificates": self.stage_certificates,
            "subdomains": self.stage_subdomains,
            "dns": self.stage_dns,
            "dns_enum": self.stage_dns_enum,
            "harvester": self.stage_harvester,
            "blackwidow": self.stage_blackwidow,
            "waf": self.stage_waf,
            "shodan": self.stage_shodan,
            "ports": self.stage_ports,
            "http": self.stage_http,
            "cloud": self.stage_cloud,
            "nuclei": self.stage_nuclei,
            "bypass": self.stage_bypass,
            "gau": self.stage_gau,
            "crawl": self.stage_crawl,
            "js": self.stage_js,
            "policies": self.stage_policies,
            "cve": self.stage_cve,
            "active": self.stage_active,
            "origin": self.stage_origin,
        }
        for name in self.options.stages:
            if name not in stage_map:
                raise ValidationError(f"unknown stage: {name}")
            self._run_stage(name, stage_map[name])
        if self.options.wappalyzer and not self._wappalyzer_executed:
            self._run_stage("wappalyzer", self.stage_wappalyzer)
        if self.options.whois:
            self._run_stage("whois", self.stage_whois)
        self.finalize()
        return self.workspace.root

    def stage_origin(self) -> str:
        if self.options.origin is None:
            return "automatic Origin discovery was not requested"
        return OriginEngine(
            self.target,
            self.workspace,
            self.options.origin,
            self.console,
            self.runner,
            self.credentials,
            timeout=self.options.timeout,
            retries=self.options.retries,
            add_finding=self._add,
            dry_run=self.options.dry_run,
        ).run()

    def stage_corporate(self) -> str:
        self.workspace.write_text(
            "manual-osint.md",
            manual_osint_markdown(
                self.target.domains, self.target.asns, self.target.organizations
            ),
        )
        return "manual handoff generated for BGP, ARIN, corporate intelligence, and ASN/DNS"

    def stage_asn(self) -> str:
        prefix_count = 0
        asn_count = 0
        organization_count = 0
        registration_count = 0
        source_errors: list[str] = []
        discovered_asns = set(self.target.asns)

        def source_failed(source: str, target: str, exc: Exception) -> None:
            message = f"{source} for {target}: {exc}"
            source_errors.append(message)
            self.console.warn(message)
            if self.options.strict:
                raise exc

        if self.options.dry_run:
            self.console.debug("Dry run: skipping DNS, BGP Toolkit, RIPEstat, and ARIN RDAP")
        else:
            for domain in self.target.domains:
                resolved_ips: list[str] = []
                try:
                    resolved_ips = resolve_domain_ips(domain)
                except OSError as exc:
                    source_failed("dns", domain, exc)
                for ip in resolved_ips:
                    address = ipaddress.ip_address(ip)
                    self._add(
                        "asn",
                        "dns",
                        "ip",
                        ip,
                        False,
                        {
                            "root": domain,
                            "candidate_only": True,
                            "publicly_routable": address.is_global,
                        },
                    )

                try:
                    bgp_records = bgp_he_domain(
                        domain, timeout=self.options.timeout, retries=self.options.retries
                    )
                except (HttpError, OSError, ValueError) as exc:
                    source_failed("bgp.he.net", domain, exc)
                    bgp_records = []
                for record in bgp_records:
                    asn = record["asn"]
                    discovered_asns.add(asn)
                    if self._add(
                        "asn",
                        "bgp.he.net",
                        "asn",
                        asn,
                        False,
                        {
                            "root": domain,
                            "holder": record.get("holder", ""),
                            "candidate_only": True,
                            "relationship": "dns_origin",
                        },
                    ):
                        asn_count += 1
                    holder = str(record.get("holder") or "").strip()
                    if holder and self._add(
                        "asn",
                        "bgp.he.net",
                        "organization",
                        holder,
                        False,
                        {
                            "root": domain,
                            "asn": asn,
                            "candidate_only": True,
                            "role": "network_operator",
                        },
                    ):
                        organization_count += 1
                    for ip in record.get("ips", []):
                        self._add(
                            "asn",
                            "bgp.he.net",
                            "ip",
                            ip,
                            False,
                            {"root": domain, "asn": asn, "candidate_only": True},
                        )
                    for cidr in record.get("prefixes", []):
                        if self._add(
                            "asn",
                            "bgp.he.net",
                            "cidr",
                            cidr,
                            False,
                            {"root": domain, "asn": asn, "candidate_only": True},
                        ):
                            prefix_count += 1

                for ip in resolved_ips:
                    if not ipaddress.ip_address(ip).is_global:
                        continue
                    try:
                        network = ripe_network_info(
                            ip, timeout=self.options.timeout, retries=self.options.retries
                        )
                    except (HttpError, OSError, ValueError) as exc:
                        source_failed("RIPEstat network-info", ip, exc)
                        network = {"asns": [], "prefix": None}
                    for asn in network.get("asns", []):
                        discovered_asns.add(asn)
                        if self._add(
                            "asn",
                            "ripestat-network-info",
                            "asn",
                            asn,
                            False,
                            {
                                "root": domain,
                                "ip": ip,
                                "candidate_only": True,
                                "relationship": "origin_asn",
                            },
                        ):
                            asn_count += 1
                    prefix = network.get("prefix")
                    if prefix and self._add(
                        "asn",
                        "ripestat-network-info",
                        "cidr",
                        prefix,
                        False,
                        {
                            "root": domain,
                            "ip": ip,
                            "asns": network.get("asns", []),
                            "candidate_only": True,
                        },
                    ):
                        prefix_count += 1

                    try:
                        rdap = arin_rdap_ip(
                            ip, timeout=self.options.timeout, retries=self.options.retries
                        )
                    except (HttpError, OSError, ValueError) as exc:
                        source_failed("ARIN RDAP", ip, exc)
                        continue
                    for asn in rdap.get("origin_asns", []):
                        discovered_asns.add(asn)
                        if self._add(
                            "asn",
                            "arin-rdap",
                            "asn",
                            asn,
                            False,
                            {"root": domain, "ip": ip, "candidate_only": True},
                        ):
                            asn_count += 1
                    registration = str(rdap.get("name") or rdap.get("handle") or "").strip()
                    if registration and self._add(
                        "asn",
                        "arin-rdap",
                        "network_registration",
                        registration,
                        False,
                        {
                            "root": domain,
                            "ip": ip,
                            "handle": rdap.get("handle"),
                            "type": rdap.get("type"),
                            "country": rdap.get("country"),
                            "start_address": rdap.get("start_address"),
                            "end_address": rdap.get("end_address"),
                            "candidate_only": True,
                        },
                    ):
                        registration_count += 1
                    for organization in rdap.get("organizations", []):
                        if self._add(
                            "asn",
                            "arin-rdap",
                            "organization",
                            organization,
                            False,
                            {
                                "root": domain,
                                "ip": ip,
                                "role": "network_registrant",
                                "candidate_only": True,
                            },
                        ):
                            organization_count += 1

            for asn in sorted(discovered_asns):
                try:
                    overview = ripe_as_overview(
                        asn, timeout=self.options.timeout, retries=self.options.retries
                    )
                except (HttpError, OSError, ValueError) as exc:
                    source_failed("RIPEstat as-overview", asn, exc)
                    continue
                authoritative = asn in self.target.asns
                if self._add(
                    "asn",
                    "ripestat-as-overview",
                    "asn",
                    asn,
                    authoritative,
                    {
                        "holder": overview.get("holder"),
                        "announced": overview.get("announced"),
                        "registry": overview.get("registry"),
                        "candidate_only": not authoritative,
                    },
                ):
                    asn_count += 1
                holder = str(overview.get("holder") or "").strip()
                if holder and self._add(
                    "asn",
                    "ripestat-as-overview",
                    "organization",
                    holder,
                    False,
                    {
                        "asn": asn,
                        "role": "asn_holder",
                        "candidate_only": not authoritative,
                    },
                ):
                    organization_count += 1

            for asn in self.target.asns:
                for cidr in ripe_prefixes(
                    asn, timeout=self.options.timeout, retries=self.options.retries
                ):
                    if self._add(
                        "asn",
                        "ripestat",
                        "cidr",
                        cidr,
                        True,
                        {"asn": asn, "scope_basis": "explicit_asn"},
                    ):
                        prefix_count += 1

        binary = find_tool("asnmap")
        has_asnmap_key = bool(self.credentials.get("PDCP_API_KEY"))
        if (binary and has_asnmap_key) or self.options.dry_run:
            executable = binary or "asnmap"
            inputs: list[tuple[str, str, bool]] = []
            inputs.extend(("-a", value, True) for value in self.target.asns)
            inputs.extend(("-d", value, False) for value in self.target.domains)
            inputs.extend(("-org", value, False) for value in self.target.organizations)
            for flag, value, authoritative in inputs:
                argv = [executable, flag, value, "-json"]
                if not self.console.verbose:
                    argv.append("-silent")
                result = self.runner.run(argv, env=self.credentials)
                if result.skipped:
                    continue
                if result.returncode != 0:
                    self.console.warn(f"asnmap failed for {value}: {result.stderr.strip()[:300]}")
                    continue
                for row in parse_json_lines(result.stdout):
                    raw_asn = str(row.get("as_number", ""))
                    try:
                        found_asn = normalize_asn(raw_asn)
                    except ValidationError:
                        found_asn = ""
                    if found_asn and self._add(
                        "asn",
                        "asnmap",
                        "asn",
                        found_asn,
                        authoritative,
                        {
                            "input": value,
                            "candidate_only": not authoritative,
                            "as_name": row.get("as_name"),
                            "as_country": row.get("as_country"),
                        },
                    ):
                        asn_count += 1
                    raw_ranges = row.get("as_range", [])
                    if isinstance(raw_ranges, str):
                        raw_ranges = [raw_ranges]
                    for raw_cidr in raw_ranges if isinstance(raw_ranges, list) else []:
                        try:
                            cidr = normalize_cidr(str(raw_cidr))
                        except ValidationError:
                            continue
                        if self._add(
                            "asn",
                            "asnmap",
                            "cidr",
                            cidr,
                            authoritative,
                            {
                                "input": value,
                                "asn": found_asn or None,
                                "candidate_only": not authoritative,
                            },
                        ):
                            prefix_count += 1
        elif binary:
            self.console.debug("PDCP_API_KEY is not configured; skipping optional asnmap adapter")

        error_note = f"; {len(source_errors)} source errors" if source_errors else ""
        return (
            f"{asn_count} ASN records, {prefix_count} prefixes, {organization_count} organizations, "
            f"and {registration_count} registrations added{error_note}; domain-derived networks are candidates"
        )

    def stage_tenant(self) -> str:
        binary = find_tool("tenant-domains.sh", self.options.tenant_script)
        binary = binary or find_tool("tenant-domains", self.options.tenant_script)
        if not binary and not self.options.dry_run:
            return "tenant-domains is unavailable; stage skipped"
        executable = binary or self.options.tenant_script or "tenant-domains.sh"
        count = 0
        for root in self.target.domains:
            argv = [executable, "-d", root]
            if not self.console.verbose:
                argv.append("-s")
            if executable.endswith(".sh") and Path(executable).is_file() and not os.access(executable, os.X_OK):
                argv.insert(0, "bash")
            result = self.runner.run(argv)
            if result.skipped:
                continue
            slug = self._artifact_slug(root)
            self.workspace.write_text(
                f"tenant-domains/{slug}-stdout.txt", result.stdout
            )
            self.workspace.write_text(
                f"tenant-domains/{slug}-stderr.txt", result.stderr
            )
            if result.returncode != 0:
                diagnostic = result.stderr.strip() or result.stdout.strip()
                if not diagnostic:
                    diagnostic = "the process returned no stdout or stderr"
                self.console.warn(
                    f"tenant-domains failed for {root} (exit {result.returncode}): "
                    f"{diagnostic[:300]}. Raw stdout/stderr were saved under "
                    "rest/tenant-domains/."
                )
                continue
            for domain in extract_domains(result.stdout):
                in_scope = domain_in_scope(domain, self.target.domains, self.target.exclude_domains)
                if self._add(
                    "tenant",
                    "tenant-domains",
                    "domain",
                    domain,
                    in_scope,
                    {"tenant_seed": root, "requires_scope_approval": not in_scope},
                ):
                    count += 1
        return f"{count} related domains; additional apex domains require explicit scope approval"

    def stage_ct(self) -> str:
        if self.options.dry_run:
            return "dry run: CT queries skipped"
        total = 0
        source_counts: dict[str, int] = {"certspotter": 0, "crt.sh": 0}
        for root in self.target.domains:
            successful_sources = 0
            try:
                names = certspotter_domains(
                    root, timeout=self.options.timeout, retries=self.options.retries
                )
            except HttpError as exc:
                self.console.warn(f"Cert Spotter unavailable for {root}: {exc}")
                if self.options.strict:
                    raise
            else:
                successful_sources += 1
                for name in names:
                    if self._add("ct", "certspotter", "domain", name, True, {"root": root}):
                        source_counts["certspotter"] += 1
                        total += 1

            try:
                names = crtsh_domains(
                    root,
                    timeout=min(self.options.timeout, 8),
                    retries=0,
                )
            except HttpError as exc:
                transient_note = (
                    " Remote transient 502/5xx response; this is a crt.sh service failure, "
                    "not a local credential or MTU error."
                    if exc.status_code == 502 or "502" in str(exc)
                    else ""
                )
                self.console.warn(
                    f"crt.sh unavailable for {root}: {exc}.{transient_note} "
                    "Continuing with Cert Spotter results."
                )
                if self.options.strict:
                    raise
            else:
                successful_sources += 1
                for name in names:
                    if self._add("ct", "crt.sh", "domain", name, True, {"root": root}):
                        source_counts["crt.sh"] += 1
                        total += 1
            if not successful_sources:
                self.console.warn(f"No CT source returned data for {root}")
        return (
            f"{total} CT findings added "
            f"(Cert Spotter: {source_counts['certspotter']}, crt.sh: {source_counts['crt.sh']})"
        )

    def stage_api(self) -> str:
        if self.options.dry_run:
            return "dry run: Censys and urlscan search requests skipped"
        counts = {"censys": 0, "intelx": 0, "urlscan": 0}
        errors: list[str] = []
        provider_status: dict[str, dict[str, Any]] = {}
        for root in self.target.domains:
            censys_key = self.credentials.get("CENSYS_API_KEY", "").strip()
            if censys_key:
                provider_status.setdefault("censys", {"configured": True, "status": "pending", "findings": 0})
                try:
                    result = censys_search(
                        root,
                        api_key=censys_key,
                        organization_id=self.credentials.get("CENSYS_ORG_ID", "").strip(),
                        timeout=max(self.options.timeout, 30),
                        retries=self.options.retries,
                    )
                    self.workspace.write_json(f"api/censys-{root}.json", result["payload"])
                    for domain in result["domains"]:
                        if self._add(
                            "api",
                            "censys-platform",
                            "domain",
                            domain,
                            domain_in_scope(domain, self.target.domains, self.target.exclude_domains),
                            {"root": root, "passive": True, "page_limit": 1},
                        ):
                            counts["censys"] += 1
                    for ip in result["ips"]:
                        scoped = ip_in_scope(ip, self.target.cidrs, self.target.exclude_cidrs)
                        if self._add(
                            "api",
                            "censys-platform",
                            "ip",
                            ip,
                            scoped,
                            {"root": root, "passive": True, "candidate_only": not scoped},
                        ):
                            counts["censys"] += 1
                    provider_status["censys"].update(status="ok", findings=counts["censys"])
                except (HttpError, OSError, ValueError) as exc:
                    message = str(exc)
                    status_code = getattr(exc, "status_code", None)
                    unauthorized = status_code == 401 or "401" in message or "unauthorized" in message.casefold()
                    forbidden = status_code == 403 or "403" in message
                    if unauthorized:
                        action = (
                            "Regenerate a current Censys Platform personal access token and place it only in "
                            "CENSYS_API_KEY; legacy CENSYS_API_ID/CENSYS_API_SECRET values are not valid here. "
                            "For organization access, also verify the API Access role. CENSYS_ORG_ID is optional."
                        )
                    elif forbidden:
                        action = (
                            "The credential was accepted but lacks permission for Global Search; verify the "
                            "Censys subscription, organization, and API Access role."
                        )
                    else:
                        action = "Retry later if the provider reports a transient 429/5xx response."
                    errors.append(f"Censys for {root}: {message}. Action: {action}")
                    provider_status["censys"].update(
                        status="error",
                        http_status=status_code,
                        transient=bool(getattr(exc, "transient", False)),
                        action=action,
                        error=errors[-1],
                    )
                    self.console.warn(errors[-1])

            intelx_key = self.credentials.get("INTELX_API_KEY", "").strip()
            if intelx_key:
                provider_status.setdefault("intelx", {"configured": True, "status": "pending", "findings": 0})
                try:
                    result = intelx_phonebook(
                        root,
                        api_key=intelx_key,
                        host=self.credentials.get("INTELX_HOST", "").strip() or "https://2.intelx.io",
                        timeout=max(self.options.timeout, 30),
                        retries=self.options.retries,
                    )
                    self.workspace.write_json(f"api/intelx-{root}.json", result["result"])
                    for value in result["values"]:
                        if harvester.EMAIL.fullmatch(value):
                            if self._add("api", "intelx", "email", value.lower(), True, {"root": root, "passive": True}):
                                counts["intelx"] += 1
                            continue
                        parsed = urlsplit(value)
                        if parsed.scheme in {"http", "https"} and parsed.hostname:
                            if self._add("api", "intelx", "url", value, domain_in_scope(parsed.hostname, self.target.domains, self.target.exclude_domains), {"root": root, "passive": True}):
                                counts["intelx"] += 1
                            continue
                        phone_match = harvester.PHONE.fullmatch(value)
                        if phone_match and 8 <= sum(character.isdigit() for character in value) <= 16:
                            if self._add("api", "intelx", "phone", value, True, {"root": root, "passive": True}):
                                counts["intelx"] += 1
                            continue
                        for domain in extract_domains(value, self.target.domains):
                            if self._add("api", "intelx", "domain", domain, True, {"root": root, "passive": True}):
                                counts["intelx"] += 1
                    provider_status["intelx"].update(status="ok", findings=counts["intelx"])
                except (HttpError, OSError, ValueError) as exc:
                    message = str(exc)
                    status_code = getattr(exc, "status_code", None)
                    unauthorized = status_code == 401 or "401" in message or "unauthorized" in message.casefold()
                    forbidden = status_code == 403 or "403" in message
                    if unauthorized:
                        action = (
                            "Verify that INTELX_API_KEY is current and belongs to the INTELX_HOST account; "
                            "the account must include Phonebook API access."
                        )
                    elif forbidden:
                        action = (
                            "The key was recognized but the account is not permitted to use Phonebook; "
                            "verify the IntelX plan and API entitlements."
                        )
                    else:
                        action = "Retry later if the provider reports a transient 429/5xx response."
                    errors.append(f"IntelX for {root}: {message}. Action: {action}")
                    provider_status["intelx"].update(
                        status="error",
                        http_status=status_code,
                        transient=bool(getattr(exc, "transient", False)),
                        action=action,
                        error=errors[-1],
                    )
                    self.console.warn(errors[-1])

            urlscan_key = self.credentials.get("URLSCAN_API_KEY", "").strip()
            if urlscan_key:
                provider_status.setdefault("urlscan", {"configured": True, "status": "pending", "findings": 0})
                try:
                    result = urlscan_search(
                        root,
                        api_key=urlscan_key,
                        timeout=self.options.timeout,
                        retries=self.options.retries,
                    )
                    self.workspace.write_json(f"api/urlscan-{root}.json", result["payload"])
                    for domain in result["domains"]:
                        if self._add(
                            "api",
                            "urlscan",
                            "domain",
                            domain,
                            domain_in_scope(domain, self.target.domains, self.target.exclude_domains),
                            {"root": root, "search_only": True, "scan_submitted": False},
                        ):
                            counts["urlscan"] += 1
                    for url in result["urls"]:
                        host = urlsplit(url).hostname or ""
                        if self._add(
                            "api",
                            "urlscan",
                            "url",
                            url,
                            domain_in_scope(host, self.target.domains, self.target.exclude_domains),
                            {"root": root, "historical": True, "scan_submitted": False},
                        ):
                            counts["urlscan"] += 1
                    for ip in result["ips"]:
                        scoped = ip_in_scope(ip, self.target.cidrs, self.target.exclude_cidrs)
                        if self._add(
                            "api",
                            "urlscan",
                            "ip",
                            ip,
                            scoped,
                            {
                                "root": root,
                                "historical": True,
                                "scan_submitted": False,
                                "candidate_only": not scoped,
                            },
                        ):
                            counts["urlscan"] += 1
                    provider_status["urlscan"].update(status="ok", findings=counts["urlscan"])
                except (HttpError, OSError, ValueError) as exc:
                    errors.append(f"urlscan for {root}: {exc}")
                    provider_status["urlscan"].update(status="error", error=errors[-1])
                    self.console.warn(errors[-1])
        if errors:
            self.workspace.write_json("api/errors.json", errors)
        self.workspace.write_json("api/provider-status.json", provider_status)
        configured = [
            name
            for name, key in (
                ("Censys", "CENSYS_API_KEY"),
                ("IntelX", "INTELX_API_KEY"),
                ("urlscan", "URLSCAN_API_KEY"),
            )
            if self.credentials.get(key)
        ]
        if not configured:
            return "Censys/IntelX/urlscan credentials unavailable; provider-backed Subfinder remains available"
        return f"{counts['censys']} Censys, {counts['intelx']} IntelX, and {counts['urlscan']} urlscan findings"

    def stage_certificates(self) -> str:
        if not self.options.active:
            raise ValidationError("certificates performs direct probes and requires -active")
        networks, skipped = self._active_networks()
        if skipped:
            self.workspace.write_lines("certificates-networks-skipped.txt", skipped)
        if not networks:
            return "no explicitly authorized CIDRs available for certificate probing"
        binary = self._tool_or_plan("caduceus")
        if not binary:
            return "caduceus unavailable; certificate probing skipped"
        path = self.workspace.write_lines("certificates-networks.txt", networks)
        self._run_caduceus(binary, path, stage="certificates")
        return f"caduceus processed {len(networks)} explicitly authorized networks"

    def stage_dns(self) -> str:
        if not self.options.active:
            raise ValidationError("dns performs direct resolution and requires -active")
        domains = self.workspace.values("domain", in_scope=True)
        if not domains:
            return "no authorized domains available for DNS validation"
        binary = self._tool_or_plan("dnsx")
        if not binary:
            return "dnsx unavailable; DNS validation skipped"
        input_file = self.workspace.write_lines("dnsx-targets.txt", domains)
        argv = dnsx.build_argv(binary, str(input_file), rate_limit=self.options.rate_limit)
        result = self.runner.run(argv, timeout=max(1800, self.options.timeout * 100))
        if result.skipped:
            return f"dry-run planned for {len(domains)} authorized domains"
        self.workspace.write_text("dnsx.jsonl", result.stdout)
        if result.returncode != 0:
            raise RuntimeError(f"dnsx exited with {result.returncode}: {result.stderr.strip()[:500]}")
        added = self._ingest_findings(dnsx.parse_output(result.stdout, self.target))
        return f"{added} normalized DNS observations from {len(domains)} domains"

    def _selected_subdomain_tools(self) -> list[str]:
        supported = ["subfinder", "assetfinder", "bbot"]
        requested = [item.lower() for item in self.options.subdomain_tools]
        if "auto" in requested:
            selected = [name for name in supported[:2] if find_tool(name)]
            if selected:
                return selected
            return supported[:2] if self.options.dry_run else []
        unknown = sorted(set(requested) - set(supported))
        if unknown:
            raise ValidationError(f"unsupported enumerators: {', '.join(unknown)}")
        return list(dict.fromkeys(requested))

    def stage_subdomains(self) -> str:
        tools = self._selected_subdomain_tools()
        if not tools:
            return "no external enumerators are available; the CT stage still provides passive coverage"
        count = 0
        for tool in tools:
            binary = find_tool(tool)
            if not binary and not self.options.dry_run:
                self.console.warn(f"{tool} is not installed")
                continue
            executable = binary or tool
            for root in self.target.domains:
                if tool == "subfinder":
                    argv = [
                        executable,
                        "-d",
                        root,
                        "-all",
                        "-oJ",
                        "-cs",
                        "-rl",
                        str(self.options.subdomain_rate_limit),
                        "-t",
                        str(self.options.subdomain_threads),
                    ]
                    if not self.console.verbose:
                        argv.append("-silent")
                    if self.options.recursive_subdomains:
                        argv.append("-recursive")
                elif tool == "assetfinder":
                    argv = [executable, "--subs-only", root]
                else:
                    argv = [
                        executable,
                        "-t",
                        root,
                        "-p",
                        "subdomain-enum",
                        "-rf",
                        "passive",
                        "--json",
                    ]
                    if not self.console.verbose:
                        argv.append("--brief")
                if tool == "subfinder":
                    with temporary_subfinder_config(self.credentials) as provider_config:
                        if provider_config:
                            argv.extend(["-pc", provider_config])
                        result = self.runner.run(argv, timeout=max(600, self.options.timeout * 30))
                else:
                    result = self.runner.run(argv, timeout=max(600, self.options.timeout * 30))
                if result.skipped:
                    continue
                if result.returncode != 0:
                    self.console.warn(f"{tool} failed for {root}: {result.stderr.strip()[:300]}")
                    continue
                if tool == "subfinder":
                    rows = parse_json_lines(result.stdout)
                    if rows:
                        for row in rows:
                            name = str(row.get("host") or "").lower().rstrip(".")
                            if not domain_in_scope(name, self.target.domains, self.target.exclude_domains):
                                continue
                            providers = row.get("sources") or row.get("source") or []
                            if isinstance(providers, str):
                                providers = [providers]
                            provider_names = sorted(
                                {str(item).strip() for item in providers if str(item).strip()}
                            ) if isinstance(providers, list) else []
                            source = f"subfinder/{provider_names[0]}" if len(provider_names) == 1 else "subfinder"
                            if self._add(
                                "subdomains",
                                source,
                                "domain",
                                name,
                                True,
                                {"root": root, "providers": provider_names},
                            ):
                                count += 1
                        continue
                for name in extract_domains(result.stdout, self.target.domains):
                    if self._add("subdomains", tool, "domain", name, True, {"root": root}):
                        count += 1
        return f"{count} new names found with {', '.join(tools)}"

    @staticmethod
    def _artifact_slug(value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-.")[:100] or "target"

    def stage_harvester(self) -> str:
        if not self.options.active:
            raise ValidationError(
                "harvester enables API endpoint and takeover checks and requires -active"
            )
        binary = self._tool_or_plan("theHarvester")
        if not binary:
            return "theHarvester unavailable; organization OSINT skipped"
        added = 0
        completed = 0
        for root in self.target.domains:
            basename = self.workspace.artifact_path(
                f"theharvester/{self._artifact_slug(root)}"
            )
            argv = [
                binary,
                "-d",
                root,
                "-l",
                str(self.options.harvester_limit),
                "-s",
                "-a",
                "-t",
                "-b",
                self.options.harvester_source,
                "-f",
                str(basename),
            ]
            if self.options.harvester_dns_server:
                argv.extend(["-e", self.options.harvester_dns_server])
            with temporary_harvester_home(self.credentials) as temporary_home:
                result = self.runner.run(
                    argv,
                    timeout=max(3600, self.options.timeout * 200),
                    env={**self.credentials, "HOME": temporary_home},
                )
            if result.skipped:
                continue
            completed += 1
            self.workspace.write_text(
                f"theharvester/{self._artifact_slug(root)}-stdout.txt", result.stdout
            )
            self.workspace.write_text(
                f"theharvester/{self._artifact_slug(root)}-stderr.txt", result.stderr
            )
            if result.returncode != 0:
                self.console.warn(
                    f"theHarvester exited with {result.returncode} for {root}; saved JSON will still be parsed"
                )
            candidates = [Path(str(basename) + ".json")]
            payload = next(
                (
                    path.read_text(encoding="utf-8", errors="replace")
                    for path in candidates
                    if path.is_file()
                ),
                result.stdout if result.stdout.lstrip().startswith(("{", "[")) else "",
            )
            if payload:
                added += self._ingest_findings(
                    harvester.parse_json(payload, root, self.target)
                )
            contact_paths = re.compile(r"/(?:contact|contacto|about|legal|terms|terminos|privacy|privacidad|aviso)(?:[/._-]|$)", re.I)
            contact_urls = {f"https://{root}/"}
            for url in self.workspace.values("url", in_scope=True):
                parsed = urlsplit(url)
                if parsed.hostname and domain_in_scope(parsed.hostname, [root], self.target.exclude_domains) and contact_paths.search(parsed.path):
                    contact_urls.add(url)
            checked = 0
            for url in sorted(contact_urls)[:12]:
                try:
                    body = request_bytes(
                        url,
                        timeout=self.options.timeout,
                        retries=min(self.options.retries, 1),
                        headers={"Accept": "text/html,application/xhtml+xml;q=0.9"},
                    ).decode("utf-8", errors="replace")
                except HttpError as exc:
                    self.console.warn(f"contact page unavailable for {url}: {exc}")
                    continue
                checked += 1
                added += self._ingest_findings(contacts.parse_html(url, body, root, self.target))
        return f"{added} normalized organization/contact findings from {completed} domains, including bounded contact-page extraction"

    def stage_blackwidow(self) -> str:
        if not self.options.active:
            raise ValidationError("BlackWidow crawls and fuzzes the target and requires -active")
        depth = self.options.blackwidow_depth
        if depth is None:
            return "BlackWidow not requested"
        binary = find_tool("blackwidow", self.options.blackwidow_path) if self.options.blackwidow_path else None
        if not binary and managed_blackwidow().is_file():
            binary = str(managed_blackwidow())
        if not binary and self.options.dry_run:
            binary = self.options.blackwidow_path or "blackwidow"
        if not binary:
            self.console.info("BlackWidow is missing; installing the pinned user-space copy")
            try:
                binary = install_blackwidow()
            except (OSError, RuntimeError) as exc:
                raise RuntimeError(f"BlackWidow automatic installation failed: {exc}") from exc
        output_root = self.workspace.artifact_path("blackwidow")
        output_root.mkdir(parents=True, exist_ok=True)
        added = 0
        completed = 0
        for root in self.target.domains:
            url = f"https://{root}/"
            argv = [binary, "-l", str(depth), "-v", "y", "-s", "y", "-u", url]
            with tempfile.TemporaryDirectory(prefix="cachaza-blackwidow-run-") as temporary:
                scan_output = Path(temporary)
                result = self.runner.run(
                    argv,
                    timeout=max(3600, self.options.timeout * 300),
                    env={**self.credentials, "CACHAZA_BLACKWIDOW_OUTPUT": str(scan_output)},
                )
                parsed_artifacts = blackwidow.parse_tree(scan_output, root, self.target)
                shutil.copytree(scan_output, output_root, dirs_exist_ok=True)
            if result.skipped:
                continue
            completed += 1
            self.workspace.write_text(f"blackwidow/{self._artifact_slug(root)}-stdout.txt", result.stdout)
            self.workspace.write_text(f"blackwidow/{self._artifact_slug(root)}-stderr.txt", result.stderr)
            added += self._ingest_findings(blackwidow.parse_output(result.stdout + "\n" + result.stderr, root, self.target))
            added += self._ingest_findings(parsed_artifacts)
            if result.returncode:
                self.console.warn(f"BlackWidow exited with {result.returncode} for {root}; partial artifacts were normalized")
        return f"{added} normalized BlackWidow findings from {completed} domains at depth {depth}"

    def stage_dns_enum(self) -> str:
        if not self.options.active:
            raise ValidationError("DNS enumeration performs direct queries and requires -active")
        added = 0
        completed: list[str] = []
        for tool in self.options.dns_enum_tools:
            binary = self._tool_or_plan(tool)
            if not binary:
                continue
            for root in self.target.domains:
                argv = [binary, root] if tool == "dnsenum" else [binary, "-dns", root]
                result = self.runner.run(
                    argv, timeout=max(3600, self.options.timeout * 200)
                )
                if result.skipped:
                    continue
                raw = result.stdout + "\n" + result.stderr
                self.workspace.write_text(
                    f"dns-enum/{self._artifact_slug(root)}-{tool}.txt", raw
                )
                if result.returncode != 0:
                    self.console.warn(
                        f"{tool} exited with {result.returncode} for {root}; partial output will still be parsed"
                    )
                added += self._ingest_findings(
                    dns_enum.parse_output(raw, tool, root, self.target)
                )
                completed.append(tool)
        transfers = len(self.workspace.values("dns_zone_transfer"))
        transfer_note = (
            f"; WARNING: {transfers} accepted zone transfer(s) observed"
            if transfers
            else "; no accepted zone transfer observed"
        )
        return f"{added} normalized DNS findings with {', '.join(sorted(set(completed))) or 'no tools'}{transfer_note}"

    def stage_waf(self) -> str:
        if not self.options.active:
            raise ValidationError("WAF detection performs direct HTTP probes and requires -active")
        urls = {f"https://{domain}" for domain in self.target.domains}
        for discovered in self.workspace.values("url", in_scope=True):
            parsed = urlsplit(discovered)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                urls.add(f"{parsed.scheme}://{parsed.netloc}")
        added = 0
        completed: list[str] = []
        for tool in self.options.waf_tools:
            binary = self._tool_or_plan(tool)
            if not binary:
                continue
            for url in sorted(urls):
                parsed = urlsplit(url)
                host = parsed.hostname or ""
                if not host:
                    continue
                slug = self._artifact_slug(f"{host}-{parsed.port or 443}")
                if tool == "wafw00f":
                    argv = [binary, url, "-a"]
                    command_timeout = max(180, self.options.timeout * 5)
                    parser = lambda value: waf.parse_wafw00f(value, url, self.target)
                elif tool == "nuclei":
                    argv = [
                        binary,
                        "-u",
                        url,
                        "-t",
                        "http/technologies/waf-detect.yaml",
                        "-jsonl",
                        "-rl",
                        "1",
                        "-bulk-size",
                        "1",
                        "-c",
                        "1",
                        "-timeout",
                        str(self.options.timeout),
                        "-retries",
                        "1",
                        "-no-stdin",
                        "-omit-raw",
                        "-no-color",
                    ]
                    if not self.console.verbose:
                        argv.append("-silent")
                    command_timeout = max(120, self.options.timeout * 5)
                    parser = lambda value: waf.parse_nuclei(value, url, self.target)
                elif tool == "nmap":
                    port = parsed.port or (443 if parsed.scheme == "https" else 80)
                    argv = [
                        binary,
                        "-Pn",
                        "-sV",
                        "-p",
                        str(port),
                        "--script",
                        "http-waf-detect,http-waf-fingerprint",
                        "--script-args",
                        "http-waf-fingerprint.intensive=1,http-waf-fingerprint.root=/",
                        "-oX",
                        "-",
                        host,
                    ]
                    command_timeout = max(600, self.options.timeout * 20)
                    parser = lambda value: waf.parse_nmap_xml(value, url, self.target)
                else:
                    raise ValidationError(f"unsupported WAF adapter: {tool}")
                result = self.runner.run(argv, timeout=command_timeout)
                if result.skipped:
                    continue
                self.workspace.write_text(f"waf/{slug}-{tool}.txt", result.stdout)
                if result.returncode != 0:
                    self.console.warn(
                        f"{tool} WAF check exited with {result.returncode} for {url}; partial output will still be parsed"
                    )
                added += self._ingest_findings(parser(result.stdout))
                completed.append(tool)
        return f"{added} normalized WAF observations with {', '.join(sorted(set(completed))) or 'no tools'}"

    def stage_shodan(self) -> str:
        fingerprints = load_fingerprint_file(self.options.fingerprints_file)
        signatures = generate_signatures(
            self.target.domains, self.target.organizations, fingerprints
        )
        self.workspace.write_lines("shodan-queries.txt", (item.as_line() for item in signatures))
        if self.options.shodan_mode == "off":
            return f"{len(signatures)} queries generated; API disabled"
        if self.options.dry_run:
            return f"{len(signatures)} queries generated; API skipped in dry run"
        if not self.credentials.get("SHODAN_API_KEY"):
            self.console.warn("SHODAN_API_KEY is not configured; signatures were generated without API calls")
            return f"{len(signatures)} queries generated; API credentials unavailable"

        results: list[dict[str, Any]] = []
        for signature in signatures[: self.options.shodan_max_queries]:
            try:
                result = shodan_request(
                    signature,
                    mode=self.options.shodan_mode,
                    pages=self.options.shodan_pages,
                    timeout=self.options.timeout,
                    retries=self.options.retries,
                    api_key=self.credentials.get("SHODAN_API_KEY"),
                )
            except HttpError as exc:
                self.console.warn(f"Shodan failed for {signature.name}: {exc}")
                continue
            results.append(result)
            for match in result["matches"]:
                self._ingest_shodan_match(match, signature.name)
        lines = [json.dumps(item, ensure_ascii=False, sort_keys=True) for item in results]
        self.workspace.write_lines("shodan-results.jsonl", lines)
        return f"{len(results)} API queries completed in {self.options.shodan_mode} mode"

    def _ingest_shodan_match(self, match: dict[str, Any], signature: str) -> None:
        ip_value = str(match.get("ip_str") or "").strip()
        allowed_cidrs = self.workspace.values("cidr", in_scope=True)
        ip_scope = ip_in_scope(ip_value, allowed_cidrs, self.target.exclude_cidrs) if ip_value else False
        if ip_value:
            try:
                ipaddress.ip_address(ip_value)
                self._add(
                    "shodan",
                    "shodan",
                    "ip",
                    ip_value,
                    ip_scope,
                    {"signature": signature, "candidate_only": not ip_scope},
                )
            except ValueError:
                pass
        for raw in match.get("hostnames", []) if isinstance(match.get("hostnames"), list) else []:
            try:
                name = normalize_domain(str(raw))
            except ValidationError:
                continue
            scoped = domain_in_scope(name, self.target.domains, self.target.exclude_domains)
            self._add(
                "shodan",
                "shodan",
                "domain",
                name,
                scoped,
                {"signature": signature, "requires_scope_approval": not scoped},
            )
        port = match.get("port")
        if ip_value and isinstance(port, int):
            self._add(
                "shodan",
                "shodan",
                "service",
                f"{ip_value}:{port}",
                ip_scope,
                {
                    "signature": signature,
                    "transport": match.get("transport"),
                    "product": match.get("product"),
                },
            )
        fingerprint = (
            match.get("ssl", {}).get("cert", {}).get("fingerprint", {}).get("sha1")
            if isinstance(match.get("ssl"), dict)
            else None
        )
        normalized = normalize_fingerprint(str(fingerprint)) if fingerprint else None
        if normalized:
            self._add(
                "shodan",
                "shodan",
                "fingerprint",
                normalized,
                ip_scope,
                {"signature": signature, "ip": ip_value or None},
            )

    def stage_cloud(self) -> str:
        if not self.options.cloud_providers:
            return "cloud classification disabled"
        if self.options.dry_run:
            return "dry run: cloud range download and classification skipped"
        ranges, errors = fetch_cloud_ranges(
            self.options.cloud_providers,
            timeout=self.options.timeout,
            retries=self.options.retries,
            jobs=self.options.jobs,
        )
        index = RangeIndex.from_provider_networks(ranges)
        matches: list[dict[str, Any]] = []
        for kind in ("ip", "cidr"):
            for value in self.workspace.values(kind):
                if kind == "ip":
                    provider = index.lookup(ipaddress.ip_address(value))
                    providers = [provider] if provider else []
                else:
                    providers = classify_cloud_value(value, ranges)
                if not providers:
                    continue
                item = {"kind": kind, "value": value, "providers": providers}
                matches.append(item)
                self._add(
                    "cloud",
                    "lord-alfred/ipranges",
                    "cloud_asset",
                    value,
                    (value in self.workspace.values(kind, in_scope=True)),
                    {"providers": providers, "classification_only": True},
                )
        self.workspace.write_lines(
            "cloud-matches.jsonl",
            (json.dumps(item, sort_keys=True) for item in matches),
        )
        if errors:
            self.workspace.write_json("cloud-errors.json", errors)
        return f"{len(matches)} matches; cloud ranges were used only for classification, never scope expansion"

    def _active_networks(self) -> tuple[list[str], list[str]]:
        allowed: list[str] = []
        skipped: list[str] = []
        for cidr in self.workspace.values("cidr", in_scope=True):
            network = ipaddress.ip_network(cidr)
            if any(
                network.version == ipaddress.ip_network(excluded).version
                and network.overlaps(ipaddress.ip_network(excluded))
                for excluded in self.target.exclude_cidrs
            ):
                skipped.append(cidr)
                continue
            if network.num_addresses > self.options.max_active_hosts and not self.options.allow_large_ranges:
                skipped.append(cidr)
                continue
            allowed.append(cidr)
        if not self.options.allow_large_ranges:
            total = active_address_count(allowed, self.options.max_active_hosts)
            if total > self.options.max_active_hosts:
                raise ValidationError(
                    f"active scope contains more than {self.options.max_active_hosts} addresses; "
                    "reduce the scope or explicitly use -allow-large-ranges"
                )
        return allowed, skipped

    def _tool_or_plan(self, name: str) -> str | None:
        binary = find_tool(name)
        if binary:
            return binary
        if self.options.dry_run:
            return name
        self.console.warn(f"{name} is not installed; adapter skipped")
        return None

    def stage_active(self) -> str:
        if not self.options.active:
            return "disabled; use -active to run authorized direct probes"
        domains = self.workspace.values("domain", in_scope=True)
        networks, skipped = self._active_networks()
        domains_file = self.workspace.write_lines("active-domains.txt", domains)
        networks_file = self.workspace.write_lines("active-networks.txt", networks)
        if skipped:
            self.workspace.write_lines("active-networks-skipped.txt", skipped)
            self.console.warn(f"{len(skipped)} networks were excluded by size limits or exclusions")
        completed: list[str] = []
        for tool in self.options.active_tools:
            if tool == "httpx":
                if not domains:
                    continue
                binary = self._tool_or_plan("httpx")
                if binary:
                    self._run_httpx(binary, domains_file)
                    completed.append("httpx")
            elif tool == "naabu":
                if not networks:
                    continue
                binary = self._tool_or_plan("naabu")
                if binary:
                    self._run_naabu(binary, networks_file)
                    completed.append("naabu")
            elif tool == "caduceus":
                if not networks:
                    continue
                binary = self._tool_or_plan("caduceus")
                if binary:
                    self._run_caduceus(binary, networks_file)
                    completed.append("caduceus")
            elif tool == "nmap":
                if not networks:
                    continue
                binary = self._tool_or_plan("nmap")
                if binary:
                    self._run_nmap(binary, networks_file)
                    completed.append("nmap")
            else:
                raise ValidationError(f"unsupported active tool: {tool}")
        enrichment = "; Wappalyzer fingerprints enabled" if self.options.wappalyzer else ""
        return f"adapters: {', '.join(completed) if completed else 'none'}{enrichment}"

    def stage_ports(self) -> str:
        if not self.options.active:
            raise ValidationError("ports performs direct probes and requires -active")
        domains = self.workspace.values("domain", in_scope=True)
        domain_file = self.workspace.write_lines("port-targets.txt", domains)
        networks, skipped = self._active_networks()
        if skipped:
            self.workspace.write_lines("port-networks-skipped.txt", skipped)
        selected = ", ".join(self.options.port_tools) or "none"
        self.console.info(
            f"ports: tools={selected}; ports={self.options.ports}; "
            f"{len(domains)} authorized domain(s), {len(networks)} authorized CIDR(s); "
            f"hard ceiling {MAX_REQUESTS_PER_SECOND} requests/packets per second and "
            f"{MAX_CONCURRENCY} network workers"
        )
        completed: list[str] = []
        for tool in self.options.port_tools:
            if tool == "naabu":
                if not domains:
                    continue
                binary = self._tool_or_plan("naabu")
                if not binary:
                    continue
                argv = [
                    binary,
                    "-l",
                    str(domain_file),
                    "-p",
                    self.options.ports,
                    "-rate",
                    str(self.options.rate_limit),
                    "-c",
                    str(self.options.jobs),
                    "-no-color",
                ]
                if not self.console.verbose:
                    argv.append("-silent")
                result = self.runner.run(argv, timeout=max(3600, self.options.timeout * 200))
                if not result.skipped:
                    self.workspace.write_text("naabu.txt", result.stdout)
                    if result.returncode != 0:
                        raise RuntimeError(
                            f"naabu exited with {result.returncode}: {result.stderr.strip()[:500]}"
                        )
                    for line in result.stdout.splitlines():
                        value = line.strip()
                        if not value or ":" not in value:
                            continue
                        host = value.rsplit(":", 1)[0].strip("[]")
                        scoped = domain_in_scope(
                            host, self.target.domains, self.target.exclude_domains
                        )
                        if not scoped:
                            scoped = ip_in_scope(
                                host, self.target.cidrs, self.target.exclude_cidrs
                            )
                        self._add(
                            "ports", "naabu", "service", value, scoped, {"active": True}
                        )
                completed.append("naabu")
            elif tool == "smap":
                if not domains:
                    continue
                if not self.credentials.get("SHODAN_API_KEY"):
                    self.console.warn("SHODAN_API_KEY is not configured; smap skipped")
                    continue
                binary = self._tool_or_plan("smap")
                if not binary:
                    continue
                result = self.runner.run(
                    smap.build_argv(binary),
                    input_text="\n".join(domains) + "\n",
                    timeout=max(900, self.options.timeout * 50),
                    env=self.credentials,
                )
                if not result.skipped:
                    self.workspace.write_text("smap.txt", result.stdout)
                    if result.returncode != 0:
                        self.console.warn(
                            f"smap exited with {result.returncode}: {result.stderr.strip()[:300]}"
                        )
                    self._ingest_findings(smap.parse_output(result.stdout, self.target))
                completed.append("smap")
            elif tool == "nmap":
                if not networks:
                    continue
                binary = self._tool_or_plan("nmap")
                if not binary:
                    continue
                network_file = self.workspace.write_lines("nmap-networks.txt", networks)
                self._run_nmap(binary, network_file)
                completed.append("nmap")
            else:
                raise ValidationError(f"unsupported port tool: {tool}")
        return (
            f"port adapters: {', '.join(completed) if completed else 'none'}; "
            "Naabu actively probes authorized domains, Smap performs passive Shodan lookup, "
            "and Nmap runs only against explicitly authorized CIDRs"
        )

    def stage_http(self) -> str:
        if not self.options.active:
            raise ValidationError("http performs direct probes and requires -active")
        targets = sorted(
            set(self.workspace.values("domain", in_scope=True))
            | set(self.workspace.values("service", in_scope=True))
        )
        if not targets:
            return "no authorized domains or services available for HTTP probing"
        binary = self._tool_or_plan("httpx")
        if not binary:
            return "httpx unavailable; HTTP probing skipped"
        input_file = self.workspace.write_lines("http-targets.txt", targets)
        before = len(self.workspace.findings)
        self._run_httpx(binary, input_file, stage="http", tech_detect=True)
        return f"{len(self.workspace.findings) - before} HTTP/technology findings from {len(targets)} targets"

    def stage_nuclei(self) -> str:
        if not self.options.active:
            raise ValidationError("nuclei performs direct checks and requires -active")
        urls = self.workspace.values("url", in_scope=True)
        if not urls:
            return "no authorized live URLs available for Nuclei"
        binary = self._tool_or_plan("nuclei")
        if not binary:
            return "nuclei unavailable; template checks skipped"
        input_file = self.workspace.write_lines("nuclei-targets.txt", urls)
        argv = nuclei.build_argv(
            binary,
            str(input_file),
            tags=self.options.nuclei_tags,
            severities=self.options.nuclei_severities,
            rate_limit=self.options.nuclei_rate_limit,
            concurrency=self.options.nuclei_concurrency,
            timeout=self.options.timeout,
            verbose=self.console.verbose,
        )
        result = self.runner.run(argv, timeout=max(3600, self.options.timeout * 300))
        if result.skipped:
            return f"dry-run planned for {len(urls)} URLs"
        self.workspace.write_text("nuclei.jsonl", result.stdout)
        if result.returncode != 0:
            self.console.warn(
                f"nuclei exited with {result.returncode}; partial JSONL will still be ingested"
            )
        added = self._ingest_findings(nuclei.parse_output(result.stdout, self.target))
        return f"{added} normalized Nuclei observations from {len(urls)} URLs"

    def stage_bypass(self) -> str:
        if not self.options.active:
            raise ValidationError("bypass validation requires -active")
        urls = sorted(
            {
                item.value
                for item in self.workspace.findings
                if item.kind == "url"
                and item.in_scope
                and str(item.metadata.get("status_code")) == "403"
            }
        )
        if not urls:
            return "no authorized HTTP 403 URLs available for bypass validation"
        binary = self._tool_or_plan("403jump")
        if not binary:
            return "403jump unavailable; bypass validation skipped"
        input_file = self.workspace.write_lines("403-targets.txt", urls)
        result = self.runner.run(
            jump403.build_argv(binary, str(input_file)),
            timeout=max(1800, self.options.timeout * 100),
        )
        if result.skipped:
            return f"dry-run planned for {len(urls)} HTTP 403 URLs"
        self.workspace.write_text("403jump.txt", result.stdout + result.stderr)
        added = self._ingest_findings(
            jump403.parse_output(result.stdout + "\n" + result.stderr, self.target)
        )
        return f"{added} possible bypass observations requiring manual validation"

    def stage_gau(self) -> str:
        binary = self._tool_or_plan("gau")
        if not binary:
            return "gau unavailable; historical URL discovery skipped"
        combined: list[str] = []
        for root in self.target.domains:
            result = self.runner.run(
                gau.build_argv(binary),
                input_text=root + "\n",
                timeout=max(1200, self.options.timeout * 60),
            )
            if result.skipped:
                continue
            if result.returncode != 0:
                self.console.warn(f"gau failed for {root}: {result.stderr.strip()[:300]}")
            combined.extend(result.stdout.splitlines())
        payload = "\n".join(sorted({line.strip() for line in combined if line.strip()}))
        if payload:
            payload += "\n"
        self.workspace.write_text("gau-urls.txt", payload)
        added = self._ingest_findings(gau.parse_output(payload, self.target))
        return f"{added} historical URLs normalized"

    def _selected_crawl_tools(self) -> list[str]:
        requested = [item.lower() for item in self.options.crawl_tools]
        supported = {"katana", "cariddi"}
        if "auto" in requested:
            if find_tool("katana") or self.options.dry_run:
                return ["katana"]
            return ["cariddi"] if find_tool("cariddi") else []
        unknown = set(requested) - supported
        if unknown:
            raise ValidationError(f"unsupported crawl tools: {', '.join(sorted(unknown))}")
        return list(dict.fromkeys(requested))

    def stage_crawl(self) -> str:
        if not self.options.active:
            raise ValidationError("crawl performs direct requests and requires -active")
        urls = sorted(
            {
                item.value
                for item in self.workspace.findings
                if item.kind == "url"
                and item.in_scope
                and (
                    item.metadata.get("status_code") is None
                    or str(item.metadata.get("status_code")).startswith(("2", "3"))
                )
            }
        )[: self.options.max_crawl_urls]
        if not urls:
            return "no authorized URLs available for crawling"
        input_file = self.workspace.write_lines("crawl-targets.txt", urls)
        completed: list[str] = []
        added = 0
        for tool in self._selected_crawl_tools():
            binary = self._tool_or_plan(tool)
            if not binary:
                continue
            if tool == "katana":
                argv = katana.build_argv(
                    binary,
                    str(input_file),
                    rate_limit=self.options.rate_limit,
                    timeout=self.options.timeout,
                )
                result = self.runner.run(argv, timeout=max(1800, self.options.timeout * 100))
                if not result.skipped:
                    self.workspace.write_text("katana.jsonl", result.stdout)
                    if result.returncode != 0:
                        self.console.warn("katana returned partial results")
                    added += self._ingest_findings(katana.parse_output(result.stdout, self.target))
            else:
                result = self.runner.run(
                    cariddi.build_argv(binary),
                    input_text="\n".join(urls) + "\n",
                    timeout=max(1800, self.options.timeout * 100),
                )
                if not result.skipped:
                    self.workspace.write_text("cariddi.txt", result.stdout)
                    if result.returncode != 0:
                        self.console.warn("cariddi returned partial results")
                    added += self._ingest_findings(cariddi.parse_output(result.stdout, self.target))
            completed.append(tool)
        return f"{added} crawler findings via {', '.join(completed) if completed else 'no adapters'}"

    def stage_js(self) -> str:
        if not self.options.active:
            raise ValidationError("JavaScript analysis requires -active")
        urls = sorted(
            {
                item.value
                for item in self.workspace.findings
                if item.kind == "url"
                and item.in_scope
                and re.search(r"\.js(?:$|[?#])", item.value, re.IGNORECASE)
            }
        )
        if not urls:
            return "no authorized JavaScript URLs available"
        binary = find_tool("JSMap-Inspector", self.options.jsmap_path)
        binary = binary or find_tool("jsmap-inspector", self.options.jsmap_path)
        if not binary and self.options.dry_run:
            binary = self.options.jsmap_path or "JSMap-Inspector"
        if not binary:
            return "JSMap Inspector unavailable; JavaScript analysis skipped"
        input_file = self.workspace.write_lines("jsmap-targets.txt", urls)
        output_file = self.workspace.artifact_path("jsmap-report.json")
        argv = jsmap.build_argv(binary, str(input_file), str(output_file))
        if binary.endswith(".py"):
            argv.insert(0, sys.executable)
        result = self.runner.run(argv, timeout=max(1800, self.options.timeout * 100))
        if result.skipped:
            return f"dry-run planned for {len(urls)} JavaScript URLs"
        payload = output_file.read_text(encoding="utf-8", errors="replace") if output_file.is_file() else result.stdout
        if not output_file.is_file():
            self.workspace.write_text("jsmap-report.json", payload)
        added = self._ingest_findings(jsmap.parse_output(payload, self.target))
        return f"{added} JavaScript analysis findings from {len(urls)} inputs"

    def stage_policies(self) -> str:
        if not self.options.active:
            raise ValidationError("policy and favicon probes require -active")
        urls = self.workspace.values("url", in_scope=True)[:20]
        if not urls:
            return "no authorized URLs available for policy analysis"
        added = 0
        completed: list[str] = []
        csp_binary = find_tool("csp-stalker", self.options.csp_stalker_path)
        if not csp_binary and self.options.dry_run:
            csp_binary = self.options.csp_stalker_path or "csp-stalker"
        if csp_binary:
            output_dir = self.workspace.artifact_path("policies/csp")
            output_dir.mkdir(parents=True, exist_ok=True)
            chunks: list[str] = []
            for url in urls:
                argv = csp_stalker.build_argv(csp_binary, url)
                if csp_binary.endswith(".py"):
                    argv.insert(0, sys.executable)
                result = self.runner.run(
                    argv,
                    cwd=output_dir,
                    timeout=max(300, self.options.timeout * 20),
                )
                if result.skipped:
                    continue
                chunks.extend([result.stdout, result.stderr])
                added += self._ingest_findings(
                    csp_stalker.parse_output(result.stdout + "\n" + result.stderr, self.target, url)
                )
            for path in output_dir.rglob("*"):
                if path.is_file() and path.suffix.lower() in {".txt", ".json", ".log"}:
                    content = path.read_text(encoding="utf-8", errors="replace")
                    chunks.append(content)
                    added += self._ingest_findings(
                        csp_stalker.parse_output(content, self.target, urls[0])
                    )
            self.workspace.write_text("csp-stalker.txt", "\n".join(chunks))
            completed.append("csp-stalker")

        favicon_binary = self._tool_or_plan("favicorn")
        if favicon_binary:
            input_file = self.workspace.write_lines("favicorn-targets.txt", urls)
            result = self.runner.run(
                favicorn.build_argv(favicon_binary, str(input_file)),
                timeout=max(900, self.options.timeout * 50),
            )
            if not result.skipped:
                self.workspace.write_text("favicorn.txt", result.stdout)
                added += self._ingest_findings(favicorn.parse_output(result.stdout, self.target))
            completed.append("favicorn")
        return f"{added} policy/fingerprint findings via {', '.join(completed) if completed else 'no adapters'}"

    def stage_cve(self) -> str:
        if not self.options.active:
            raise ValidationError("CVE correlation belongs to the authorized full profile and requires -active")
        technologies: dict[str, bool] = {}
        for item in self.workspace.findings:
            if item.kind != "technology":
                continue
            technology = str(item.metadata.get("technology") or item.value.split(":")[-1]).strip()
            normalized = re.sub(r"[0-9].*$", "", technology).strip(" /-_")
            if normalized:
                technologies[normalized] = technologies.get(normalized, False) or item.in_scope
        selected = sorted(technologies)[:20]
        if not selected:
            return "no technology fingerprints available for CVE correlation"
        binary = self._tool_or_plan("vulnx")
        if not binary:
            return "vulnx unavailable; CVE correlation skipped"
        chunks: list[str] = []
        added = 0
        for technology in selected:
            result = self.runner.run(
                vulnx.build_argv(binary, technology),
                timeout=max(300, self.options.timeout * 20),
                env=self.credentials,
            )
            if result.skipped:
                continue
            chunks.append(f"# {technology}\n{result.stdout}")
            added += self._ingest_findings(
                vulnx.parse_output(result.stdout, technology, in_scope=technologies[technology])
            )
        self.workspace.write_text("vulnx-raw.txt", "\n".join(chunks))
        return f"{added} CVE candidates correlated from {len(selected)} technologies"

    def _run_httpx(
        self,
        binary: str,
        domains_file: Path,
        *,
        stage: str = "active",
        tech_detect: bool | None = None,
    ) -> None:
        detect_technology = self.options.wappalyzer if tech_detect is None else tech_detect
        argv = [
            binary,
            "-l",
            str(domains_file),
            "-json",
            "-status-code",
            "-title",
            "-content-length",
            "-web-server",
            "-ip",
            "-cname",
            "-cdn",
            "-asn",
            "-location",
            "-no-color",
            "-follow-redirects",
            "-no-fallback",
            "-t",
            str(self.options.jobs),
            "-rl",
            str(self.options.rate_limit),
            "-ports",
            self.options.ports,
        ]
        if detect_technology:
            argv.append("-tech-detect")
            self._wappalyzer_executed = True
        if not self.console.verbose:
            argv.append("-silent")
        result = self.runner.run(argv, timeout=max(1800, self.options.timeout * 100))
        if result.skipped:
            return
        self.workspace.write_text("httpx.jsonl", result.stdout)
        if detect_technology:
            self.workspace.write_text("wappalyzer.jsonl", result.stdout)
        if result.returncode != 0:
            raise RuntimeError(f"httpx exited with {result.returncode}: {result.stderr.strip()[:500]}")
        rows = parse_json_lines(result.stdout)
        for row in rows:
            url = str(row.get("url") or "").strip()
            host = (
                urlsplit(url).hostname
                or str(row.get("input") or row.get("host") or "").strip()
            )
            scoped = domain_in_scope(host, self.target.domains, self.target.exclude_domains)
            if url:
                self._add(
                    stage,
                    "httpx",
                    "url",
                    url,
                    scoped,
                    {
                        "status_code": row.get("status_code"),
                        "title": row.get("title"),
                        "webserver": row.get("webserver"),
                        "content_length": row.get("content_length"),
                        "location": row.get("location"),
                        "host": host,
                    },
                )
            ips = self._row_ips(row)
            for ip in ips:
                scoped_ip = ip_in_scope(ip, self.target.cidrs, self.target.exclude_cidrs)
                self._add(
                    stage,
                    "httpx",
                    "ip",
                    ip,
                    scoped_ip,
                    {"url": url or None, "host": host, "candidate_only": not scoped_ip},
                )
            port = row.get("port")
            if host and isinstance(port, int):
                self._add(
                    stage,
                    "httpx",
                    "service",
                    f"{host}:{port}",
                    scoped,
                    {
                        "url": url or None,
                        "status_code": row.get("status_code"),
                        "scheme": urlsplit(url).scheme if url else None,
                    },
                )
            for raw_cname in row.get("cname", []) if isinstance(row.get("cname"), list) else []:
                cname = str(raw_cname).lower().rstrip(".")
                cname_scope = domain_in_scope(cname, self.target.domains, self.target.exclude_domains)
                self._add(
                    stage,
                    "httpx",
                    "domain",
                    cname,
                    cname_scope,
                    {"cname_for": host, "requires_scope_approval": not cname_scope},
                )
            raw_asn = row.get("asn")
            if isinstance(raw_asn, dict):
                raw_asn = raw_asn.get("asn") or raw_asn.get("number")
            if raw_asn:
                try:
                    asn_value = normalize_asn(str(raw_asn))
                except ValidationError:
                    asn_value = ""
                if asn_value:
                    self._add(
                        stage,
                        "httpx",
                        "asn",
                        asn_value,
                        asn_value in self.target.asns,
                        {"host": host, "url": url or None, "candidate_only": asn_value not in self.target.asns},
                    )
            cdn_name = str(row.get("cdn_name") or row.get("cdn") or "").strip()
            if cdn_name:
                self._add(
                    stage,
                    "httpx",
                    "cloud_asset",
                    host or url,
                    scoped,
                    {"provider": cdn_name, "url": url or None, "classification_only": True},
                )
        if detect_technology:
            self._consume_wappalyzer_rows(rows, stage=stage)

    @staticmethod
    def _row_ips(row: dict[str, Any]) -> list[str]:
        candidates: list[Any] = []
        for key in ("a", "aaaa", "host_ip", "ip"):
            raw = row.get(key)
            if isinstance(raw, list):
                candidates.extend(raw)
            elif raw:
                candidates.append(raw)
        values: set[str] = set()
        for raw in candidates:
            try:
                values.add(str(ipaddress.ip_address(str(raw).strip())))
            except ValueError:
                continue
        return sorted(values)

    def _consume_wappalyzer_rows(self, rows: list[dict[str, Any]], *, stage: str) -> int:
        detected = 0
        for row in rows:
            url = str(row.get("url") or "").strip()
            raw_host = str(row.get("input") or row.get("host") or "").strip()
            parsed_host = urlsplit(url).hostname if url else None
            host = parsed_host or raw_host
            scoped = domain_in_scope(host, self.target.domains, self.target.exclude_domains)
            domain_scoped = scoped
            if not scoped:
                scoped = ip_in_scope(host, self.target.cidrs, self.target.exclude_cidrs)
            ips = self._row_ips(row)
            for ip in ips:
                self._add(
                    stage,
                    "httpx-wappalyzer",
                    "ip",
                    ip,
                    ip_in_scope(ip, self.target.cidrs, self.target.exclude_cidrs),
                    {
                        "root": host if domain_scoped else None,
                        "url": url or None,
                        "candidate_only": not ip_in_scope(
                            ip, self.target.cidrs, self.target.exclude_cidrs
                        ),
                    },
                )
            raw_tech = row.get("tech", [])
            if isinstance(raw_tech, str):
                technologies = [item.strip() for item in raw_tech.split(",") if item.strip()]
            elif isinstance(raw_tech, list):
                technologies = [str(item).strip() for item in raw_tech if str(item).strip()]
            else:
                technologies = []
            endpoint = host or url or "unknown-endpoint"
            for technology in sorted(set(technologies)):
                if self._add(
                    stage,
                    "httpx-wappalyzer",
                    "technology",
                    f"{endpoint}: {technology}",
                    scoped,
                    {
                        "technology": technology,
                        "target": endpoint,
                        "url": url or None,
                        "ips": ips,
                        "status_code": row.get("status_code"),
                        "title": row.get("title"),
                        "webserver": row.get("webserver"),
                    },
                ):
                    detected += 1
        return detected

    def stage_wappalyzer(self) -> str:
        origins: set[str] = set()
        covered_hosts: set[str] = set()
        for raw_url in self.workspace.values("url", in_scope=True):
            parsed = urlsplit(raw_url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            origins.add(origin)
            covered_hosts.add(parsed.hostname.casefold())
        fallback_hosts = {
            value
            for value in (
                set(self.workspace.values("domain", in_scope=True))
                | set(self.workspace.values("ip", in_scope=True))
            )
            if value.casefold() not in covered_hosts
        }
        targets = sorted(origins | fallback_hosts)
        targets_file = self.workspace.write_lines("wappalyzer-targets.txt", targets)
        if not targets:
            return "no authorized domains, URLs, or IPs available for technology detection"
        binary = self._tool_or_plan("httpx")
        if not binary:
            return "httpx is unavailable; Wappalyzer fingerprint detection skipped"
        argv = [
            binary,
            "-l",
            str(targets_file),
            "-json",
            "-tech-detect",
            "-ip",
            "-status-code",
            "-title",
            "-web-server",
            "-follow-redirects",
            "-no-color",
            "-t",
            str(self.options.jobs),
            "-rl",
            str(self.options.rate_limit),
        ]
        if not self.console.verbose:
            argv.append("-silent")
        self._wappalyzer_executed = True
        result = self.runner.run(argv, timeout=max(1800, self.options.timeout * 100))
        if result.skipped:
            return f"dry-run planned for {len(targets)} authorized targets"
        self.workspace.write_text("wappalyzer.jsonl", result.stdout)
        if result.returncode != 0:
            raise RuntimeError(
                f"httpx Wappalyzer detection exited with {result.returncode}: "
                f"{result.stderr.strip()[:500]}"
            )
        detected = self._consume_wappalyzer_rows(
            parse_json_lines(result.stdout), stage="wappalyzer"
        )
        return f"{detected} technology observations from {len(targets)} authorized targets"

    @staticmethod
    def _whois_summary(output: str) -> dict[str, list[str]]:
        wanted = {
            "inetnum",
            "netrange",
            "cidr",
            "netname",
            "orgname",
            "org-name",
            "organization",
            "country",
            "origin",
            "originas",
            "route",
            "descr",
        }
        summary: dict[str, list[str]] = {}
        for line in output.splitlines():
            if ":" not in line or line.lstrip().startswith(("#", "%")):
                continue
            key, raw_value = line.split(":", 1)
            normalized = key.strip().lower()
            value = raw_value.strip()
            if normalized not in wanted or not value:
                continue
            values = summary.setdefault(normalized, [])
            if value not in values and len(values) < 10:
                values.append(value)
        return summary

    def stage_whois(self) -> str:
        targets: list[str] = []
        for value in self.workspace.values("ip"):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global:
                targets.append(str(address))
        targets = sorted(set(targets), key=lambda value: (ipaddress.ip_address(value).version, value))
        self.workspace.write_lines("whois-targets.txt", targets)
        if not targets:
            return "no unique public IP addresses available for WHOIS"
        binary = self._tool_or_plan("whois")
        if not binary:
            return "whois is unavailable; enrichment skipped"
        results: list[dict[str, Any]] = []
        successful = 0
        for ip in targets:
            result = self.runner.run([binary, ip], timeout=max(30, self.options.timeout * 3))
            if result.skipped:
                continue
            summary = self._whois_summary(result.stdout)
            results.append(
                {
                    "ip": ip,
                    "returncode": result.returncode,
                    "summary": summary,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )
            if result.returncode == 0:
                successful += 1
            self._add(
                "whois",
                "whois",
                "whois",
                ip,
                ip_in_scope(ip, self.target.cidrs, self.target.exclude_cidrs),
                {
                    "returncode": result.returncode,
                    "summary": summary,
                    "candidate_only": not ip_in_scope(
                        ip, self.target.cidrs, self.target.exclude_cidrs
                    ),
                },
            )
        self.workspace.write_lines(
            "whois-results.jsonl",
            (json.dumps(item, ensure_ascii=False, sort_keys=True) for item in results),
        )
        if self.options.dry_run:
            return f"dry-run planned for {len(targets)} unique public IPs"
        return f"{successful}/{len(targets)} unique public IP WHOIS queries succeeded"

    def _run_naabu(self, binary: str, networks_file: Path) -> None:
        argv = [
            binary,
            "-l",
            str(networks_file),
            "-p",
            self.options.ports,
            "-rate",
            str(self.options.rate_limit),
            "-c",
            str(self.options.jobs),
            "-no-color",
        ]
        if not self.console.verbose:
            argv.append("-silent")
        result = self.runner.run(argv, timeout=max(3600, self.options.timeout * 200))
        if result.skipped:
            return
        self.workspace.write_text("naabu.txt", result.stdout)
        if result.returncode != 0:
            raise RuntimeError(f"naabu exited with {result.returncode}: {result.stderr.strip()[:500]}")
        for line in result.stdout.splitlines():
            value = line.strip()
            if value:
                self._add("active", "naabu", "service", value, True, {})

    def _run_caduceus(
        self, binary: str, networks_file: Path, *, stage: str = "active"
    ) -> None:
        argv = [
            binary,
            "-i",
            str(networks_file),
            "-j",
            "-c",
            str(min(self.options.jobs, 20)),
            "-t",
            str(self.options.timeout),
            "-p",
            self.options.ports,
        ]
        result = self.runner.run(argv, timeout=max(3600, self.options.timeout * 200))
        if result.skipped:
            return
        self.workspace.write_text("caduceus.jsonl", result.stdout)
        if result.returncode != 0:
            raise RuntimeError(f"caduceus exited with {result.returncode}: {result.stderr.strip()[:500]}")
        for name in extract_domains(result.stdout, self.target.domains):
            self._add(stage, "caduceus", "domain", name, True, {"certificate_scan": True})

    def _run_nmap(self, binary: str, networks_file: Path) -> None:
        argv = [
            binary,
            "-sV",
            "-Pn",
            "--open",
            "-T3",
            "--max-retries",
            "2",
            "-p",
            self.options.ports,
            "-iL",
            str(networks_file),
            "-oX",
            str(self.workspace.artifact_path("nmap.xml")),
        ]
        result = self.runner.run(argv, timeout=max(7200, self.options.timeout * 300))
        if not result.skipped and result.returncode != 0:
            raise RuntimeError(f"nmap exited with {result.returncode}: {result.stderr.strip()[:500]}")

    def finalize(self) -> None:
        self.workspace.write_artifact_lists()
        export_reports(
            self.workspace,
            self.target,
            self.options.report_formats,
            version=__version__,
            failures=self.failures,
            txt_color=self.options.report_color,
        )
        self.workspace.write_manifest(
            self.target,
            version=__version__,
            command_history=self.runner.history,
            dry_run=self.options.dry_run,
            profile=self.options.profile,
        )
