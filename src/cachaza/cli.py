from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__
from .console import Console
from .credentials import load_credentials
from .external import doctor_rows
from .managed_tools import install_missing_tools
from .models import OriginConfig, TargetSpec
from .monitor import monitor_crtsh, monitor_gungnir
from .origin import render_origin_summary
from .pipeline import Pipeline, RunOptions
from .profiles import ACTIVE_STAGES, DEFAULT_PROFILE, PROFILES, profile_stages
from .reports import REPORT_FORMATS, build_key_findings, render_key_findings_console
from .safety import (
    ValidationError,
    build_target_spec,
    extract_domains,
    normalize_domain,
)
from .signatures import generate_signatures
from .sources import CLOUD_PROVIDERS, load_fingerprint_file
from .workspace import RunWorkspace
from .update import offer_update, perform_update


STAGE_HELP = {
    "corporate": "corporate/BGP/WHOIS intelligence handoff",
    "asn": "DNS, BGP Toolkit, RIPEstat, ARIN RDAP, and optional asnmap",
    "tenant": "Microsoft 365 related-domain discovery",
    "ct": "Certificate Transparency through Cert Spotter and crt.sh",
    "api": "passive Censys Platform, IntelX Phonebook, and urlscan enrichment with provider diagnostics",
    "certificates": "authorized certificate discovery with Caduceus",
    "subdomains": "passive, rate-limited Subfinder, Assetfinder, or BBOT enumeration",
    "dns": "authorized DNS validation with dnsx",
    "dns_enum": "authorized dnsenum/Fierce discovery with explicit zone-transfer warnings",
    "harvester": "authorized theHarvester organization, contact, host, API, and takeover discovery",
    "blackwidow": "authorized BlackWidow crawling and Inject-X candidate checks at the requested depth",
    "waf": "focused WAF fingerprinting with wafw00f, the single Nuclei waf-detect template, and optional Nmap",
    "shodan": "Karma/Shodan signatures and optional API queries",
    "ports": "authorized Naabu/Nmap discovery plus passive Smap intelligence",
    "http": "authorized HTTPX probing and technology fingerprinting",
    "cloud": "classification against public cloud range lists",
    "bypass": "candidate 403 bypass validation",
    "gau": "passive historical URL and sensitive-name discovery",
    "crawl": "authorized Katana/Cariddi endpoint crawling",
    "js": "authorized JavaScript URL and API endpoint inventory with JSMap Inspector",
    "policies": "authorized CSP and favicon analysis",
    "cve": "candidate CVE correlation from observed technologies",
    "active": "authorized httpx, naabu, Caduceus, or nmap adapters",
    "origin": "automatic Origin candidate discovery, scoring, and bounded Direct-origin validation",
}

PROFILE_HELP = """Profiles:
  passive  Default passive OSINT and historical sources; no direct target probing.
  safe     Passive discovery plus bounded DNS, TLS, port, and HTTP probes; requires -active.
  full     Safe reconnaissance plus GAU, crawling, JavaScript endpoint mapping, and focused WAF fingerprinting; requires -active."""

USEFUL_OPTIONS_HELP = """Useful options:
  -active        authorizes direct probes required by active stages and safe/full profiles
  -authorized    confirms permission for automatic Direct-origin validation
  -origin-auto   discovers, scores, selects, and verifies correlated origin candidates automatically
  -whois         enriches every unique public IP with registration information
  -wappalyzer    detects HTTP technologies; requires -active
  -s             runs passive Subfinder and Assetfinder subdomain discovery
  -harvester     gathers organization, contact, host, API, and takeover evidence; requires -active
  -blw LEVEL     runs BlackWidow at crawl depth LEVEL with verbose crawling and Inject-X; requires -active
  -dns-enum      runs dnsenum and Fierce and highlights successful AXFR; requires -active
  -w             detects WAFs with wafw00f and the single Nuclei waf-detect template; optional Nmap; requires -active
  -format all    writes HTML, JSON, TXT, PDF, and CSV reports
  -up/-update    updates Cachaza, prints the installed version, and runs doctor

Nuclei is restricted to the single WAF detection template.
Cachaza does not use Nuclei for vulnerability scanning."""

REMOVED_NUCLEI_STAGE_MESSAGE = (
    "The general Nuclei stage has been removed. Nuclei is only available through "
    "the WAF stage.\nUse: -stages waf -waf-tools nuclei -active"
)


class CombinedHelpAction(argparse.Action):
    """Show root help followed by the complete run option reference."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest, nargs=0, default=default, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        run_parser = getattr(parser, "_combined_run_parser", None)
        if run_parser is not None:
            print("\nComplete 'run' options (also included here so cachaza -h is sufficient):\n")
            run_parser.print_help()
        parser.exit()


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _report_formats(values: list[str] | None) -> list[str]:
    if not values:
        return ["json", "txt"]
    requested = {
        item.lower()
        for value in values
        for item in _csv(value)
    }
    unknown = requested - set(REPORT_FORMATS) - {"all"}
    if unknown:
        raise ValidationError(
            f"invalid -format: {', '.join(sorted(unknown))}; use html,json,txt,pdf,csv, or all"
        )
    if "all" in requested:
        return list(REPORT_FORMATS)
    if not requested:
        raise ValidationError("-format requires html, json, txt, pdf, csv, or all")
    return [value for value in REPORT_FORMATS if value in requested]


def _add_target_arguments(parser: argparse.ArgumentParser, *, require_domain: bool = False) -> None:
    parser.add_argument("-d", "-domain", dest="domain", action="append", default=[], help="root domain (repeatable)")
    if not require_domain:
        parser.add_argument("-a", "-asn", dest="asn", action="append", default=[], help="ASN, for example AS1234")
        parser.add_argument(
            "-org",
            action="append",
            default=[],
            help="optional organization hint; normally discovered from the domain",
        )
        parser.add_argument("-cidr", action="append", default=[], help="authorized CIDR (repeatable)")
        parser.add_argument(
            "-targets-file",
            action="append",
            default=[],
            help="file containing domain:, asn:, org:, or cidr: entries",
        )
        parser.add_argument("-exclude-domain", action="append", default=[], help="excluded domain")
        parser.add_argument("-exclude-cidr", action="append", default=[], help="excluded CIDR")


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-h", "-help", action=CombinedHelpAction, help="show this complete help message and exit")
    common.add_argument("-v", "-verbose", dest="verbose", action="count", default=argparse.SUPPRESS, help="show tool output and every finding; repeat for metadata")
    common.add_argument("-q", "-silent", dest="silent", action="store_true", default=argparse.SUPPRESS, help="suppress progress and verbose output")
    common.add_argument("-nc", "-no-color", dest="no_color", action="store_true", default=argparse.SUPPRESS, help="disable ANSI colors in console and report.txt")

    parser = argparse.ArgumentParser(
        prog="cachaza",
        description="Passive-first OSINT and authorized reconnaissance orchestrator for Kali Linux.",
        epilog=f"""Common run examples:
  cachaza run -d example.com -profile passive -o example-report -format all -v
  cachaza run -d example.com -profile safe -active -o example-safe -format all -v
  cachaza run -d example.com -profile full -active -o example-full -format all -v
  cachaza run -d example.com -o example-report -whois -format all -v
  cachaza run -d example.com -o example-report -active -wappalyzer -format all -v
  cachaza run -d example.com -o example-report -active -whois -wappalyzer -format all -v
  cachaza run -d example.com -s -harvester -dns-enum -w -active -o focused-report -format all -v
  cachaza run -d example.com -profile passive -s -whois -shodan-mode search -shodan-pages 5 -shodan-max-queries 200 -api-config config/providers.env -o max-passive -format all -v
  cachaza run -d example.com -profile full -active -s -harvester -dns-enum -w -blw 4 -whois -wappalyzer -shodan-mode search -shodan-pages 5 -shodan-max-queries 200 -api-config config/providers.env -o max-everything -format all -v

{PROFILE_HELP}

{USEFUL_OPTIONS_HELP}

`cachaza run -h` remains available as a shorter run-only view.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[common],
        add_help=False,
        allow_abbrev=False,
    )
    parser.add_argument("-version", action="version", version=f"%(prog)s {__version__}")
    parser.set_defaults(verbose=0, silent=False, no_color=False)
    parser.add_argument(
        "-up",
        "-update",
        dest="update",
        action="store_true",
        help="update Cachaza with git/pipx, then show the version and run doctor",
    )
    commands = parser.add_subparsers(dest="command")

    run = commands.add_parser(
        "run",
        parents=[common],
        add_help=False,
        allow_abbrev=False,
        help="execute the selected workflow and write normalized artifacts/reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""Examples:
  Passive:       cachaza run -d example.com -profile passive -o example-report -format all -v
  Safe:          cachaza run -d example.com -profile safe -active -o example-safe -format all -v
  Full:          cachaza run -d example.com -profile full -active -o example-full -format all -v
  WHOIS:        cachaza run -d example.com -o example-report -whois -format all -v
  Active:       cachaza run -d example.com -o example-report -active -format all -v
  Technologies: cachaza run -d example.com -o example-report -active -wappalyzer -format all -v
  Everything:   cachaza run -d example.com -o example-report -active -whois -wappalyzer -format all -v
  Focused OSINT: cachaza run -d example.com -s -harvester -dns-enum -w -active -o focused -format all -v
  Max passive:   cachaza run -d example.com -profile passive -s -whois -shodan-mode search -shodan-pages 5 -shodan-max-queries 200 -api-config config/providers.env -o max-passive -format all -v
  Max everything:cachaza run -d example.com -profile full -active -s -harvester -dns-enum -w -blw 4 -whois -wappalyzer -shodan-mode search -shodan-pages 5 -shodan-max-queries 200 -api-config config/providers.env -o max-everything -format all -v

{PROFILE_HELP}

{USEFUL_OPTIONS_HELP}

Reusing the same -o directory continues a compatible Cachaza run and preserves
its findings. Direct probes must be explicitly authorized with -active.""",
    )
    _add_target_arguments(run)
    run.add_argument(
        "-o",
        "-output",
        dest="output",
        help="new or existing compatible output directory; simple names are stored under ./output",
    )
    run.add_argument(
        "-format",
        "-report-format",
        dest="report_formats",
        action="append",
        help="reports: html,json,txt,pdf,csv, or all; accepts commas/repetition (default: json,txt)",
    )
    state = run.add_mutually_exclusive_group()
    state.add_argument(
        "-resume",
        action="store_true",
        help="require and resume an existing compatible -o workspace using stage checkpoints",
    )
    state.add_argument(
        "-fresh",
        action="store_true",
        help="safely reset an existing verified Cachaza workspace before running",
    )
    run.add_argument(
        "-profile",
        choices=tuple(PROFILES),
        default=DEFAULT_PROFILE,
        help="pipeline preset: passive (default), safe, or full; safe/full require -active",
    )
    run.add_argument(
        "-passive", dest="profile", action="store_const", const="passive",
        default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    run.add_argument(
        "-full", dest="profile", action="store_const", const="full",
        default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    run.add_argument(
        "-stages",
        default=None,
        help="override the selected profile with a comma-separated stage list",
    )
    run.add_argument("-skip-stages", default="", help="comma-separated stages to omit from the profile/override")
    run.add_argument("-dry-run", action="store_true", help="create plan/artifacts without network or tool execution")
    run.add_argument("-strict", action="store_true", help="stop on the first source failure")
    run.add_argument("-timeout", type=int, default=20, help="HTTP/TLS timeout in seconds (default: 20)")
    run.add_argument("-retries", type=int, default=2, help="HTTP retries (default: 2)")
    run.add_argument("-j", "-jobs", dest="jobs", type=int, default=2, help="concurrency, hard-capped at 2 (default: 2)")
    run.add_argument(
        "-subdomain-tools",
        default="auto",
        help="auto or list: subfinder,assetfinder,bbot",
    )
    run.add_argument(
        "-s",
        "-subdomains",
        dest="subdomains_bundle",
        action="store_true",
        help="ensure passive Subfinder + Assetfinder enumeration is included",
    )
    run.add_argument(
        "-subdomain-rate-limit",
        type=int,
        default=1,
        help="Subfinder requests per second (default: 1)",
    )
    run.add_argument(
        "-subdomain-threads",
        type=int,
        default=1,
        help="Subfinder resolver threads (default: 1)",
    )
    run.add_argument("-recursive-subdomains", action="store_true", help="enable recursive Subfinder mode")
    run.add_argument("-tenant-script", help="path to tenant-domains.sh")
    run.add_argument("-fingerprints", help="SHA-1 fingerprint file for Shodan signatures")
    run.add_argument("-api-config", help="optional KEY=value credential file parsed as data, never executed")
    run.add_argument(
        "-shodan-mode",
        choices=("off", "count", "search"),
        default="count",
        help="count avoids search credits; search retrieves results",
    )
    run.add_argument("-shodan-pages", type=int, default=1, help="pages in search mode (1-5)")
    run.add_argument("-shodan-max-queries", type=int, default=40, help="API query cap (default: 40)")
    run.add_argument(
        "-cloud-providers",
        default=",".join(CLOUD_PROVIDERS),
        help="providers to classify or 'none'",
    )
    run.add_argument("-active", action="store_true", help="enable authorized direct probes against explicit scope")
    run.add_argument(
        "-authorized",
        action="store_true",
        help="confirm permission to assess the domain and automatically correlated origin infrastructure",
    )
    origin = run.add_argument_group("Automatic Origin discovery and verification")
    origin.add_argument("-origin-auto", action="store_true", help="run automatic Origin candidate discovery; no IP input or per-IP approval is required")
    origin.add_argument("-origin-mode", choices=("passive", "balanced", "deep"), default="balanced", help="Origin discovery intensity (default: balanced)")
    origin.add_argument("-origin-auto-verify", action="store_true", default=True, help="automatically perform bounded Direct-origin validation when the mode permits it")
    origin.add_argument("-origin-min-auto-score", type=int, default=50, metavar="N")
    origin.add_argument("-origin-max-auto-candidates", type=int, default=None, metavar="N")
    origin.add_argument("-origin-stop-score", type=int, default=85, metavar="N")
    origin.add_argument("-origin-continue-after-match", action="store_true")
    origin.add_argument("-origin-ports", default="80,443", metavar="LIST")
    origin.add_argument("-origin-deep-ports", default="80,443,8000,8080,8443,8888", metavar="LIST")
    origin.add_argument("-origin-max-requests", type=int, default=None, metavar="N")
    origin.add_argument("-origin-max-requests-per-ip", type=int, default=None, metavar="N")
    origin.add_argument("-origin-rate-limit", type=float, default=1.0, metavar="N", help="direct Origin requests per second (maximum: 2; default: 1)")
    origin.add_argument("-origin-concurrency", type=int, default=None, metavar="N", help="direct Origin network workers (maximum/default: 2)")
    origin.add_argument("-origin-connect-timeout", type=float, default=5.0, metavar="N")
    origin.add_argument("-origin-total-timeout", type=float, default=12.0, metavar="N")
    origin.add_argument("-origin-body-limit", type=int, default=2_097_152, metavar="N")
    origin.add_argument("-origin-max-redirects", type=int, default=5, metavar="N")
    origin.add_argument("-origin-max-paths", type=int, default=None, metavar="N")
    origin.add_argument("-origin-path", action="append", default=[], metavar="PATH")
    origin.add_argument("-origin-use-observed-paths", action="store_true")
    origin.add_argument("-origin-use-favicon", action="store_true", default=True)
    origin.add_argument("-origin-use-static-resources", action="store_true", default=True)
    origin.add_argument("-origin-tls", action="store_true", default=True)
    origin.add_argument("-origin-jarm", action="store_true", default=None)
    origin.add_argument("-origin-dns-permutations", action="store_true")
    origin.add_argument("-origin-max-permutations", type=int, default=None, metavar="N")
    origin.add_argument("-origin-historical-dns", action="store_true", default=True)
    origin.add_argument("-origin-max-history-results", type=int, default=100, metavar="N")
    origin.add_argument("-origin-query-engines", default="virustotal,securitytrails,censys,shodan,urlscan,uncover", metavar="LIST")
    origin.add_argument("-origin-exclude-provider", action="append", default=[], metavar="LIST")
    origin.add_argument("-origin-exclude-cidr", dest="origin_exclude_cidr_file", metavar="FILE")
    origin.add_argument("-origin-include-cidr", dest="origin_include_cidr_file", metavar="FILE")
    origin.add_argument("-origin-save-bodies", action="store_true")
    origin.add_argument("-origin-no-direct-validation", action="store_true", help="discover and rank candidates without contacting candidate IPs")
    run.add_argument(
        "-whois",
        action="store_true",
        help="query WHOIS once for each unique public IP and save results under rest/",
    )
    run.add_argument(
        "-wappalyzer",
        action="store_true",
        help="detect web technologies with httpx Wappalyzer fingerprints (requires -active)",
    )
    run.add_argument(
        "-active-tools",
        default="httpx,naabu,caduceus",
        help="list: httpx,naabu,caduceus,nmap",
    )
    run.add_argument("-port-tools", default="naabu,smap", help="list: naabu,smap,nmap")
    run.add_argument("-crawl-tools", default="auto", help="auto or list: katana,cariddi")
    run.add_argument("-ports", default="80,443,8080,8443", help="ports for active tools")
    run.add_argument("-rate-limit", type=int, default=2, help="requests/packets per second, hard-capped at 2")
    run.add_argument("-max-active-hosts", type=int, default=4096, help="active address limit")
    run.add_argument(
        "-allow-large-ranges",
        action="store_true",
        help="allow ranges above the host limit (requires -active)",
    )
    run.add_argument("-max-crawl-urls", type=int, default=50)
    run.add_argument("-jsmap-path", help="explicit JSMap Inspector executable or Python script")
    run.add_argument("-csp-stalker-path", help="explicit CSP Stalker executable or Python script")
    run.add_argument(
        "-w",
        "-waf",
        dest="waf",
        action="store_true",
        help=(
            "detect and fingerprint WAFs using wafw00f and the single Nuclei "
            "waf-detect template; optional Nmap correlation (requires -active)"
        ),
    )
    run.add_argument(
        "-waf-tools",
        default="wafw00f,nuclei",
        help="WAF adapters: wafw00f,nuclei,nmap",
    )
    run.add_argument(
        "-harvester",
        dest="harvester",
        action="store_true",
        help="run theHarvester with Shodan/API/takeover checks (requires -active)",
    )
    run.add_argument(
        "-harvester-source",
        default="all",
        help="theHarvester -b source (default: all)",
    )
    run.add_argument(
        "-harvester-limit",
        type=int,
        default=500,
        help="theHarvester result limit (default: 500)",
    )
    run.add_argument(
        "-harvester-dns-server",
        help="optional DNS server passed to theHarvester -e",
    )
    run.add_argument(
        "-dns-enum",
        dest="dns_enum",
        action="store_true",
        help="run dnsenum and Fierce and flag accepted zone transfers (requires -active)",
    )
    run.add_argument(
        "-dns-enum-tools",
        default="dnsenum,fierce",
        help="DNS enumeration adapters: dnsenum,fierce",
    )
    run.add_argument(
        "-blw",
        dest="blackwidow_depth",
        type=int,
        metavar="LEVEL",
        help="run BlackWidow with -l LEVEL -v y -s y against each root (1-10; requires -active)",
    )
    run.add_argument(
        "-blackwidow-path",
        help="explicit BlackWidow executable; otherwise Cachaza uses/installs a pinned user-space copy",
    )

    plan = commands.add_parser("plan", parents=[common], add_help=False, allow_abbrev=False, help="validate scope and preview stages without network calls or files")
    _add_target_arguments(plan)
    plan.add_argument("-profile", choices=tuple(PROFILES), default=DEFAULT_PROFILE)
    plan.add_argument("-stages", default=None)
    plan.add_argument("-skip-stages", default="")
    plan.add_argument("-active", action="store_true", help="include the active branch in the plan")
    plan.add_argument("-json", action="store_true", help="JSON output")

    signatures = commands.add_parser(
        "signatures", parents=[common], add_help=False, allow_abbrev=False, help="build Karma/Shodan queries from domains, organizations, or fingerprints"
    )
    _add_target_arguments(signatures, require_domain=True)
    signatures.add_argument("-org", action="append", default=[], help="organization (repeatable)")
    signatures.add_argument("-fingerprints", help="SHA-1 fingerprint file")
    signatures.add_argument("-o", "-output", dest="output", help="output file (default: stdout)")
    signatures.add_argument("-json", action="store_true", help="JSONL instead of name::query")

    normalize = commands.add_parser(
        "normalize", parents=[common], add_help=False, allow_abbrev=False, help="extract, validate, filter, sort, and deduplicate domains from text/JSON"
    )
    normalize.add_argument("-i", "-input", dest="input", action="append", default=[], help="input file; without -i reads stdin")
    normalize.add_argument("-r", "-root", dest="root", action="append", default=[], help="filter by root (repeatable)")
    normalize.add_argument("-o", "-output", dest="output", help="output file (default: stdout)")

    monitor = commands.add_parser(
        "monitor", parents=[common], add_help=False, allow_abbrev=False, help="persistently monitor CT with Gungnir or Cert Spotter/crt.sh polling"
    )
    _add_target_arguments(monitor, require_domain=True)
    monitor.add_argument("-o", "-output", dest="output", default="monitor-output", help="state/output directory")
    monitor.add_argument("-backend", choices=("auto", "gungnir", "crtsh"), default="auto")
    monitor.add_argument("-interval", type=int, default=300, help="polling interval, minimum 60 seconds")
    monitor.add_argument("-once", action="store_true", help="run one polling iteration and exit")
    monitor.add_argument("-timeout", type=int, default=20)
    monitor.add_argument("-retries", type=int, default=2)

    doctor = commands.add_parser("doctor", parents=[common], add_help=False, allow_abbrev=False, help="report optional tool paths and credential availability")
    doctor.add_argument("-api-config", help="KEY=value provider file to inspect in addition to the environment")
    doctor.add_argument(
        "-install",
        action="store_true",
        help="install every missing tool with an approved user-space Go, pipx, or Cachaza recipe",
    )
    parser._combined_run_parser = run
    return parser


def _target_from_args(args: argparse.Namespace) -> TargetSpec:
    return build_target_spec(
        domains=args.domain,
        asns=getattr(args, "asn", []),
        organizations=getattr(args, "org", []),
        cidrs=getattr(args, "cidr", []),
        target_files=getattr(args, "targets_file", []),
        exclude_domains=getattr(args, "exclude_domain", []),
        exclude_cidrs=getattr(args, "exclude_cidr", []),
    )


def _validate_ports(value: str) -> str:
    if not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise ValidationError("-ports must contain comma-separated port numbers or ranges")
    for item in value.split(","):
        ends = [int(part) for part in item.split("-")]
        if any(port < 1 or port > 65535 for port in ends) or (len(ends) == 2 and ends[0] > ends[1]):
            raise ValidationError(f"invalid port or range: {item}")
    return value


def _origin_port_list(value: str, option: str) -> list[int]:
    if not re.fullmatch(r"\d+(?:,\d+)*", value):
        raise ValidationError(f"{option} must contain comma-separated web port numbers")
    ports = list(dict.fromkeys(int(item) for item in value.split(",")))
    if not ports or len(ports) > 12 or any(port < 1 or port > 65535 for port in ports):
        raise ValidationError(f"{option} must contain 1-12 ports between 1 and 65535")
    return ports


def _origin_config_from_args(args: argparse.Namespace) -> OriginConfig:
    deep = args.origin_mode == "deep"
    excluded = [
        item
        for raw in args.origin_exclude_provider
        for item in _csv(raw)
    ]
    return OriginConfig(
        mode=args.origin_mode,
        auto_verify=args.origin_auto_verify,
        minimum_score=args.origin_min_auto_score,
        maximum_candidates=args.origin_max_auto_candidates if args.origin_max_auto_candidates is not None else (20 if deep else 10),
        stop_score=args.origin_stop_score,
        continue_after_match=args.origin_continue_after_match,
        ports=_origin_port_list(args.origin_ports, "-origin-ports"),
        deep_ports=_origin_port_list(args.origin_deep_ports, "-origin-deep-ports"),
        maximum_total_requests=args.origin_max_requests if args.origin_max_requests is not None else (100 if deep else 40),
        maximum_requests_per_ip=args.origin_max_requests_per_ip if args.origin_max_requests_per_ip is not None else (10 if deep else 6),
        rate_limit_per_second=args.origin_rate_limit,
        maximum_concurrency=args.origin_concurrency if args.origin_concurrency is not None else 2,
        connect_timeout=args.origin_connect_timeout,
        total_timeout=args.origin_total_timeout,
        maximum_body_bytes=args.origin_body_limit,
        maximum_redirects=args.origin_max_redirects,
        maximum_paths=args.origin_max_paths if args.origin_max_paths is not None else (5 if deep else 3),
        paths=list(args.origin_path),
        use_observed_paths=args.origin_use_observed_paths,
        use_favicon=args.origin_use_favicon,
        use_static_resources=args.origin_use_static_resources,
        tls=args.origin_tls,
        jarm=args.origin_jarm if args.origin_jarm is not None else deep,
        dns_permutations=args.origin_dns_permutations,
        maximum_permutations=args.origin_max_permutations if args.origin_max_permutations is not None else (50_000 if deep else 10_000),
        historical_dns=args.origin_historical_dns,
        maximum_history_results=args.origin_max_history_results,
        query_engines=_csv(args.origin_query_engines),
        exclude_providers=excluded,
        exclude_cidr_file=args.origin_exclude_cidr_file,
        include_cidr_file=args.origin_include_cidr_file,
        save_bodies=args.origin_save_bodies,
        direct_validation=(
            args.origin_mode != "passive"
            and not args.origin_no_direct_validation
            and args.origin_auto_verify
        ),
        authorized=args.authorized,
    )


def _validate_origin_config(config: OriginConfig) -> None:
    checks = (
        (0 <= config.minimum_score <= 100, "-origin-min-auto-score must be between 0 and 100"),
        (1 <= config.maximum_candidates <= 100, "-origin-max-auto-candidates must be between 1 and 100"),
        (1 <= config.stop_score <= 100, "-origin-stop-score must be between 1 and 100"),
        (1 <= config.maximum_total_requests <= 500, "-origin-max-requests must be between 1 and 500"),
        (1 <= config.maximum_requests_per_ip <= 25, "-origin-max-requests-per-ip must be between 1 and 25"),
        (0 < config.rate_limit_per_second <= 2, "-origin-rate-limit must be greater than 0 and at most 2"),
        (1 <= config.maximum_concurrency <= 2, "-origin-concurrency must be between 1 and 2"),
        (0.1 <= config.connect_timeout <= 60, "-origin-connect-timeout must be between 0.1 and 60"),
        (0.5 <= config.total_timeout <= 120, "-origin-total-timeout must be between 0.5 and 120"),
        (1_024 <= config.maximum_body_bytes <= 10_485_760, "-origin-body-limit must be between 1024 and 10485760"),
        (0 <= config.maximum_redirects <= 10, "-origin-max-redirects must be between 0 and 10"),
        (1 <= config.maximum_paths <= 10, "-origin-max-paths must be between 1 and 10"),
        (1 <= config.maximum_permutations <= 100_000, "-origin-max-permutations must be between 1 and 100000"),
        (1 <= config.maximum_history_results <= 500, "-origin-max-history-results must be between 1 and 500"),
        (bool(config.query_engines), "-origin-query-engines cannot be empty"),
    )
    for valid, message in checks:
        if not valid:
            raise ValidationError(message)
    for path in config.paths:
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValidationError("-origin-path must be an absolute public path without query or fragment")


def _validate_run_args(args: argparse.Namespace, target: TargetSpec) -> None:
    if target.empty:
        raise ValidationError("provide at least one domain, ASN, organization, or CIDR")
    requested_stages = _csv(args.stages) if args.stages else profile_stages(args.profile)
    if "nuclei" in requested_stages:
        raise ValidationError(REMOVED_NUCLEI_STAGE_MESSAGE)
    if args.origin_auto:
        if not target.domains:
            raise ValidationError("-origin-auto requires at least one -d domain")
        config = _origin_config_from_args(args)
        _validate_origin_config(config)
        if args.active and not args.authorized:
            raise ValidationError(
                "Automatic origin validation requires explicit authorization.\n"
                "Use -authorized only when you own the target or have permission to assess it."
            )
        if config.direct_validation and (not args.active or not args.authorized):
            raise ValidationError(
                "Automatic Direct-origin validation in balanced/deep mode requires -active -authorized"
            )
    if args.allow_large_ranges and not args.active:
        raise ValidationError("-allow-large-ranges is valid only with -active")
    if args.wappalyzer and not args.active:
        raise ValidationError("-wappalyzer performs direct HTTP probes and requires -active")
    requested_bundles = [
        name
        for enabled, name in (
            (args.waf, "-w"),
            (args.harvester, "-harvester"),
            (args.dns_enum, "-dns-enum"),
            (args.blackwidow_depth is not None, "-blw"),
        )
        if enabled
    ]
    if requested_bundles and not args.active:
        raise ValidationError(
            f"{', '.join(requested_bundles)} perform direct checks and require -active"
        )
    if PROFILES[args.profile].requires_active and not args.active:
        raise ValidationError(
            f"-profile {args.profile} selects direct-contact stages and requires -active"
        )
    if not 1 <= args.timeout <= 300:
        raise ValidationError("-timeout must be between 1 and 300")
    if not 0 <= args.retries <= 10:
        raise ValidationError("-retries must be between 0 and 10")
    if not 1 <= args.jobs <= 2:
        raise ValidationError("-jobs must be between 1 and 2; Cachaza enforces a hard concurrency ceiling of 2")
    if not 1 <= args.rate_limit <= 2:
        raise ValidationError("-rate-limit must be between 1 and 2; Cachaza never permits more than 2 requests/packets per second")
    if not 1 <= args.max_active_hosts <= 1_000_000:
        raise ValidationError("-max-active-hosts must be between 1 and 1000000")
    if not 1 <= args.shodan_pages <= 5:
        raise ValidationError("-shodan-pages must be between 1 and 5")
    if not 1 <= args.shodan_max_queries <= 200:
        raise ValidationError("-shodan-max-queries must be between 1 and 200")
    if not 1 <= args.max_crawl_urls <= 5000:
        raise ValidationError("-max-crawl-urls must be between 1 and 5000")
    if not 1 <= args.subdomain_rate_limit <= 2:
        raise ValidationError("-subdomain-rate-limit must be between 1 and 2")
    if not 1 <= args.subdomain_threads <= 2:
        raise ValidationError("-subdomain-threads must be between 1 and 2")
    if not 1 <= args.harvester_limit <= 5000:
        raise ValidationError("-harvester-limit must be between 1 and 5000")
    if args.blackwidow_depth is not None and not 1 <= args.blackwidow_depth <= 10:
        raise ValidationError("-blw LEVEL must be between 1 and 10")
    _validate_ports(args.ports)
    active_without_gate = sorted(set(requested_stages) & ACTIVE_STAGES) if not args.active else []
    if active_without_gate:
        raise ValidationError(
            f"active stages require -active: {', '.join(active_without_gate)}"
        )
    if args.resume and not args.output:
        raise ValidationError("-resume requires an explicit -o workspace")


def _run_output_root(value: str) -> Path:
    requested = Path(value).expanduser()
    if not requested.is_absolute() and requested.parent == Path("."):
        return (Path.cwd() / "output" / requested.name).resolve()
    return requested.resolve()


def _prepare_run_output(
    output: str | None,
    resume_requested: bool,
    fresh_requested: bool,
    target: TargetSpec,
) -> tuple[str | None, bool]:
    """Resolve -o and safely continue an existing compatible workspace."""
    requested_value = output
    if not requested_value:
        return None, False
    root = _run_output_root(requested_value)
    if root.exists() and not root.is_dir():
        raise ValidationError(f"output path exists and is not a directory: {root}")
    if not root.exists() or not any(root.iterdir()):
        if resume_requested:
            raise ValidationError(f"resume directory does not exist or is empty: {root}")
        return str(root), False

    scope_file = root / "rest" / "scope.json"
    if not scope_file.is_file():
        legacy_scope = root / "scope.json"
        if legacy_scope.is_file():
            scope_file = legacy_scope
    if not scope_file.is_file():
        raise ValidationError(
            f"existing -o directory is not a Cachaza workspace (rest/scope.json is missing): {root}"
        )
    try:
        previous_scope = json.loads(scope_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError(f"scope.json is invalid in existing -o directory: {root}") from exc
    if previous_scope != target.to_dict():
        raise ValidationError(
            "scope does not match the existing -o run; choose another -o directory to change scope"
        )
    if fresh_requested:
        try:
            RunWorkspace.reset_verified(root, target)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        return str(root), False
    return str(root), True


def command_run(args: argparse.Namespace, console: Console) -> int:
    target = _target_from_args(args)
    _validate_run_args(args, target)
    stages = _csv(args.stages) if args.stages else profile_stages(args.profile)
    for enabled, name in (
        (args.subdomains_bundle, "subdomains"),
        (args.harvester, "harvester"),
        (args.dns_enum, "dns_enum"),
        (args.waf, "waf"),
        (args.blackwidow_depth is not None, "blackwidow"),
        (args.origin_auto, "origin"),
    ):
        if enabled and name not in stages:
            stages.append(name)
    skipped_stages = set(_csv(args.skip_stages))
    stages = [name for name in stages if name not in skipped_stages]
    unknown_stages = set(stages) - set(STAGE_HELP)
    if unknown_stages:
        raise ValidationError(f"unknown stages: {', '.join(sorted(unknown_stages))}")
    providers = [] if args.cloud_providers.strip().lower() == "none" else _csv(args.cloud_providers)
    report_formats = _report_formats(args.report_formats)
    active_tools = _csv(args.active_tools)
    allowed_active = {"httpx", "naabu", "caduceus", "nmap"}
    if set(active_tools) - allowed_active:
        raise ValidationError("-active-tools contains an unsupported adapter")
    port_tools = _csv(args.port_tools)
    if set(port_tools) - {"naabu", "smap", "nmap"}:
        raise ValidationError("-port-tools contains an unsupported adapter")
    crawl_tools = _csv(args.crawl_tools)
    if set(crawl_tools) - {"auto", "katana", "cariddi"}:
        raise ValidationError("-crawl-tools contains an unsupported adapter")
    waf_tools = _csv(args.waf_tools)
    if not waf_tools or set(waf_tools) - {"wafw00f", "nuclei", "nmap"}:
        raise ValidationError("-waf-tools must contain wafw00f,nuclei, and/or nmap")
    dns_enum_tools = _csv(args.dns_enum_tools)
    if not dns_enum_tools or set(dns_enum_tools) - {"dnsenum", "fierce"}:
        raise ValidationError("-dns-enum-tools must contain dnsenum and/or fierce")
    output, resume = _prepare_run_output(args.output, args.resume, args.fresh, target)
    workspace = RunWorkspace.create(output, target, resume=resume)
    origin_config = _origin_config_from_args(args) if args.origin_auto else None
    options = RunOptions(
        stages=stages,
        profile=args.profile,
        timeout=args.timeout,
        retries=args.retries,
        jobs=args.jobs,
        dry_run=args.dry_run,
        strict=args.strict,
        recursive_subdomains=args.recursive_subdomains,
        subdomain_tools=(
            ["subfinder", "assetfinder"]
            if args.subdomains_bundle and args.subdomain_tools == "auto"
            else _csv(args.subdomain_tools)
        ),
        subdomain_rate_limit=args.subdomain_rate_limit,
        subdomain_threads=args.subdomain_threads,
        tenant_script=args.tenant_script,
        fingerprints_file=args.fingerprints,
        shodan_mode=args.shodan_mode,
        shodan_pages=args.shodan_pages,
        shodan_max_queries=args.shodan_max_queries,
        cloud_providers=providers,
        active=args.active,
        active_tools=active_tools,
        ports=args.ports,
        rate_limit=args.rate_limit,
        max_active_hosts=args.max_active_hosts,
        allow_large_ranges=args.allow_large_ranges,
        report_formats=report_formats,
        report_color=not args.no_color,
        whois=args.whois,
        wappalyzer=args.wappalyzer,
        api_config=args.api_config,
        port_tools=port_tools,
        crawl_tools=crawl_tools,
        max_crawl_urls=args.max_crawl_urls,
        jsmap_path=args.jsmap_path,
        csp_stalker_path=args.csp_stalker_path,
        waf_tools=waf_tools,
        harvester_source=args.harvester_source,
        harvester_limit=args.harvester_limit,
        harvester_dns_server=args.harvester_dns_server,
        dns_enum_tools=dns_enum_tools,
        blackwidow_depth=args.blackwidow_depth,
        blackwidow_path=args.blackwidow_path,
        origin=origin_config,
    )
    root = Pipeline(target, workspace, options, console).execute()
    if not args.silent:
        print(f"Output directory: {root}")
        for report_format in report_formats:
            report = root / f"report.{report_format}"
            if report.is_file():
                print(f"{report_format.upper()} report: {report}")
        print(f"Supporting artifacts: {root / 'rest'}")
        print(render_key_findings_console(build_key_findings(workspace.findings), color=not args.no_color))
        origin_ranking = root / "rest" / "origin" / "final-ranking.json"
        if origin_ranking.is_file():
            try:
                ranking = json.loads(origin_ranking.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                ranking = {}
            if ranking:
                print("\n" + render_origin_summary(ranking))
        html_report = root / "report.html"
        if html_report.is_file():
            print(
                "\nRecommended next step: open the HTML report; it contains the richest "
                f"interactive analysis:\n  {html_report}"
            )
        else:
            print(
                "\nRecommended next step: generate and open report.html with -format html "
                "or -format all; it contains the richest interactive analysis."
            )
    return 0


def command_plan(args: argparse.Namespace) -> int:
    target = _target_from_args(args)
    if target.empty:
        raise ValidationError("provide at least one target")
    stages = _csv(args.stages) if args.stages else profile_stages(args.profile)
    if "nuclei" in stages:
        raise ValidationError(REMOVED_NUCLEI_STAGE_MESSAGE)
    skipped = set(_csv(args.skip_stages))
    stages = [name for name in stages if name not in skipped]
    unknown = set(stages) - set(STAGE_HELP)
    if unknown:
        raise ValidationError(f"unknown stages: {', '.join(sorted(unknown))}")
    data = {
        "scope": target.to_dict(),
        "passive_by_default": True,
        "domain_only_ready": bool(target.domains),
        "automatic_discovery": ["DNS", "bgp.he.net", "RIPEstat", "ARIN RDAP"],
        "organization_hint_optional": True,
        "active_requested": args.active,
        "profile": args.profile,
        "stages": [{"name": name, "description": STAGE_HELP[name]} for name in stages],
        "active_guard": "-active" if args.active else None,
    }
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        print("Scope:")
        print(json.dumps(target.to_dict(), indent=2, ensure_ascii=False))
        print("\nWorkflow:")
        for index, item in enumerate(data["stages"], 1):
            suffix = " (blocked without -active)" if item["name"] in ACTIVE_STAGES and not args.active else ""
            print(f"  {index}. {item['name']}: {item['description']}{suffix}")
        if target.domains:
            print("\nASN and network holders are discovered automatically; -org and -asn are optional.")
        if args.active:
            print("\n-active enables direct probes with rate, scope, and host-count limits.")
    return 0


def command_signatures(args: argparse.Namespace) -> int:
    domains = [normalize_domain(item) for item in args.domain]
    if not domains and not args.org and not args.fingerprints:
        raise ValidationError("provide -domain, -org, or -fingerprints")
    fingerprints = load_fingerprint_file(args.fingerprints)
    values = generate_signatures(domains, args.org, fingerprints)
    if args.json:
        lines = [json.dumps({"id": item.identifier, "name": item.name, "query": item.query}, sort_keys=True) for item in values]
    else:
        lines = [item.as_line() for item in values]
    payload = "\n".join(lines) + ("\n" if lines else "")
    if args.output:
        Path(args.output).expanduser().write_text(payload, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(payload)
    return 0


def command_normalize(args: argparse.Namespace) -> int:
    roots = [normalize_domain(item) for item in args.root]
    chunks: list[str] = []
    if args.input:
        for filename in args.input:
            path = Path(filename).expanduser()
            if not path.is_file():
                raise ValidationError(f"file does not exist: {path}")
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    else:
        chunks.append(sys.stdin.read())
    values = extract_domains("\n".join(chunks), roots or None)
    payload = "\n".join(values) + ("\n" if values else "")
    if args.output:
        Path(args.output).expanduser().write_text(payload, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(payload)
    return 0


def command_monitor(args: argparse.Namespace, console: Console) -> int:
    domains = list(dict.fromkeys(normalize_domain(item) for item in args.domain))
    if not domains:
        raise ValidationError("monitor requires at least one -domain")
    if args.interval < 60:
        raise ValidationError("-interval must be at least 60 seconds")
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    backend = args.backend
    if backend == "auto":
        from .external import find_tool

        backend = "gungnir" if find_tool("gungnir") and not args.once else "crtsh"
    if backend == "gungnir":
        if args.once:
            raise ValidationError("-once is available only with the polling backend")
        return monitor_gungnir(domains, output, console)
    return monitor_crtsh(
        domains,
        output,
        console,
        interval=args.interval,
        once=args.once,
        timeout=args.timeout,
        retries=args.retries,
    )


def command_doctor(args: argparse.Namespace, console: Console) -> int:
    install_failures = 0
    if args.install:
        console.info("Installing missing supported tools in the current user's home directory")
        for result in install_missing_tools():
            if result.status == "installed":
                console.info(f"{result.name} installed: {result.detail}")
            elif result.status == "failed":
                install_failures += 1
                console.warn(f"{result.name} installation failed: {result.detail}")
            else:
                console.debug(f"{result.name} already ready: {result.detail}")
    credentials = load_credentials(args.api_config)
    print(f"{'COMPONENT':<24} {'STATUS':<10} PATH/SOURCE")
    print(f"{'-' * 24} {'-' * 10} {'-' * 30}")
    for name, status, location in doctor_rows(credentials):
        print(f"{name:<24} {status:<10} {location}")
    print("\nReportLab and the bounded JSMap analyzer ship with Cachaza; external adapters are verified above.")
    print("Credential 'ok' means present, not accepted by the provider; run artifacts record API responses.")
    print(
        "Use 'cachaza doctor -install' to install missing supported user-space tools; "
        "Kali system packages remain under apt/sudo control."
    )
    return 2 if install_failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    raw_args = list(argv) if argv is not None else sys.argv[1:]
    normalized_args = [
        "-" + item[2:] if item.startswith("--") and item != "--" else item
        for item in raw_args
    ]
    command_names = {"run", "plan", "signatures", "normalize", "monitor", "doctor"}
    command_index = next(
        (index for index, item in enumerate(normalized_args) if item in command_names),
        None,
    )
    if command_index is not None and command_index > 0:
        movable = {"-v", "-verbose", "-q", "-silent", "-nc", "-no-color"}
        before = normalized_args[:command_index]
        global_flags = [item for item in before if item in movable]
        remaining = [item for item in before if item not in movable]
        normalized_args = (
            remaining
            + [normalized_args[command_index]]
            + global_flags
            + normalized_args[command_index + 1 :]
        )
    args = parser.parse_args(normalized_args)
    console = Console(verbose=args.verbose, silent=args.silent, color=not args.no_color)
    try:
        console.banner(__version__)
        if args.update:
            if args.command:
                raise ValidationError("-update cannot be combined with a command")
            return perform_update(console)
        if not args.command:
            parser.error("a command is required (run, plan, signatures, normalize, monitor, or doctor)")
        if argv is None:
            update_status = offer_update(console)
            if update_status is not None:
                return update_status
        if args.command == "run":
            return command_run(args, console)
        if args.command == "plan":
            return command_plan(args)
        if args.command == "signatures":
            return command_signatures(args)
        if args.command == "normalize":
            return command_normalize(args)
        if args.command == "monitor":
            return command_monitor(args, console)
        if args.command == "doctor":
            return command_doctor(args, console)
        parser.error("unknown command")
    except (ValidationError, ValueError, OSError, RuntimeError) as exc:
        console.error(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
