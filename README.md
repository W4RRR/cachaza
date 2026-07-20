# Cachaza

> Passive-first OSINT and authorized reconnaissance orchestration for Kali Linux.

Cachaza turns a domain or an explicitly approved network scope into a reproducible reconnaissance workspace. It keeps every observation in one normalized `Finding` model, preserves provenance, separates authorized scope from candidate intelligence, and produces self-contained reports with a relationship graph.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94.svg)](https://www.kali.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Features

- Passive-first operation with `passive`, `safe`, and `full` profiles.
- Explicit `-active` authorization gate for every direct-contact stage.
- Automatic Origin candidate discovery, explainable scoring, and bounded Direct-origin validation with `-origin-auto`.
- Automatic DNS, ASN, prefix, registry, and network-holder enrichment.
- Passive discovery through Certificate Transparency, Censys Platform, IntelX Phonebook, urlscan, Shodan, Subfinder providers, and historical URL archives.
- Bounded active adapters for dnsx, Caduceus, Naabu, Nmap, httpx, 403jump, Katana, endpoint-only Cariddi, the bundled source-map analyzer, CSP Stalker, Favicorn, and Vulnx.
- Focused WAF identification with wafw00f and Nuclei's single `http/technologies/waf-detect.yaml` template; Nmap NSE is optional correlation.
- Endpoint inventories from GAU, Katana, Cariddi, JavaScript analysis, and existing passive sources. Nuclei never participates in endpoint discovery or vulnerability scanning.
- Focused `-harvester` theHarvester contact/API discovery and `-dns-enum` dnsenum/Fierce enumeration with prominent zone-transfer warnings.
- Authorized `-blw LEVEL` BlackWidow crawling and Inject-X candidate checks, normalized without presenting candidates as confirmed vulnerabilities.
- Conservative `-s` Subfinder + Assetfinder enumeration with normalized, deduplicated names.
- Normalized findings with `stage`, `source`, `kind`, `value`, `in_scope`, `metadata`, and `observed_at`.
- HTML, JSON, TXT, PDF, and CSV reports with executive key findings and a relationship explorer that previews nodes on hover.
- Resume checkpoints and safe fresh-run handling inside a verified workspace.
- Startup version checks plus an explicit `cachaza -update`/`-up` workflow.
- HTML escaping and Content Security Policy protection, plus CSV formula-injection neutralization.

## Authorized use only

Use Cachaza only against systems you own or are explicitly authorized to assess. A domain-derived ASN, prefix, IP, tenant, cloud range, or search result is contextual intelligence; it is not proof of ownership and never expands active scope automatically.

Direct probes require `-active`. Large network ranges also remain subject to the configured host limit unless `-allow-large-ranges` is deliberately supplied.

## Install on Kali

```bash
sudo apt update
sudo apt install -y git golang-go pipx python3-venv
pipx ensurepath

mkdir -p ~/tools
git clone https://github.com/W4RRR/cachaza.git ~/tools/cachaza
cd ~/tools/cachaza
pipx install .

cachaza -version
cachaza doctor -install
cachaza doctor
```

## Startup banner and updates

Interactive commands display the cocktail first, followed by the full Cachaza wordmark, project attribution, and installed version:

```text
                             .-========-.
                              \   o   /
                               \     /
                                `---'
                                  ||
                                  ||
                                __||__
                               /______\

_________     _____  _________   ___ ___    _____  __________  _____
\_   ___ \   /  _  \ \_   ___ \ /   |   \  /  _  \ \____    / /  _  \
/    \  \/  /  /_\  \/    \  \//    ~    \/  /_\  \  /     / /  /_\  \
\     \____/    |    \     \___\    Y    /    |    \/     /_/    |    \
 \______  /\____|__  /\______  /\___|_  /\____|__  /_______ \____|__  /
        \/         \/        \/       \/         \/        \/       \/
                   github.com/W4RRR/cachaza by W4RRR
                                v0.10.2
```

`-silent` suppresses the banner together with progress and findings. Cachaza checks the public GitHub version at most once every 24 hours. If a newer release is found in an interactive terminal, it offers `Update now? [Y/n]`. Non-interactive jobs are never blocked by a prompt; they receive the update command instead. Disable the network check for controlled/offline environments with `CACHAZA_SKIP_UPDATE_CHECK=1`.

Update explicitly at any time:

```bash
cachaza -up
# equivalent
cachaza -update
```

From a Git checkout this performs the safe fast-forward workflow and then verifies the installation:

```bash
git pull --ff-only origin main && \
pipx install --force . && \
cachaza -version && \
cachaza doctor
```

For a pipx installation without a local checkout, Cachaza reinstalls directly from `https://github.com/W4RRR/cachaza.git`. It never runs a merge, reset, or destructive Git command.

## Quick start

The default profile is passive:

```bash
cachaza plan -d example.com
cachaza run -d example.com -o example-passive -format all -v
```

Preview all stages without running them:

```bash
cachaza plan -d example.com -profile full
```

Run the bounded safe profile after authorization:

```bash
cachaza run -d example.com \
  -profile safe -active \
  -o example-safe -format all -v
```

Run the complete authorized workflow:

```bash
cachaza run -d example.com \
  -profile full -active \
  -o example-full -format all -v
```

Maximum passive collection (no application/network scanning, but it can consume Shodan search credits):

```bash
cachaza run -d example.com -profile passive -s -whois \
  -shodan-mode search -shodan-pages 5 -shodan-max-queries 200 \
  -api-config config/providers.env \
  -o max-passive -format all -v
```

Maximum authorized workflow, including every focused bundle and BlackWidow depth 4:

```bash
cachaza run -d example.com -profile full -active -s \
  -harvester -dns-enum -w -blw 4 -whois -wappalyzer \
  -shodan-mode search -shodan-pages 5 -shodan-max-queries 200 \
  -api-config config/providers.env \
  -o max-everything -format all -v
```

The second command is deliberately noisy, can take a long time, consumes provider credits, crawls the site, and performs active candidate checks. Use it only with written authorization. `-profile full` already includes the focused `waf` stage with its safe default tools, so `-w` is redundant here but documents intent. The profile does not implicitly enable `-harvester`, `-dns-enum`, or `-blw`.

## Automatic Origin discovery

`-origin-auto` runs the complete Origin discovery pipeline without asking the operator to supply or approve individual IP addresses. Passive evidence is collected and normalized first; impossible, CDN, private, mail-only, and unrelated third-party candidates are rejected; remaining candidates receive a deterministic score. Direct-origin validation is permitted only after the engagement-wide `-active -authorized` acknowledgement.

Balanced mode is the default:

```bash
cachaza run -d example.com \
  -active -authorized \
  -origin-auto -origin-mode balanced \
  -o ./runs/example-origin
```

Discovery-only mode does not contact candidate IP addresses and needs no active authorization gate:

```bash
cachaza run -d example.com \
  -origin-auto -origin-mode passive \
  -o ./runs/example-origin-passive
```

Deep mode remains bounded to configured web ports, observed public paths, and a finite request budget:

```bash
cachaza run -d example.com \
  -active -authorized \
  -origin-auto -origin-mode deep \
  -origin-max-auto-candidates 20 \
  -origin-max-requests 100 \
  -origin-rate-limit 1 \
  -origin-concurrency 2 \
  -o ./runs/example-origin-deep
```

Use `-origin-no-direct-validation` to force candidate discovery and ranking only. Use `-dry-run` to print the complete plan, authorization state, ports, candidate cap, rate limit, concurrency, and request budget without performing DNS, HTTP, TLS, API, or tool calls.

The validator connects to the candidate IP but sends the target domain as TLS SNI and HTTP `Host`. It performs TCP connect checks only on the configured web ports, then HEAD and limited GET requests to `/`, an observed favicon, and a small number of already observed static resources. In deep mode, optional JARM correlation uses TLSX against one selected IP/port at a time with exact SNI, concurrency 1, zero retries, and the same finite activity budget; it is skipped when TLSX is unavailable. It never sends POST requests, trust-manipulation headers, performs path fuzzing, runs Nuclei against candidates, enumerates an ASN/CIDR, or attempts to defeat mTLS, Authenticated Origin Pulls, ACLs, or Tunnel.

Every run writes the explainable Origin evidence under `rest/origin/`, including `public-baseline.json`, all/selected/rejected candidate JSONL files, validation results, network classifications, the persisted request budget, and final JSON/CSV rankings. A high-confidence result is a strong technical correlation, not proof of ownership or permission for further testing.

Cloudflare-specific interpretation follows the vendor's current documentation: a DNS-only record can reveal an actual origin address, proxied addresses are Cloudflare anycast edges, AOP adds client-certificate authentication, an origin firewall may accept only Cloudflare ranges, and Tunnel can operate without a publicly routable origin. See [Proxy status](https://developers.cloudflare.com/dns/proxy-status/), [exposed IP addresses](https://developers.cloudflare.com/dns/manage-dns-records/troubleshooting/exposed-ip-address/), [Cloudflare IP addresses](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/), [Authenticated Origin Pulls](https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/explanation/), and [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/).

## Profiles

| Profile | Direct contact | Ordered stages |
|---|---:|---|
| `passive` | No application/network scanning | `corporate`, `asn`, `tenant`, `ct`, `api`, `subdomains`, `shodan`, `cloud`, `gau` |
| `safe` | Yes; requires `-active` | Passive funnel plus `certificates`, `dns`, `ports`, and `http` |
| `full` | Yes; requires `-active` | Safe reconnaissance plus GAU, endpoint crawling, JavaScript endpoint mapping, and focused WAF identification. |

Choose the profile according to the engagement boundary:

- **`passive`** is the default. It collects public OSINT, Certificate Transparency, historical URLs, tenant relationships, infrastructure, and passive subdomains without directly probing the target application or network.
- **`safe`** starts with the passive funnel, then performs bounded certificate, DNS, port, and HTTP validation. It must be explicitly authorized with `-active`.
- **`full`** includes everything in `safe`, then adds historical URL discovery, endpoint crawling, JavaScript endpoint mapping, and focused WAF identification. It also requires `-active`. It does not run the explicit `bypass`, `policies`, or `cve` stages automatically.

`-stages` replaces the selected profile's stage list. `-skip-stages` removes specific stages while preserving the remaining order.

```bash
cachaza run -d example.com -stages asn,ct,api,subdomains,gau -o focused
cachaza run -d example.com -profile full -active -skip-stages js -o full-without-js
```

Any explicit active stage still requires `-active`, even when selected through `-stages`.

## Pipeline stages

| Stage | Type | Purpose |
|---|---|---|
| `corporate` | Passive/manual | Writes low-frequency OSINT and verification handoffs. |
| `asn` | Passive | Resolves domains and correlates BGP Toolkit, RIPEstat, ARIN RDAP, and optional ASNmap data. |
| `tenant` | Passive | Preserves tenant-related domains as candidates pending scope approval. |
| `ct` | Passive | Queries Cert Spotter and `crt.sh` independently. |
| `api` | Passive | Searches Censys Platform, IntelX Phonebook, and urlscan without submitting scans; writes per-provider execution status. |
| `certificates` | Active | Uses Caduceus only against explicitly authorized CIDRs. |
| `subdomains` | Passive | Uses Subfinder, Assetfinder, or passive BBOT modules and retains provider provenance. |
| `dns` | Active | Validates in-scope names with dnsx and normalizes A, AAAA, and CNAME evidence. |
| `dns_enum` | Active/optional | Runs dnsenum and Fierce for authorized DNS discovery; successful AXFR is recorded as a high-risk normalized finding. |
| `harvester` | Active/optional | Runs theHarvester's source, Shodan, API endpoint, and takeover workflow and extracts normalized contact/surface data. |
| `blackwidow` | Active/optional | Runs BlackWidow at the requested depth with crawling and Inject-X, then normalizes URLs, subdomains, APIs, contacts, forms, and manual-validation candidates. |
| `waf` | Active | Runs wafw00f and the single Nuclei WAF template per unique live authorized HTTP origin; Nmap NSE is optional. |
| `shodan` | Passive | Generates signatures and optionally performs bounded count/search API calls. |
| `ports` | Mixed | Uses Naabu/Nmap for authorized probes and Smap for Shodan-backed observations. |
| `http` | Active | Probes approved names/services with httpx and records status, server, ASN, CNAME, CDN, IP, and technology evidence. |
| `cloud` | Passive | Classifies existing IP/CIDR findings against provider ranges; never expands scope. |
| `bypass` | Active | Tests observed in-scope HTTP 403 URLs and records possible bypasses as candidates. |
| `gau` | Passive | Collects archived URLs with host, path, historical source, and API-endpoint hints; archived URLs are not treated as live. |
| `crawl` | Active | Runs scoped Katana or endpoint-only Cariddi discovery without fuzzing, payloads, or secret hunting. |
| `js` | Active | Extracts related URLs, API routes, JavaScript files, and Swagger/OpenAPI/GraphQL references with the bundled same-origin `JSMap-Inspector` CLI. |
| `policies` | Active | Collects CSP observations and favicon fingerprints. |
| `cve` | Passive correlation after active fingerprinting | Correlates observed technologies with Vulnx; results are candidates, not confirmed vulnerabilities. |

The compatibility stage `active` remains available for focused httpx/Naabu/Caduceus/Nmap runs, but named stages are preferred for new workflows.

## Scope

A domain is sufficient for passive discovery:

```bash
cachaza run -d example.com
```

Explicit network inputs authorize only those values:

```bash
cachaza run \
  -d example.com \
  -asn AS64500 \
  -cidr 192.0.2.0/28 \
  -exclude-domain dev.example.com \
  -exclude-cidr 192.0.2.8/29 \
  -profile safe -active
```

For larger engagements, use a target file:

```text
domain: example.com
asn: AS64500
org: Example Organization
cidr: 192.0.2.0/28
exclude-domain: dev.example.com
exclude-cidr: 192.0.2.8/29
```

```bash
cachaza run -targets-file scope.txt -profile safe -active
```

Automatically discovered prefixes and provider IPs remain `in_scope: false` unless they were explicitly authorized.

## Credentials and passive providers

Credentials may be exported normally or loaded from a data-only file. Cachaza parses `KEY=value` lines and never executes the file.

```bash
cp config/providers.example.env config/providers.env
chmod 600 config/providers.env
cachaza run -d example.com -api-config config/providers.env -o example-passive
```

Core variables include:

```bash
export PDCP_API_KEY='...'
export SHODAN_API_KEY='...'
export CERTSPOTTER_API_KEY='...'
export CENSYS_API_KEY='...'
export CENSYS_ORG_ID='...'
export INTELX_API_KEY='...'
export URLSCAN_API_KEY='...'
export VT_API_KEY='...'             # optional historical DNS for Origin discovery
```

`CENSYS_API_KEY` is the Censys Platform PAT used by Cachaza's native API stage; `CENSYS_ORG_ID` is optional. theHarvester's older Censys connector instead expects a separate `CENSYS_API_ID` plus `CENSYS_API_SECRET`. Do not copy the same PAT into all three fields.

IntelX and ZoomEye normally need only `INTELX_API_KEY` and `ZOOMEYE_API_KEY`; their host fields are optional overrides. Cachaza sends supported values from `providers.env` to Subfinder and creates a private temporary theHarvester `api-keys.yaml` for each execution, then removes it. This fixes the common situation where keys were present in `providers.env` but theHarvester ignored them because it only read `~/.theHarvester/api-keys.yaml`.

`cachaza doctor -api-config config/providers.env` checks whether values are present, but presence is not proof that a provider accepts them. Each real run writes `rest/api/provider-status.json`, including the HTTP status, whether the failure is transient, and a concrete corrective action.

- Censys `401`: the Platform PAT is invalid or expired. Regenerate it and put it only in `CENSYS_API_KEY`; the legacy `CENSYS_API_ID`/`CENSYS_API_SECRET` pair is a different credential type. Organization users must also have the Censys API Access role. `CENSYS_ORG_ID` remains optional.
- Censys `403`: the credential was accepted, but the account, organization, role, or subscription does not permit Global Search.
- IntelX `401`: verify that `INTELX_API_KEY` belongs to the configured `INTELX_HOST`, has not expired, and that the account includes Phonebook API access.
- `crt.sh` `502`: this is a transient upstream gateway failure, not evidence of a bad local key, VPN MTU, or Cachaza configuration. Cachaza continues with Cert Spotter and does not repeatedly retry the failed request.
- `tenant-domains` nonzero exit: Cachaza now prints the exit code even when the tool produces no diagnostic and retains stdout/stderr in `rest/tenant-domains/`.

Censys is primarily infrastructure search, so a valid Censys run is not expected to discover every public email. IntelX/theHarvester may also return zero emails because of plan coverage or provider indexing.

## VPN-safe network policy

Cachaza enforces a product-wide ceiling of **2 request/packet starts per second** and **2 concurrent network workers**. Native HTTP sources share one process-wide limiter. For Subfinder, dnsx, Katana, httpx, Naabu, Nmap, Caduceus, and TLSx, Cachaza also rewrites their native rate/concurrency arguments so a higher caller-provided value cannot escape the ceiling. Nuclei is more restrictive: its only permitted WAF command is forced to `-rl 1 -bulk-size 1 -c 1 -retries 0`. Common subprocess worker-pool environment variables and simultaneous child-process starts are capped at two as an additional safeguard.

The CLI rejects `-jobs`, `-rate-limit`, subdomain, or Origin values above two instead of silently accepting an unsafe configuration. Nuclei has no user-configurable template, tag, severity, rate, or concurrency options. Colors are enabled by default even when output is piped through `tee`; use either `-nc` or `-no-color` to disable ANSI colors in the console and `report.txt`.

Some independent upstream programs do not expose a trustworthy requests-per-second option. Cachaza can bound their process scheduling and common runtime worker pools, but it cannot inspect arbitrary internal schedulers. For a strict auditable engagement, select only adapters with native limits. Naabu, httpx, dnsx, Subfinder, and Katana are explicitly capped; Nuclei is limited to one WAF template against one normalized origin per process invocation.

These controls reduce burst load but do not change interface MTU. If the VPN still drops at two requests per second, measure the tunnel path MTU separately and adjust the VPN interface/MSS; a `502` from one public API is not an MTU diagnosis.

## Active controls

The hard defaults can only be tightened per engagement:

```bash
cachaza run -d example.com \
  -profile full -active \
  -ports 80,443,8080,8443 \
  -rate-limit 2 \
  -max-active-hosts 256 \
  -max-crawl-urls 25 \
  -o authorized-run -format all
```

Useful selectors:

```bash
-port-tools naabu,smap        # naabu,smap,nmap
-crawl-tools auto             # auto,katana,cariddi
-waf-tools wafw00f,nuclei     # add nmap only for explicit NSE correlation
```

`JSMap-Inspector` is bundled with Cachaza because the similarly named upstream project is an offline HTML interface, not an automatable CLI. `cachaza doctor -install` also installs a pinned, request-limited CSP Stalker wrapper. Use `-jsmap-path` or `-csp-stalker-path` only to select an explicitly installed compatible replacement.

### What the `ports` stage does

`ports` requires `-active` and starts from normalized findings that are already in scope:

1. It writes authorized domain targets to `rest/port-targets.txt` and records any over-limit/unauthorized networks in `rest/port-networks-skipped.txt`.
2. Naabu actively probes only the configured `-ports` on those authorized domains, at no more than 2 packets per second with 2 workers. Open endpoints become normalized `service` findings.
3. Smap performs a passive Shodan-backed lookup when `SHODAN_API_KEY` is configured. It does not replace the active Naabu result.
4. Optional Nmap runs only against explicitly authorized CIDRs that pass the active-range safety checks, with `--max-rate 2 --max-parallelism 2` added automatically.
5. The following `http` stage consumes the discovered domains/services and performs bounded HTTP fingerprinting; `ports` itself does not run vulnerability templates.

The default selector is `-port-tools naabu,smap`; Nmap runs only when explicitly included with `-port-tools ... ,nmap`. With `-v`, Cachaza prints the selected adapters, ports, target counts, and the enforced network ceiling at the start of the stage.

## Focused discovery bundles

These switches add one focused stage to the selected profile. `-w`, `-harvester`, `-dns-enum`, and `-blw` contact the target or its DNS service and therefore require the explicit `-active` authorization gate. `-s` uses passive providers and does not require it.

| Shortcut | Long option | Tools and concrete behavior | Normalized output |
|---|---|---|---|
| `-w` | `-waf` | Runs `wafw00f URL -a` and only Nuclei's `http/technologies/waf-detect.yaml` template at `-rl 1 -bulk-size 1 -c 1 -retries 0`. Nmap's `http-waf-detect` and intensive `http-waf-fingerprint` scripts run only when `nmap` is explicitly added to `-waf-tools`. | Deduplicated `waf` findings that retain target origin, vendor, source, confidence, and bounded evidence. |
| `-harvester` | - | Runs theHarvester per root with Shodan, API scanning, takeover checks, and `-b all`; `-harvester-dns-server` supplies the optional `-e` value. | Emails, phones, addresses, hosts, URLs, API endpoints, IPs, and redacted API-key candidates. |
| `-dns-enum` | - | Runs `dnsenum DOMAIN` and `fierce -dns DOMAIN`, saves raw output separately, and correlates names and addresses. | Deduplicated domains/IPs plus a high-visibility `dns_zone_transfer` finding if AXFR succeeds. |
| `-s` | `-subdomains` | Ensures both `assetfinder --subs-only DOMAIN` and rate-limited Subfinder (`-all -rl 1 -t 1`) are selected. | In-scope domain findings with source/provider provenance. |
| `-blw LEVEL` | - | Runs `blackwidow -l LEVEL -v y -s y -u https://DOMAIN/`. LEVEL is 1-10. If absent, Cachaza downloads a pinned copy to the user's Cachaza data directory; no internal `sudo` prompt is used. | Deduplicated URLs, dynamic/API endpoints, subdomains, emails, phones, forms, and Inject-X output marked as unconfirmed/manual-validation evidence. |

Run all focused bundles (BlackWidow depth 4):

```bash
cachaza run -d example.com \
  -s -harvester -dns-enum -w -blw 4 -active \
  -o focused-example -format all -v
```

### Endpoint reconnaissance

The `full` profile orders `http` before `waf` and obtains endpoint evidence from GAU, Katana or Cariddi, JavaScript analysis, and existing passive sources:

```bash
cachaza run \
  -d example.com \
  -profile full \
  -active \
  -format all \
  -o example-recon

cachaza run \
  -d example.com \
  -stages http,gau,crawl,js,waf \
  -crawl-tools katana \
  -waf-tools wafw00f,nuclei \
  -active \
  -format all \
  -o example-endpoints
```

GAU records remain historical until another source confirms a live response. Katana remains FQDN-scoped and bounded. Cariddi uses endpoint discovery only (`-e -plain`) and never enables its `-s` secret-hunting mode. JavaScript analysis extracts related files, URLs, routes, and Swagger/OpenAPI/GraphQL references; strings such as `token`, `password`, or `secret` are not promoted to security findings by this flow.

### WAF correlation

```bash
cachaza run -d example.com -w -active -o example-waf -format all
cachaza run -d example.com -w -active -waf-tools wafw00f,nuclei -o example-waf
cachaza run \
  -d example.com \
  -stages waf \
  -waf-tools nuclei \
  -active \
  -format all \
  -o example-waf
```

The third command is the only Nuclei behavior available in Cachaza: one immutable WAF template, one request per second, one host per batch, one concurrent template, and zero retries. The former general `nuclei` stage and all tag/severity controls have been removed. `-stages nuclei` returns an actionable error instead of silently changing behavior.

WAF targets are deduplicated by `scheme + hostname + effective port`, never by individual path. Default ports are collapsed (`https://example.com:443/login` becomes `https://example.com`); a non-standard port is retained only after httpx or a crawler confirms a live HTTP(S) URL. GAU history, DNS records, Naabu services, and Nmap services do not become Nuclei targets. If `waf` runs alone without live URL evidence, the only fallback is `https://ROOT_DOMAIN`.

Nuclei is restricted to the single WAF detection template. Cachaza does not use Nuclei for vulnerability scanning or endpoint discovery.

Cachaza invokes `nmap` directly, not through `sudo`, because an internal privilege prompt would break unattended runs. Start Cachaza from an appropriately privileged shell if the local Nmap configuration needs elevated access. A product name reported by multiple tools is presented once in the key summary while every source-specific observation remains in the evidence records.

### theHarvester organization and contact discovery

```bash
cachaza run -d example.com -harvester -active \
  -harvester-source all \
  -harvester-limit 500 \
  -harvester-dns-server 1.1.1.1 \
  -o example-harvester -format all
```

The generated command is equivalent to:

```bash
theHarvester -d example.com -l 500 -s -a -t -b all -e 1.1.1.1 -f OUTPUT_BASE
```

theHarvester requires a value after `-e`; Cachaza omits that flag unless `-harvester-dns-server` is set. Saved JSON is parsed structurally. Possible keys/tokens are represented only by a redacted SHA-256 fingerprint and marked `candidate` for manual validation; the summary never prints the raw value.

Cachaza also requests at most 12 already discovered contact/legal pages sequentially (plus the root page), extracting visible `mailto:`, `tel:`, Cloudflare-obfuscated emails, JSON-LD postal addresses, and conservative visible-text matches. This is why public details present on `/contacto/`, `/terminos-de-uso/`, or `/politica-de-privacidad/` can now appear even when a provider returns no emails.

### BlackWidow

```bash
cachaza run -d example.com -blw 2 -active -o example-blackwidow -format all -v
cachaza run -d example.com -blw 4 -blackwidow-path /opt/BlackWidow/blackwidow -active -o example-blackwidow
```

`-blw 2` maps to BlackWidow's actual value-taking interface: `blackwidow -l 2 -v y -s y -u https://example.com/`. Upstream `-v` and `-s` are not bare switches. `-s y` enables Inject-X checks, so Cachaza always requires `-active`. Raw stdout/stderr and discovered files are retained under `rest/blackwidow/`; normalized results flow into every report. Any possible SQLi/XSS/traversal/redirect line is labelled `candidate` and `requires_manual_validation`.

### DNS enumeration and zone transfer

```bash
cachaza run -d example.com -dns-enum -active -o example-dns -format all
cachaza run -d example.com -dns-enum -active -dns-enum-tools dnsenum -o dnsenum-only
```

Raw outputs live under `rest/dns-enum/`. If either tool reports a successful AXFR, the terminal summary prints `Zone transfer allowed: ALLOWED`, the normalized finding carries `risk: high`, and every selected report repeats the warning. Failure/refusal messages do not create a false positive.

### Passive subdomain enumeration

```bash
cachaza run -d example.com -s -o example-subs -format all
cachaza run -d example.com -s -subdomain-rate-limit 1 -subdomain-threads 1 -o example-subs
```

`-subdomain-tools auto` remains available. `-s` simply makes the two-tool Subfinder + Assetfinder choice explicit. Names are normalized, restricted to the requested roots/exclusions, and deduplicated in reports while source-level provenance remains intact.

## Reports and workspace

Supported formats are `html`, `json`, `txt`, `pdf`, `csv`, and `all`:

```bash
cachaza run -d example.com -o example-report -format html,json,pdf
cachaza run -d example.com -o example-report -format all
```

Every format receives the same normalized data and executive categories: WAFs, API-key/secret candidates, API endpoints, subdomains, emails, phones, addresses, and successful DNS zone transfers. The console and executive views show at most 13 subdomains followed by `more on reports`; the complete list remains available in the detailed reports and `rest/subdomains.txt`.

The HTML report is the recommended primary result because it provides the richest reporting experience: searchable normalized evidence, expandable details, filters, summaries, and the interactive relationship explorer. At the end of every run, Cachaza prints the exact `report.html` path and recommends opening it. Generate it with `-format html` or `-format all`, then open the path shown by Cachaza; on Kali, for example:

```bash
xdg-open ./output/example-report/report.html
```

- **HTML:** self-contained, searchable evidence and relationship graph. Hovering a node immediately updates the right-hand inspector; clicking pins the node so its details return after hover ends.
- **JSON:** lossless scope, findings, metadata, stage state, graph, network intelligence, and `key_findings` object for automation.
- **CSV:** one normalized row per finding with spreadsheet formula prefixes neutralized.
- **TXT:** color-aware terminal report with executive summary, key findings, full inventory, stages, and evidence.
- **PDF:** designed for sharing: branded cover, metric cards, key-findings dashboard, explicit scope, infrastructure tables, execution status, normalized inventory, page headers/footers, and a detailed evidence appendix. The PDF appendix is capped at 300 rows; JSON/CSV remain the lossless formats for larger runs.

Untrusted values are escaped, HTML carries a restrictive Content Security Policy, candidate secrets are redacted, and spreadsheet formula prefixes are neutralized in CSV.

Important workspace files:

| Path | Content |
|---|---|
| `report.*` | Selected reports in the workspace root. |
| `rest/findings.jsonl` | Canonical append-only normalized evidence. |
| `rest/scope.json` | Exact requested scope and exclusions. |
| `rest/manifest.json` | Version, profile, stage states, counts, and command history. |
| `rest/api/provider-status.json` | Native Censys/IntelX/urlscan request status and safe diagnostics; never contains configured API keys. |
| `rest/stages/*.json` | Completed stage checkpoints. |
| `rest/domains.txt`, `rest/services.txt` | Derived convenience views, not separate sources of truth. |
| `rest/urls.txt` | Complete in-scope URLs as observed by their source. |
| `rest/endpoints.txt` | Deduplicated endpoint URLs without fragments or query values; sorted parameter names are retained. |
| `rest/api-endpoints.txt` | Explicit API findings plus URL findings marked as API endpoints by GAU, crawlers, or JavaScript analysis. |
| `rest/wafs.txt` | One tab-separated `origin`, `vendor`, `source` row per retained WAF observation. |
| `rest/security-findings.txt`, `rest/cve-candidates.txt` | Human-readable filtered views. |

Reusing a compatible `-o` workspace resumes it automatically. Use `-resume` when the workspace must already exist, or `-fresh` to reset only a verified workspace whose saved scope matches the current request.

```bash
cachaza run -d example.com -profile passive -o example-run
cachaza run -d example.com -profile passive -o example-run -resume
cachaza run -d example.com -profile passive -o example-run -fresh
```

Changing scope is rejected to prevent evidence from unrelated engagements being mixed.

## Commands

| Command | What it does concretely |
|---|---|
| `cachaza run` | Builds or resumes a scoped workspace, executes the ordered profile/stage funnel, normalizes and deduplicates evidence, saves raw artifacts and checkpoints, and exports the selected reports. Direct-contact stages remain blocked without `-active`. |
| `cachaza plan` | Validates scope and prints the exact ordered workflow, profile, active boundaries, and automatic discovery behavior. It performs no network/tool execution and creates no files; `-json` makes the plan machine-readable. |
| `cachaza signatures` | Produces named Karma/Shodan queries from domains, organization hints, and optional SHA-1 certificate fingerprints. It can write `name::query` text or JSONL and does not spend Shodan search credits. |
| `cachaza normalize` | Reads arbitrary text/JSON from files or stdin, extracts syntactically valid domains, converts case/wildcards/URLs to canonical names, optionally filters them under one or more roots, deduplicates, sorts, and writes plain lines. |
| `cachaza monitor` | Watches Certificate Transparency for new in-scope names. `auto` prefers streaming Gungnir when suitable; otherwise Cachaza polls Cert Spotter + crt.sh, persists seen-state, supports `-once`, and prints only newly observed names. |
| `cachaza doctor` | Checks every optional executable plus provider credential presence. `-api-config FILE` includes a data-only provider file; `-install` installs every absent tool with an approved Go, pipx, or pinned Cachaza user-space recipe. Credential acceptance is verified only by a real provider request. |

```bash
cachaza -help
cachaza doctor
cachaza doctor -api-config config/providers.env
cachaza doctor -install
```

`cachaza -h` now includes both the command overview and the complete `run` option reference. `cachaza run -h` remains available as the shorter run-only view.

Output controls:

```bash
cachaza run -d example.com -v
cachaza run -d example.com -vv
cachaza run -d example.com -silent
cachaza run -d example.com -no-color
cachaza run -d example.com -dry-run
```

Global options shown by `cachaza -h`:

| Option | Specific behavior |
|---|---|
| `-h`, `-help` | At the top level, prints the command overview and every `run` option in one combined reference; on a selected subcommand, prints that command's help. |
| `-v`, `-verbose` | Streams external tool output and prints every normalized finding; repeat as `-vv` to include normalized metadata. |
| `-q`, `-silent` | Suppresses the banner, startup version check/prompt, progress, verbose findings, report paths, and final key summary. Report files are still generated normally. |
| `-nc`, `-no-color` | Disables ANSI styling in the terminal and `report.txt`; it does not remove visual styling from HTML/PDF. |
| `-version` | Prints the installed Cachaza version and exits. |
| `-up`, `-update` | Runs the explicit update/reinstall workflow, then verifies the version and executes `doctor`. It cannot be combined with another command. |

## Optional tools

Cachaza remains usable when optional binaries are absent; affected stages are isolated and skipped unless `-strict` is selected. Run `cachaza doctor -install` to fill all supported user-space dependencies, then `cachaza doctor` to verify them. Kali packages that require apt/sudo remain an explicit administrator action. See [docs/OPTIONAL_TOOLS.md](docs/OPTIONAL_TOOLS.md) for recipes and compatibility notes.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

The test suite also runs without pytest-specific features:

```bash
python -m unittest discover -s tests -v
```

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the workflow and safety model, and [docs/MIGRATION.md](docs/MIGRATION.md) for migration from the earlier Bash workflow.

## Contributing

Issues and pull requests are welcome at [W4RRR/cachaza](https://github.com/W4RRR/cachaza). Preserve provenance, keep passive collection conservative, and never promote inferred third-party infrastructure into active scope automatically.
