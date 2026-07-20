# Optional tool adapters

Cachaza detects available binaries at runtime and reports missing components through `cachaza doctor`. `cachaza doctor -install` installs every absent dependency for which Cachaza has an approved user-space recipe. It never invokes sudo; Kali packages managed by apt remain an explicit administrator choice.

## Complete user-space installation

Install the Go toolchain and pipx once, then let Cachaza fill the missing supported tools:

```bash
sudo apt update
sudo apt install -y golang-go pipx python3-venv
pipx ensurepath
hash -r
cachaza doctor -install
cachaza doctor
```

The installer:

- puts Go binaries, including AlterX and Uncover, in `~/.local/bin`;
- installs BBOT and wafw00f with pipx when absent;
- installs pinned BlackWidow and CSP-Stalker copies under `~/.local/share/cachaza/tools`;
- patches the managed CSP-Stalker copy to start at most two requests per second and runs it with its real upstream CLI;
- exposes Cachaza's bundled same-origin source-map analyzer as `JSMap-Inspector`.

An existing executable always wins: `doctor -install` does not replace tools already found in `PATH` or `~/.local/bin`.

## ProjectDiscovery tools

Install a recent Go toolchain, then install only the adapters needed for the selected profile:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go install -v github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
```

Manual Go installations normally use `~/go/bin`; Cachaza's installer deliberately sets `GOBIN=~/.local/bin`. Ensure both locations are on `PATH` when mixing both approaches:

```bash
export PATH="$HOME/.local/bin:$PATH:$(go env GOPATH)/bin"
```

## Other Go adapters

```bash
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
go install -v github.com/trap-bytes/403jump@latest
go install -v github.com/g0ldencybersec/Caduceus@latest
go install -v github.com/d3mondev/puredns/v2@latest
```

Nmap, WHOIS, Smap, Gungnir, Favicorn, theHarvester, dnsenum, Fierce, MassDNS, and tenant-domain helpers remain optional system or specialist tools. Install them from their maintained Kali package/upstream repository and verify their CLI with `-help`/`--help`.

Focused bundle upstreams:

- [wafw00f](https://github.com/enablesecurity/wafw00f) for broad WAF fingerprints.
- Nuclei's `http/technologies/waf-detect.yaml` template for a second WAF signal. This is the only Nuclei template Cachaza permits; it is not used for vulnerabilities or endpoints.
- Nmap `http-waf-detect` and `http-waf-fingerprint` NSE scripts for optional protocol-level correlation. Nmap is not in the default `wafw00f,nuclei` selector.
- theHarvester for organization contacts, hosts, APIs, and takeover candidates.
- dnsenum and Fierce for DNS enumeration and AXFR observations.
- [BlackWidow](https://github.com/1N3/BlackWidow) for authorized crawling and Inject-X candidates. `-blw LEVEL` downloads commit `c9eb24e238c390b03897a04c79e55cb17ec35b8c` into `~/.local/share/cachaza/tools/BlackWidow` when no executable is available.
- [CSP-Stalker](https://github.com/0xakashk/CSP-Stalker) for CSP-derived domains. Cachaza installs commit `464808cb6cc5c340761583f7643b361780040d50` and adds only its mandatory request pacing patch.
- The upstream [JSMap Inspector](https://github.com/ynsmroztas/JSMap-Inspector) is an offline HTML application and does not publish the `JSMap-Inspector.py` CLI previously documented here. Cachaza now supplies its own bounded CLI entry point with the expected `-l`/`-o` interface.

Compatible alternate scripts can still be supplied explicitly:

```bash
cachaza run -d example.com -profile full -active \
  -jsmap-path /opt/custom-jsmap-cli \
  -csp-stalker-path /opt/CSP-Stalker/cli_CSP_Stalker.py
```

## Adapter compatibility

| Adapter | Expected interface |
|---|---|
| Subfinder | JSONL through `-oJ -cs`; optional provider config through `-pc`. |
| dnsx | JSONL through `-json`, response fields enabled. |
| Naabu | File input `-l`, port list `-p`, rate `-rate`. |
| httpx | JSONL with status, IP, CNAME, CDN, ASN, and technology fields. |
| Nuclei | One normalized live origin through `-u`, the immutable `-t http/technologies/waf-detect.yaml`, JSONL, rate/bulk/concurrency 1, and zero retries. No tags, severities, workflows, lists, directories, automatic scans, or other templates are accepted. |
| Katana | List input, FQDN scope, depth 3, known files, and JSONL output. |
| Cariddi | URL input on stdin with endpoint/plain output (`-e -plain`), concurrency 1, depth 1, bounded timeout, and maximum-distance 3. Its `-s` secret-hunting mode is deliberately absent. |
| JSMap Inspector | Bundled CLI reads JavaScript URL input with `-l`, follows only same-origin maps, caps each response, extracts URL/route/API/related-JavaScript references, and writes JSON with `-o`; it does not classify secret-like words. |
| CSP Stalker | One URL through `-u`; upstream writes under `./results`, so Cachaza sets a stage-specific working directory instead of passing the nonexistent `-o` option. |
| GAU | Domain input on stdin with `--subs`. |
| 403jump | Target file through `-f`. |
| Favicorn | URL file through `-f`. |
| Vulnx | `search TERM --limit 20 --json --silent`. |
| wafw00f | One authorized URL with `-a`; human/JSON-like output is normalized defensively. |
| theHarvester | `-d`, `-l`, `-s`, `-a`, `-t`, `-b`, and file output through `-f`; `-e` is supplied only with an explicit DNS server. |
| dnsenum | One authorized root domain as a positional argument. |
| Fierce | Legacy-compatible `-dns DOMAIN` interface. |
| BlackWidow | `-l LEVEL -v y -s y -u URL`; Cachaza never assumes `-v`/`-s` are bare flags and never invokes `sudo` internally. |
| AlterX + PureDNS/DNSx | Used only with `-origin-dns-permutations`; seed/output counts are capped, wildcard results are not promoted automatically, and no CIDR/ASN expansion occurs. |
| TLSX | Optional `-origin-jarm` correlation against one already selected IP/port at a time; Cachaza supplies the exact target SNI, concurrency 1, zero retries, a finite timeout, and never passes a CIDR. |

When an upstream tool changes its CLI, the stage fails in isolation and records the error. Run the test suite and a `-dry-run` plan after upgrading a major tool version.
