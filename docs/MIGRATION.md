# Migration from the Bash workflow

Cachaza 0.7 consolidates passive OSINT and authorized active reconnaissance into the Python package and its normalized workspace. The Bash runner is no longer required.

## 0.10 automatic Origin discovery

Origin IPs are no longer supplied or approved one at a time. The options `-approve-origin-ip` and `-approve-origin-candidates-file` are intentionally absent. Use `-origin-auto`; passive mode needs no active gate, while Direct-origin validation requires the engagement-wide `-active -authorized` acknowledgement.

```bash
cachaza run -d example.com -active -authorized \
  -origin-auto -origin-mode balanced -o ./runs/example-origin
```

Existing general active-scope behavior remains unchanged. The authorization exception is isolated to the Origin stage: it may contact only automatically generated, correlated, public, non-CDN `origin_candidate` addresses that pass the configured score and central request-budget gates.

## What changed

- Phase functions are Python `stage_*` methods and typed adapters.
- All observations become `Finding` objects before reporting.
- `rest/findings.jsonl` replaces phase-specific text files as the canonical evidence store.
- Reports are generated only by Cachaza and include the relationship graph and PDF output.
- The default profile is passive; `safe` and `full` require `-active`.
- Resume state uses stage checkpoints rather than checking whether arbitrary output files exist.
- API configuration is parsed as data and never sourced as shell code.

## Profile mapping

| Previous workflow mode | Cachaza command |
|---|---|
| Passive collection | `cachaza run -d example.com -profile passive` |
| Bounded validation | `cachaza run -d example.com -profile safe -active` |
| Complete authorized workflow | `cachaza run -d example.com -profile full -active` |

## Phase mapping

| Earlier phase | Cachaza destination |
|---|---|
| Passive subdomains | `stage_subdomains` plus Subfinder/Assetfinder/BBOT normalization |
| DNS validation | `stage_dns` and `adapters/dnsx.py` |
| Passive/active ports | `stage_ports` and Smap/Naabu/Nmap adapters |
| HTTP probing | `stage_http` with normalized httpx evidence |
| Template checks | `stage_nuclei` and `adapters/nuclei.py` |
| HTTP 403 checks | `stage_bypass` and `adapters/jump403.py` |
| Historical/sensitive URLs | `stage_gau` and `adapters/gau.py` |
| Endpoint crawling | `stage_crawl` and Katana/Cariddi adapters |
| JavaScript analysis | `stage_js` and `adapters/jsmap.py` |
| CSP/favicon analysis | `stage_policies` and CSP Stalker/Favicorn adapters |
| CVE lookup | `stage_cve` and `adapters/vulnx.py` |
| Provider enrichment | `stage_api`, native Censys/IntelX/urlscan sources, provider diagnostics, and temporary Subfinder/theHarvester configuration |
| Per-phase resume files | `rest/stages/*.json` checkpoints |
| Separate report generator | Cachaza HTML/JSON/TXT/PDF/CSV exporters |

## Move an engagement

Start a new Cachaza workspace rather than copying old phase directories:

```bash
cachaza run -d example.com -profile passive -o example-migrated -format all
```

If a prior scope included approved CIDRs, provide them explicitly again:

```bash
cachaza run -d example.com \
  -cidr 192.0.2.0/28 \
  -profile full -active \
  -o example-authorized -format all
```

Review `rest/scope.json` before active work. Do not import inferred provider or CDN ranges as authorized CIDRs without written approval.

## Credentials

Copy the example file and enter only the providers you use:

```bash
cp config/providers.example.env config/providers.env
chmod 600 config/providers.env
cachaza run -d example.com -api-config config/providers.env
```

`config/providers.env` is ignored by Git. Existing exported environment variables continue to work.

## Resume behavior

```bash
cachaza run -d example.com -profile passive -o example-run
cachaza run -d example.com -profile full -active -o example-run -resume
```

The second command may extend the stage selection. Completed checkpoints are reused only when their scope and execution options remain compatible. Use `-fresh` to deliberately rebuild a verified workspace from zero.
