# Cachaza 1.2.0 performance validation

Measured on Windows on 2026-09-07 against commit `3cdedca` (1.1.2).
All benchmarks are offline. These numbers describe controlled fixtures, not
the speed of an Internet audit or the reliability of any provider.

| Measurement | Before | After |
| --- | ---: | ---: |
| Browser layout, 1,200 uncollapsed nodes, `performance.now()` | 1,548 ms | 400 ms |
| V8 layout, same dataset | 1,612 ms | 348 ms |
| Minimum node-center distance at 100% spacing | 1.58 | 85.00 |
| Full stage list, fixed collectors, median of five | 87.65 ms | 67.09 ms |
| Twelve identical provider calls, simulated 10 ms transport | 12 calls / 126.11 ms | 1 call / 11.15 ms |
| Origin redirect also listed as a resource | 4 HTTP calls | 3 HTTP calls |
| Artifact extraction, 100,000 findings, one sample, excluding disk | 107.68 ms | 94.15 ms |

The full-stage fixture compares jobs=1 and jobs=2 with identical stage functions,
fixed evidence timestamps and artificial CT/API latency. It asserts the exact
same ordered findings and stages. Real speedups depend on provider latency and
the unchanged process-wide network ceiling (two concurrent operations, two
request starts per second in the existing limiter).

## Changes and boundaries

- A: Explicit conservative dependency DAG. Corporate, CT and API have independent
  source/artifact ownership. Other stages remain barriers because of workspace
  readers, external processes or temporary process-wide credential state.
  Findings are buffered and committed in requested order, before checkpoints.
  Resume, strict mode and jobs=1 remain sequential. Live progress can interleave.
- B/G: Injectable `RunCache.activate()` context; 60-second TTL, 256 entries,
  keyed hashes, copy-on-read and coalescing concurrent identical requests.
  Raw HTTP payloads over 1 MiB are not retained. GET/HEAD only; failed transports,
  invalid JSON, failed DNS and unsuccessful public baselines are not retained.
  System DNS answers are shared between the ASN and Origin adapters.
  Public baseline requests are reusable only with identical probe options.
- C: Shared presentation helpers and removal of the unused legacy HTML renderer.
  TXT/HTML snapshots were identical immediately after extraction. Final HTML
  changes only its presentation code. The final normalized report JSON, including
  findings and graph, matches the pre-refactor snapshot. Artifact lists match.
- D: Exact spatial indexing for the existing finite-radius forces, rather than
  inventing a long-range force to use Barnes–Hut. Deterministic collision placement
  covers visible URL children; four settled layouts are retained. Kind clusters
  get separate regions; overview edges are quieter; Origin highlighting stays.
  SVG is retained for accessibility and the existing standalone CSP. Large URL
  groups remain collapsed by default. No canvas/WebGL dependency was added.
- E: Repeated candidate HTTP probes with identical Host/SNI, port, method, path,
  timeout and body limit reuse their response. Hits do not consume Origin budget.
  Validation request counts intentionally decrease; scoring rules are unchanged.
- F: Artifact list extraction builds one index. ReportLab and cryptography were
  already imported inside the relevant PDF/TLS functions, so those imports were
  retained. Cloud workers use the existing policy constant; no cap was raised.

External httpx/wafw00f/certificate collectors have different request and evidence
semantics from the Python baseline. Their outputs are not treated as interchangeable
cache entries. Raw collected evidence remains verbatim, including its language.

## Optional instrumentation

Set `CACHAZA_METRICS=1` to write `rest/metrics.json`. The default output is unchanged.
Set `CACHAZA_CACHE=0` to disable the general per-run TTL cache for comparison.
Neither environment variable changes checkpoint keys or adds a CLI flag.

Metrics include stage durations, non-skipped command-history entries, cache
hits/misses and Python transport counters. Transport counters measure wrapper
invocations; they do not count packets or requests inside external tools, and
urllib redirects may involve more than one wire request. No URLs, API keys,
request bodies or credential-bearing cache identities are serialized.

## Reproduction

```text
python -m pip install -e ".[dev]"
python -m pytest -q
python tests/benchmark_runtime.py
node tests/benchmark_graph.cjs src/cachaza/html_report.py 1200
node tests/benchmark_graph.cjs src/cachaza/html_report.py 1200 --groups
node tests/benchmark_graph.cjs src/cachaza/html_report.py 1200 --html > graph-benchmark.html
```

Open the generated benchmark HTML locally to measure the browser engine. To
compare the original layout, save `git show 3cdedca:src/cachaza/html_report.py`
outside the repository and pass that path to the same benchmark script.
The Node regression runs when Node is on PATH or `CACHAZA_TEST_NODE` points to it.
Python runtime dependencies are unchanged.

Final validation: 201 tests and 27 subtests passed, with both Node layout
regressions enabled. A real CLI `full` dry-run completed all 16 stages, wrote
JSON/TXT plus optional metrics, and retained the final mini-summary on redirected
stdout and stderr. The installed CLI and project metadata both report 1.2.0.

Browser interaction checks: initial URL grouping, keyboard search, expanding 50
URLs, changing spacing to 180%, Fit and mobile/desktop controls. The expanded
59-node fixture had a minimum measured center distance of 154.99 at 180%.
