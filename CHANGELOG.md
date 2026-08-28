# Changelog

## 1.0.7 - 2026-08-28

- Made `-resume` idempotent for output handling: missing or empty directories are created as new workspaces, while compatible existing workspaces continue from checkpoints.
- Kept scope mismatch and non-workspace protections for populated output directories.

## 1.0.6 - 2026-08-28

- Changed AI executive summaries to concise bullet highlights in HTML and PDF.
- Enforced the selected AI language across narrative fields, action recommendations and report labels.
- Replaced the gridded Origin overview with an organic, type-grouped supporting-node layout.
- Made graph hover update the evidence and relationship inspector while preserving click selection.

## 1.0.5 - 2026-08-28

- Fixed Python 3.13 compatibility when extracting provider details from HTTP errors.
- Made OpenRouter routing failures non-fatal so deterministic HTML/PDF reports are still exported.
- Added an actionable OpenRouter model diagnostic after structured-output fallback fails.

## 1.0.4 - 2026-08-27

- Added independent dnsenum and Fierce runtime controls with backward-compatible fallback.
- Added a timestamped full execution log with command duration, timeout and return code.
- Added findings-by-tool sections to HTML and PDF reports.
- Made Origin-path layout the graph default, click-only node detail cards, and multi-Origin outcomes.
- Added colored provider diagnostics and current Censys CenQL/organization validation.
- Improved OpenRouter structured-output recovery and visible failure diagnostics.

## 1.0.2 - 2026-08-27

- Added `-op` / `-professional-report` as a one-step OpenRouter-assisted executive reporting mode.
- Added a fluid white-label HTML presentation optimized for desktop, tablet, Android and iOS widths.
- Removed product branding from professional HTML/PDF content, metadata, embedded report data and structured outputs.
- Added the assessed domain or authorized scope as the explicit report subject.
- Added a deterministic, vendor-neutral Origin exposure remediation roadmap with owners and closure tests to HTML and PDF.
- Constrained the OpenRouter narrative to the supplied remediation controls and prevented invented vendor features or completion claims.
- Added a dedicated responsive Origin Exposure Path graph to HTML and an equivalent executive infographic to PDF.

## 1.0.1 - 2026-08-27

- Professionalized the executive HTML and PDF reports for leadership review.
- Added a deterministic five-step Origin attribution trace with tactics, techniques, procedures, tools and supporting evidence.
- Highlighted the leading Origin IP and its attribution path in the interactive graph.
- Restricted CDN/WAF bypass claims to candidates with positive authorized Direct-origin validation evidence.
- Added optional OpenRouter-assisted executive narratives using bounded report digests and strict structured output.
- Kept deterministic reports available when OpenRouter is disabled or unavailable, without embedding API credentials in artifacts.

## 1.0.0 - 2026-08-21

- Integrated the standalone Origin exposure workflow into Cachaza's normalized pipeline.
- Added autonomous passive Origin adapters for Censys, Shodan, urlscan, OTX, ViewDNS and FOFA alongside existing DNS, CT, VirusTotal and SecurityTrails evidence.
- Added `-origin-ip` and `-real-origin-ip` aliases for `-origin-auto`.
- Added explicit `origin_ip`, heuristic Origin probability, confidence band, scoring method and complete candidate ranking to terminal, JSON, TXT and CSV output.
- Added ranked Origin visuals to HTML and PDF and Origin probability metadata to the HTML relationship graph.
- Prevented rejected edge/third-party candidates from being presented as the most likely Origin IP.
- Preserved bounded Direct-origin validation, explicit authorization gates and the central request budget.
- Added a tag-driven GitHub Release workflow and pinned non-checkout `cachaza -up` installations to the latest published stable release.

The Origin probability is an explainable correlation score, not a statistically calibrated probability or proof of ownership.
