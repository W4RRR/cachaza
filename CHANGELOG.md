# Changelog

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
