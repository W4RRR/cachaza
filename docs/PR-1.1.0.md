Origin reports could display an uncalibrated correlation score as a probability and claim a CDN/WAF bypass even when the baseline reported no CDN. The CLI, HTML and PDF now present scores out of 100 separately from direct validation. A direct match without an established edge boundary receives an architecture-review conclusion.

This release adds offline report comparison, persistent review annotations and report regeneration; stage cache expiration and selective refresh; and coverage/freshness views. Refresh archives old stage findings, replaces successful collections, restores findings after failure and invalidates dependent checkpoints. The evidence explorer renders 100 records per page with a debounced search. Contact summaries normalize equivalent numbers and filter year/postcode false positives.

Legacy JSON probability fields remain available as deprecated score aliases. Audit operations and Origin assessment policy are extracted into focused modules. Pull requests now run tests and wheel-installation smoke checks across Python 3.11–3.13.

Validation: full pytest suite; offline CLI regressions for comparison, annotations, scope mismatch, expiration and failed refresh; local browser search/pagination/review checks; PDF visual inspection using a private, uncommitted example. No target scans or provider requests were performed during verification.
