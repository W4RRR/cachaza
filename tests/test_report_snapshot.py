"""Contract snapshot captured from 1.1.2 before the performance refactor."""
import hashlib
import json

import test_reports


def test_normalized_report_matches_pre_optimization_snapshot(tmp_path):
    data = test_reports.InteractiveReportTests()._report(tmp_path)
    def normalize(value):
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()
                    if key not in {"generated_at", "observed_at", "first_seen", "last_seen"}}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value
    digest = hashlib.sha256(json.dumps(normalize(data), sort_keys=True).encode()).hexdigest()
    assert digest == "f949d6ad2fe98dadbd4a3c02e3b49a7955cc57c8134c21cdb64df72658f68e03"
