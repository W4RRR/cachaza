from __future__ import annotations

import contextlib
import io
import json
import unittest

from cachaza.cli import main
from cachaza.profiles import PROFILES, profile_stages


class ProfileTests(unittest.TestCase):
    def test_passive_is_default_and_contains_no_direct_stage(self) -> None:
        stages = profile_stages("passive")
        self.assertEqual(stages[0], "corporate")
        self.assertIn("gau", stages)
        self.assertNotIn("http", stages)
        self.assertFalse(PROFILES["passive"].requires_active)

    def test_safe_and_full_require_active_gate(self) -> None:
        for profile in ("safe", "full"):
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                code = main(["run", "-d", "example.com", "-profile", profile, "-dry-run"])
            self.assertEqual(code, 2)
            self.assertIn("requires -active", errors.getvalue())

    def test_plan_reports_profile_and_blocked_stages(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["plan", "-d", "example.com", "-profile", "full", "-json"])
        self.assertEqual(code, 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data["profile"], "full")
        self.assertIn("nuclei", [item["name"] for item in data["stages"]])


if __name__ == "__main__":
    unittest.main()

