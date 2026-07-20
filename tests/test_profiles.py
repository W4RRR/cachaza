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
        stages = [item["name"] for item in data["stages"]]
        self.assertNotIn("nuclei", stages)
        for required in ("gau", "crawl", "js", "waf"):
            self.assertIn(required, stages)
        self.assertLess(stages.index("http"), stages.index("waf"))

    def test_removed_general_nuclei_stage_returns_actionable_error(self) -> None:
        for command in ("run", "plan"):
            errors = io.StringIO()
            args = [command, "-d", "example.com", "-stages", "nuclei", "-active"]
            if command == "run":
                args.append("-dry-run")
            with contextlib.redirect_stderr(errors):
                code = main(args)
            self.assertEqual(code, 2)
            self.assertIn("general Nuclei stage has been removed", errors.getvalue())
            self.assertIn("-stages waf -waf-tools nuclei -active", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
