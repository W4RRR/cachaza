from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cachaza.cli import main


class ResumeTests(unittest.TestCase):
    def test_resume_uses_completed_stage_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            args = [
                "run", "-d", "example.com", "-stages", "corporate",
                "-o", str(root), "-format", "json", "-silent",
            ]
            self.assertEqual(main(args), 0)
            self.assertTrue((root / "rest" / "stages" / "corporate.json").is_file())
            self.assertEqual(main(args + ["-resume"]), 0)
            manifest = json.loads((root / "rest" / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["stages"][0]["status"], "cached")

    def test_fresh_resets_only_verified_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            base = [
                "run", "-d", "example.com", "-stages", "corporate",
                "-o", str(root), "-format", "json", "-silent",
            ]
            self.assertEqual(main(base), 0)
            marker = root / "rest" / "old-marker.txt"
            marker.write_text("old", encoding="utf-8")
            self.assertEqual(main(base + ["-fresh"]), 0)
            self.assertFalse(marker.exists())
            self.assertTrue((root / "rest" / "scope.json").is_file())

    def test_resume_can_extend_stage_selection_without_repeating_valid_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            base = [
                "run", "-d", "example.com", "-shodan-mode", "off",
                "-o", str(root), "-format", "json", "-silent",
            ]
            self.assertEqual(main(base + ["-stages", "corporate"]), 0)
            self.assertEqual(
                main(base + ["-stages", "corporate,shodan", "-resume"]),
                0,
            )
            manifest = json.loads((root / "rest" / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["stages"][0]["status"], "cached")
            self.assertEqual(manifest["stages"][1]["name"], "shodan")


if __name__ == "__main__":
    unittest.main()
