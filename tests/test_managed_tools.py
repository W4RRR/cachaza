from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cachaza import jsmap_cli
from cachaza.adapters import csp_stalker
from cachaza.managed_tools import GO_TOOL_MODULES, install_go_tool, install_missing_tools


class ManagedToolTests(unittest.TestCase):
    def test_alterx_and_uncover_use_official_go_modules_and_local_bin(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            calls: list[tuple[list[str], dict[str, str]]] = []

            def run(argv, *, env, check):  # noqa: ANN001
                name = "alterx" if "alterx/cmd/alterx" in argv[-1] else "uncover"
                executable = home / ".local" / "bin" / (
                    f"{name}.exe" if os.name == "nt" else name
                )
                executable.write_text("binary", encoding="utf-8")
                calls.append((argv, env))

            with (
                patch("cachaza.managed_tools.Path.home", return_value=home),
                patch("cachaza.managed_tools.shutil.which", return_value="/usr/bin/go"),
                patch("cachaza.managed_tools.subprocess.run", side_effect=run),
            ):
                self.assertIn("alterx", install_go_tool("alterx"))
                self.assertIn("uncover", install_go_tool("uncover"))

            self.assertEqual(
                calls[0][0],
                ["/usr/bin/go", "install", "-v", GO_TOOL_MODULES["alterx"]],
            )
            self.assertEqual(
                calls[1][0],
                ["/usr/bin/go", "install", "-v", GO_TOOL_MODULES["uncover"]],
            )
            self.assertEqual(calls[0][1]["GOBIN"], str(home / ".local" / "bin"))
            self.assertEqual(calls[0][1]["GOMAXPROCS"], "2")

    def test_install_missing_tools_only_invokes_absent_recipes(self) -> None:
        missing = {"alterx", "uncover"}

        def finder(name: str) -> str | None:
            return None if name in missing else f"/already/{name}"

        with patch(
            "cachaza.managed_tools.install_go_tool",
            side_effect=lambda name: f"/installed/{name}",
        ) as install:
            results = install_missing_tools(finder)
        installed = {item.name for item in results if item.status == "installed"}
        self.assertEqual(installed, missing)
        self.assertEqual([call.args[0] for call in install.call_args_list], ["alterx", "uncover"])

    def test_csp_stalker_adapter_matches_upstream_cli(self) -> None:
        argv = csp_stalker.build_argv("/home/kali/.local/bin/csp-stalker", "https://example.com")
        self.assertEqual(argv, ["/home/kali/.local/bin/csp-stalker", "-u", "https://example.com"])
        self.assertNotIn("-o", argv)

    def test_builtin_jsmap_analyzer_extracts_urls_and_secret_hints(self) -> None:
        script = b"console.log('ok');\n//# sourceMappingURL=app.js.map\n"
        source_map = json.dumps(
            {
                "sources": ["webpack:///src/app.js"],
                "sourcesContent": [
                    "const api_key = value; fetch('https://api.example.com/v1');"
                ],
            }
        ).encode()
        with patch("cachaza.jsmap_cli._fetch", side_effect=[script, source_map]):
            record = jsmap_cli.analyze_url("https://example.com/assets/app.js")
        self.assertEqual(record["sourcemap_url"], "https://example.com/assets/app.js.map")
        self.assertEqual(record["urls"], ["https://api.example.com/v1"])
        self.assertEqual(record["secret_hints"][0]["kind"], "api_key")


if __name__ == "__main__":
    unittest.main()
