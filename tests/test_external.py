from __future__ import annotations

import contextlib
import io
import sys
import unittest

from cachaza.console import Console
from cachaza.external import CommandRunner


class ExternalRunnerTests(unittest.TestCase):
    def test_console_keeps_colors_when_stderr_is_redirected(self) -> None:
        terminal = io.StringIO()
        with contextlib.redirect_stderr(terminal):
            Console(color=True).info("colored")
        self.assertIn("\x1b[32m", terminal.getvalue())

    def test_verbose_streams_and_still_captures_tool_output(self) -> None:
        console = Console(verbose=1, silent=False, color=False)
        runner = CommandRunner(console, timeout=10)
        terminal = io.StringIO()
        with contextlib.redirect_stderr(terminal):
            result = runner.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; print('stdout-finding'); print('stderr-progress', file=sys.stderr)",
                ]
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn("stdout-finding", result.stdout)
        self.assertIn("stderr-progress", result.stderr)
        self.assertIn("stdout-finding", terminal.getvalue())
        self.assertIn("stderr-progress", terminal.getvalue())


if __name__ == "__main__":
    unittest.main()
