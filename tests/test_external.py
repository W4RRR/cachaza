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

    def test_captured_timeout_preserves_partial_output(self) -> None:
        runner = CommandRunner(Console(silent=True, color=False), timeout=1)
        result = runner.run(
            [
                sys.executable,
                "-c",
                "import time; print('before-timeout', flush=True); time.sleep(5)",
            ]
        )
        self.assertEqual(result.returncode, 124)
        self.assertIn("before-timeout", result.stdout)
        self.assertIn("Command timed out", result.stderr)

    def test_streaming_timeout_returns_instead_of_hanging(self) -> None:
        runner = CommandRunner(Console(verbose=1, color=False), timeout=1)
        terminal = io.StringIO()
        with contextlib.redirect_stderr(terminal):
            result = runner.run(
                [
                    sys.executable,
                    "-c",
                    "import time; print('streamed', flush=True); time.sleep(5)",
                ]
            )
        self.assertEqual(result.returncode, 124)
        self.assertIn("streamed", result.stdout)
        self.assertIn("Command timed out", result.stderr)
        self.assertIn("Command timed out", terminal.getvalue())


if __name__ == "__main__":
    unittest.main()
