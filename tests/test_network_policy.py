from __future__ import annotations

import unittest

from cachaza.network_policy import constrained_environment, enforce_tool_limits


class NetworkPolicyTests(unittest.TestCase):
    def test_nuclei_limits_are_added_or_capped(self) -> None:
        argv = enforce_tool_limits(
            ["nuclei", "-u", "https://example.com", "-rl", "50", "-c", "25"]
        )
        self.assertEqual(argv[argv.index("-rl") + 1], "2")
        self.assertEqual(argv[argv.index("-c") + 1], "2")
        for option in ("-bulk-size", "-hbs", "-headc", "-jsc", "-pc", "-prc", "-tlc"):
            self.assertEqual(argv[argv.index(option) + 1], "2")

    def test_active_tool_limits_cannot_exceed_two(self) -> None:
        cases = (
            (["subfinder", "-d", "example.com", "-rl", "100", "-t", "20"], "-rl", "-t"),
            (["dnsx", "-l", "targets.txt", "-rl", "100", "-t", "20"], "-rl", "-t"),
            (["httpx", "-l", "targets.txt", "-rl", "100", "-t", "20"], "-rl", "-t"),
            (["naabu", "-host", "example.com", "-rate", "100", "-c", "20"], "-rate", "-c"),
            (["katana", "-u", "https://example.com", "-rate-limit", "100", "-concurrency", "20"], "-rate-limit", "-concurrency"),
            (["nmap", "-Pn", "example.com", "--max-rate", "100", "--max-parallelism", "20"], "--max-rate", "--max-parallelism"),
        )
        for source, rate_flag, worker_flag in cases:
            with self.subTest(tool=source[0]):
                argv = enforce_tool_limits(source)
                self.assertEqual(argv[argv.index(rate_flag) + 1], "2")
                self.assertEqual(argv[argv.index(worker_flag) + 1], "2")

    def test_subprocess_worker_environment_is_forced_to_two(self) -> None:
        values = constrained_environment({"GOMAXPROCS": "99", "OMP_NUM_THREADS": "99"})
        for name in (
            "CACHAZA_MAX_REQUESTS_PER_SECOND",
            "CACHAZA_MAX_CONCURRENCY",
            "GOMAXPROCS",
            "OMP_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
            "NUMEXPR_NUM_THREADS",
            "RAYON_NUM_THREADS",
            "UV_THREADPOOL_SIZE",
        ):
            self.assertEqual(values[name], "2")


if __name__ == "__main__":
    unittest.main()
