from __future__ import annotations

import unittest

from cachaza.adapters.waf import NUCLEI_WAF_TEMPLATE, build_nuclei_waf_argv
from cachaza.network_policy import (
    NetworkPolicyError,
    constrained_environment,
    enforce_tool_limits,
)


class NetworkPolicyTests(unittest.TestCase):
    def test_nuclei_waf_limits_are_forced_to_one(self) -> None:
        source = build_nuclei_waf_argv(
            "nuclei", "https://example.com", timeout=20, silent=True
        )
        self.assertIn("-silent", source)
        source[source.index("-rl") + 1] = "50"
        source[source.index("-bulk-size") + 1] = "25"
        source[source.index("-c") + 1] = "25"
        argv = enforce_tool_limits(source)
        self.assertEqual(argv[argv.index("-rl") + 1], "1")
        self.assertEqual(argv[argv.index("-bulk-size") + 1], "1")
        self.assertEqual(argv[argv.index("-c") + 1], "1")

    def test_general_nuclei_commands_are_rejected(self) -> None:
        with self.assertRaisesRegex(NetworkPolicyError, "general scanning options"):
            enforce_tool_limits(
                ["nuclei", "-u", "https://example.com", "-tags", "cve,misconfig"]
            )
        with self.assertRaisesRegex(NetworkPolicyError, "only permitted template"):
            enforce_tool_limits(
                ["nuclei", "-u", "https://example.com", "-t", "cves/"]
            )

    def test_nuclei_rejects_template_aliases_directories_lists_and_extra_targets(self) -> None:
        safe = build_nuclei_waf_argv(
            "nuclei", "https://example.com", timeout=20, silent=True
        )
        unsafe_variants = (
            safe + ["-templates", NUCLEI_WAF_TEMPLATE],
            safe + ["-template-directory", "http/"],
            safe + ["-l", "urls.txt"],
            safe + ["https://api.example.com"],
        )
        for argv in unsafe_variants:
            with self.subTest(argv=argv):
                with self.assertRaises(NetworkPolicyError):
                    enforce_tool_limits(argv)

    def test_only_exact_waf_template_and_origin_are_accepted(self) -> None:
        argv = build_nuclei_waf_argv(
            "nuclei", "https://example.com/login", timeout=20, silent=False
        )
        self.assertEqual(argv[argv.index("-u") + 1], "https://example.com")
        self.assertEqual(argv[argv.index("-t") + 1], NUCLEI_WAF_TEMPLATE)
        self.assertEqual(argv.count("-t"), 1)
        for forbidden in (
            "-tags",
            "-severity",
            "-as",
            "-l",
            "-workflows",
            "-automatic-scan",
        ):
            self.assertNotIn(forbidden, argv)
        self.assertEqual(argv[argv.index("-rl") + 1], "1")
        self.assertEqual(argv[argv.index("-bulk-size") + 1], "1")
        self.assertEqual(argv[argv.index("-c") + 1], "1")
        self.assertEqual(argv[argv.index("-retries") + 1], "0")
        enforce_tool_limits(argv)

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
