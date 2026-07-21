from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cachaza.credentials import (
    load_credentials,
    subfinder_provider_values,
    temporary_harvester_home,
    temporary_subfinder_config,
)


class CredentialTests(unittest.TestCase):
    def test_env_file_is_parsed_as_data_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "should-not-exist"
            path = root / "providers.env"
            path.write_text(
                'export GITHUB_TOKEN="ghp_test"\n'
                'CENSYS_API_KEY="censys_pat"\n'
                f'URLSCAN_API_KEY="$(touch {marker})"\n',
                encoding="utf-8",
            )
            values = load_credentials(path)
            providers = subfinder_provider_values(values)
            self.assertEqual(providers["github"], "ghp_test")
            self.assertEqual(values["CENSYS_API_KEY"], "censys_pat")
            self.assertFalse(marker.exists())

    def test_temporary_provider_file_is_removed(self) -> None:
        with temporary_subfinder_config({"GITHUB_TOKEN": "token"}) as filename:
            self.assertIsNotNone(filename)
            path = Path(str(filename))
            self.assertTrue(path.is_file())
            self.assertIn('"token"', path.read_text(encoding="utf-8"))
        self.assertFalse(path.exists())

    def test_subfinder_intelx_host_accepts_developer_tab_url(self) -> None:
        providers = subfinder_provider_values(
            {
                "INTELX_API_KEY": "intel-key",
                "INTELX_HOST": "https://free.intelx.io/",
            }
        )
        self.assertEqual(providers["intelx"], "free.intelx.io:intel-key")

    def test_harvester_home_maps_single_key_providers_without_touching_home(self) -> None:
        with temporary_harvester_home(
            {"INTELX_API_KEY": "intel-key", "PDCP_API_KEY": "pd-key"}
        ) as home:
            config = Path(home) / ".theHarvester" / "api-keys.yaml"
            payload = config.read_text(encoding="utf-8")
            self.assertIn('"intelx"', payload)
            self.assertIn('"projectDiscovery"', payload)
            self.assertIn('"key": "intel-key"', payload)
        self.assertFalse(Path(home).exists())


if __name__ == "__main__":
    unittest.main()
