from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

from cachaza.cloud import RangeIndex


class RangeIndexTests(unittest.TestCase):
    def test_longest_prefix_and_ipv6(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ranges.txt"
            path.write_text(
                "10.0.0.0/8 broad provider\n"
                "10.20.0.0/16 specific provider\n"
                "2001:db8::/32 ipv6 provider\n"
                "not-a-cidr ignored\n",
                encoding="utf-8",
            )
            index = RangeIndex.from_file(path)
            self.assertEqual(index.lookup(ipaddress.ip_address("10.20.4.5")), "specific provider")
            self.assertEqual(index.lookup(ipaddress.ip_address("10.30.4.5")), "broad provider")
            self.assertEqual(index.lookup(ipaddress.ip_address("2001:db8::1")), "ipv6 provider")
            self.assertIsNone(index.lookup(ipaddress.ip_address("192.0.2.1")))


if __name__ == "__main__":
    unittest.main()

