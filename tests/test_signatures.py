from __future__ import annotations

import unittest

from cachaza.signatures import generate_signatures, normalize_fingerprint


class SignatureTests(unittest.TestCase):
    def test_generates_core_queries(self) -> None:
        values = generate_signatures(["example.com"], ["Example Corp"])
        queries = {item.query for item in values}
        self.assertIn('ssl:"example.com"', queries)
        self.assertIn('hostname:"example.com"', queries)
        self.assertIn('org:"Example Corp"', queries)
        self.assertTrue(any('http.title:"Index of /"' in item for item in queries))

    def test_fingerprint_normalization(self) -> None:
        raw = ":".join(["AA"] * 20)
        self.assertEqual(normalize_fingerprint(raw), "aa" * 20)
        values = generate_signatures([], fingerprints=[raw])
        self.assertEqual(values[0].query, f'ssl.cert.fingerprint:"{"aa" * 20}"')


if __name__ == "__main__":
    unittest.main()
