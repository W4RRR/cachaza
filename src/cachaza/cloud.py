"""Efficient longest-prefix cloud/provider classification."""

from __future__ import annotations

import ipaddress
from pathlib import Path


class RangeIndex:
    """Longest-prefix-match index for IPv4 and IPv6 networks."""

    def __init__(self, networks: dict[int, dict[int, dict[int, str]]]) -> None:
        self._networks = networks
        self._prefixes = {
            version: sorted(values, reverse=True) for version, values in networks.items()
        }

    @classmethod
    def from_file(cls, path: Path) -> "RangeIndex":
        networks: dict[int, dict[int, dict[int, str]]] = {4: {}, 6: {}}
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(maxsplit=1)
                if len(parts) != 2:
                    continue
                try:
                    network = ipaddress.ip_network(parts[0], strict=False)
                except ValueError:
                    continue
                networks[network.version].setdefault(network.prefixlen, {})[
                    int(network.network_address)
                ] = parts[1].strip()
        return cls(networks)

    @classmethod
    def from_provider_networks(
        cls, values: dict[str, list[ipaddress._BaseNetwork]]
    ) -> "RangeIndex":
        networks: dict[int, dict[int, dict[int, str]]] = {4: {}, 6: {}}
        for provider, entries in values.items():
            for network in entries:
                networks[network.version].setdefault(network.prefixlen, {})[
                    int(network.network_address)
                ] = provider
        return cls(networks)

    def lookup(self, address: ipaddress._BaseAddress) -> str | None:
        by_prefix = self._networks.get(address.version, {})
        needle = int(address)
        bits = address.max_prefixlen
        for prefixlen in self._prefixes.get(address.version, []):
            host_bits = bits - prefixlen
            start = (needle >> host_bits) << host_bits if host_bits else needle
            provider = by_prefix[prefixlen].get(start)
            if provider is not None:
                return provider
        return None

