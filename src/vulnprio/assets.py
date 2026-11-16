"""Asset inventory: how important each host is and whether the internet can reach it.

assets.csv columns (header names are case-insensitive):

    host            IP, CIDR range or hostname
    name            what it is ("Payroll DB")
    criticality     critical, high, medium or low
    internet_facing yes / no
    owner           optional, who fixes it

The most specific entry wins: a hostname or single IP beats a /24, a /24
beats a /16.
"""

from __future__ import annotations

import csv
import ipaddress
from pathlib import Path

from .model import Asset

CRITICALITY = ("critical", "high", "medium", "low")
_YES = {"yes", "y", "true", "1", "internet", "public", "external"}


class Inventory:
    def __init__(self, assets: list[Asset]):
        self.by_name: dict[str, Asset] = {}
        self.by_net: list[tuple[ipaddress._BaseNetwork, Asset]] = []
        for a in assets:
            try:
                self.by_net.append((ipaddress.ip_network(a.match, strict=False), a))
            except ValueError:
                self.by_name[a.match.lower()] = a
        self.by_net.sort(key=lambda x: x[0].prefixlen, reverse=True)

    @classmethod
    def empty(cls) -> "Inventory":
        return cls([])

    @classmethod
    def load(cls, path: str | Path) -> "Inventory":
        text = Path(path).read_text(encoding="utf-8-sig")
        rows = csv.DictReader(text.splitlines())
        assets, problems = [], []
        for n, row in enumerate(rows, 2):
            row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            if not row.get("host"):
                continue
            crit = (row.get("criticality") or "medium").lower()
            if crit not in CRITICALITY:
                problems.append(f"line {n}: criticality '{crit}' is not one of {', '.join(CRITICALITY)}")
                continue
            assets.append(Asset(row["host"], row.get("name") or row["host"], crit,
                                (row.get("internet_facing") or "").lower() in _YES, row.get("owner") or None))
        if problems:
            raise ValueError(f"{Path(path).name}: " + "; ".join(problems))
        return cls(assets)

    def __len__(self) -> int:
        return len(self.by_name) + len(self.by_net)

    def find(self, host: str, hostname: str | None = None) -> Asset | None:
        for key in (hostname, host):
            if key and key.lower() in self.by_name:
                return self.by_name[key.lower()]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        for net, asset in self.by_net:
            if ip.version == net.version and ip in net:
                return asset
        return None
