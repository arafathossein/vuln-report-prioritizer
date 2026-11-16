from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """One vulnerability on one host and port, as the scanner reported it."""

    scanner: str  # "openvas" or "nessus"
    host: str  # IP address as reported
    hostname: str | None
    port: str  # e.g. "443/tcp", "general/tcp"
    name: str
    vuln_id: str  # NVT OID or Nessus plugin ID
    cvss: float  # best available base score, 0-10
    cves: list[str] = field(default_factory=list)
    solution: str | None = None
    summary: str | None = None
    exploit_available: bool = False  # scanner says a public exploit exists (Nessus)
    source_file: str = ""


@dataclass
class Asset:
    match: str  # IP, CIDR or hostname from the inventory
    name: str
    criticality: str  # critical, high, medium, low
    internet_facing: bool
    owner: str | None = None


@dataclass
class Ranked:
    finding: Finding
    score: int
    reasons: list[str]
    asset: Asset | None
    kev: list[str]  # CVEs from the finding that are in CISA KEV
    ransomware: bool  # KEV marks one of them as used in ransomware campaigns
    deadline_days: int
    rank: int = 0

    @property
    def internet_facing(self) -> bool:
        return bool(self.asset and self.asset.internet_facing)


@dataclass
class Campaign:
    """One fix that clears several findings, e.g. the same upgrade on 12 hosts."""

    title: str
    solution: str
    items: list[Ranked]

    @property
    def score(self) -> int:
        return sum(r.score for r in self.items)

    @property
    def hosts(self) -> list[str]:
        return sorted({r.finding.host for r in self.items})

    @property
    def deadline_days(self) -> int:
        return min(r.deadline_days for r in self.items)
