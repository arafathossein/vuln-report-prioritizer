"""Scoring: open, additive and explained.

Every point comes with a reason a person can check. The weights are
deliberately simple so a security lead can argue with them; change them in
Weights if your policy differs.

    CVSS base score x 10             0-100
    CVE in CISA KEV                  +60
      ...used in ransomware          +15 more
    Public exploit (scanner says)    +15  (only when not already in KEV)
    Internet-facing asset            +30
    Asset criticality                +30 critical, +20 high, +10 medium, 0 low
    Asset not in the inventory       +10  (unknown is not the same as safe)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .assets import Inventory
from .kev import Kev
from .model import Campaign, Finding, Ranked


@dataclass
class Weights:
    kev: int = 60
    ransomware: int = 15
    exploit: int = 15
    internet: int = 30
    criticality: tuple[tuple[str, int], ...] = (("critical", 30), ("high", 20), ("medium", 10), ("low", 0))
    unknown_asset: int = 10


@dataclass
class Deadlines:
    """Suggested days to fix. A starting point for your own policy, not a standard."""

    kev_internet: int = 7
    kev: int = 14
    critical_internet: int = 14
    high: int = 30
    other: int = 90


def _deadline(f: Finding, kev_hit: bool, internet: bool, d: Deadlines) -> int:
    if kev_hit:
        return d.kev_internet if internet else d.kev
    if f.cvss >= 9.0 and internet:
        return d.critical_internet
    if f.cvss >= 7.0:
        return d.high
    return d.other


def score_one(f: Finding, inv: Inventory, kev: Kev, w: Weights = Weights(), d: Deadlines = Deadlines()) -> Ranked:
    reasons = [f"CVSS {f.cvss:.1f}"]
    score = round(f.cvss * 10)
    kev_hits = [c for c in f.cves if c in kev]
    ransomware = any(kev.get(c).ransomware for c in kev_hits)
    if kev_hits:
        score += w.kev
        reasons.append(f"In CISA KEV ({', '.join(kev_hits)})")
        if ransomware:
            score += w.ransomware
            reasons.append("Used in ransomware campaigns")
    elif f.exploit_available:
        score += w.exploit
        reasons.append("Public exploit available")
    asset = inv.find(f.host, f.hostname)
    if asset is None:
        if len(inv):
            score += w.unknown_asset
            reasons.append("Host not in the asset inventory")
    else:
        if asset.internet_facing:
            score += w.internet
            reasons.append("Internet-facing")
        bonus = dict(w.criticality).get(asset.criticality, 0)
        if bonus:
            score += bonus
            reasons.append(f"{asset.criticality.title()} asset ({asset.name})")
    return Ranked(f, score, reasons, asset, kev_hits, ransomware, _deadline(f, bool(kev_hits), bool(asset and asset.internet_facing), d))


def rank(findings: list[Finding], inv: Inventory, kev: Kev, min_cvss: float = 0.1,
         w: Weights = Weights(), d: Deadlines = Deadlines()) -> list[Ranked]:
    """Score, de-duplicate and sort. Informational results (CVSS 0) are dropped by default."""
    seen: dict[tuple[str, str, str], Ranked] = {}
    for f in findings:
        if f.cvss < min_cvss and not any(c in kev for c in f.cves):
            continue
        r = score_one(f, inv, kev, w, d)
        key = (f.host, f.port, ",".join(f.cves) or f.vuln_id or f.name)  # same issue from two scans counts once
        if key not in seen or r.score > seen[key].score:
            seen[key] = r
    out = sorted(seen.values(), key=lambda r: (-r.score, -r.finding.cvss, r.finding.host, r.finding.name))
    for i, r in enumerate(out, 1):
        r.rank = i
    return out


def _fix_key(r: Ranked) -> str:
    # Same plugin/NVT means the same fix; fall back to the normalised solution text.
    if r.finding.vuln_id:
        return f"{r.finding.scanner}:{r.finding.vuln_id}"
    return re.sub(r"\W+", " ", (r.finding.solution or r.finding.name).lower()).strip()[:120]


def campaigns(ranked: list[Ranked], min_hosts: int = 2) -> list[Campaign]:
    """Group findings that one fix clears on several hosts."""
    groups: dict[str, list[Ranked]] = {}
    for r in ranked:
        groups.setdefault(_fix_key(r), []).append(r)
    out = []
    for items in groups.values():
        if len({r.finding.host for r in items}) < min_hosts:
            continue
        first = items[0].finding
        out.append(Campaign(first.name, first.solution or "See the scanner's solution text.", items))
    return sorted(out, key=lambda c: -c.score)
