"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The catalog lists CVEs that CISA has evidence of being exploited in the
wild. It's the single best signal for "fix this first". Download it with
`vulnprio update-kev`; it changes most weeks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# CISA's own GitHub mirror of the same catalog, used when cisa.gov can't be reached (some networks block it).
KEV_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class KevEntry:
    cve: str
    ransomware: bool
    name: str


class Kev:
    def __init__(self, entries: dict[str, KevEntry], version: str | None = None, source: str = ""):
        self.entries = entries
        self.version = version
        self.source = source

    @classmethod
    def empty(cls) -> "Kev":
        return cls({}, None, "none")

    @classmethod
    def from_json(cls, data: dict, source: str = "") -> "Kev":
        vulns = data.get("vulnerabilities")
        if not isinstance(vulns, list):
            raise ValueError("not a KEV catalog: no 'vulnerabilities' list")
        entries = {}
        for v in vulns:
            cve = str(v.get("cveID", "")).upper().strip()
            if cve:
                entries[cve] = KevEntry(cve, str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                                        str(v.get("vulnerabilityName", "")))
        return cls(entries, data.get("catalogVersion"), source)

    @classmethod
    def load(cls, path: str | Path) -> "Kev":
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")), str(path))

    def __contains__(self, cve: str) -> bool:
        return cve.upper() in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, cve: str) -> KevEntry | None:
        return self.entries.get(cve.upper())


def download(dest: str | Path, url: str = KEV_URL, client: httpx.Client | None = None) -> Kev:
    client = client or httpx.Client(timeout=60, follow_redirects=True)
    urls = [url] + ([KEV_MIRROR] if url == KEV_URL else [])
    for i, u in enumerate(urls):
        try:
            resp = client.get(u)
            resp.raise_for_status()
            data = resp.json()
            url = u
            break
        except (httpx.HTTPError, ValueError):
            if i == len(urls) - 1:
                raise
    kev = Kev.from_json(data, url)  # validate before overwriting a working copy
    if len(kev) < 100 and url in (KEV_URL, KEV_MIRROR):
        raise ValueError(f"downloaded catalog has only {len(kev)} entries; refusing to replace the local copy")
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(dest)
    return kev
