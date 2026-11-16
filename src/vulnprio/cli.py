"""Command line.

    vulnprio update-kev                                   # download CISA KEV to data/kev.json
    vulnprio rank scan.xml scan.nessus --assets assets.csv --top 20
    vulnprio demo                                         # bundled sample scans
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from .assets import Inventory
from .kev import KEV_URL, Kev, download
from .parsers import parse_file
from .report import Result, html_report, markdown, to_csv, to_json
from .score import campaigns, rank
from .summary import summarise

DEFAULT_KEV = Path("data/kev.json")


def _llm() -> dict | None:
    base = os.getenv("LLM_BASE_URL")
    if not base:
        return None
    return {"base_url": base, "api_key": os.getenv("LLM_API_KEY", ""), "model": os.getenv("LLM_MODEL", "llama3.1:8b"),
            "mask": os.getenv("MASK_INTERNAL_IPS", "true").lower() != "false"}


def build(files: list[Path], inv: Inventory, kev: Kev, top: int, min_cvss: float, kev_info: str) -> Result:
    findings = [f for p in files for f in parse_file(p)]
    ranked = rank(findings, inv, kev, min_cvss)
    camps = campaigns(ranked)
    headline, points, source = summarise(ranked, camps, top, _llm())
    return Result(ranked, camps, top, headline, points, source, [p.name for p in files], kev_info, len(inv))


def write(res: Result, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "fix-list.md").write_text(markdown(res), encoding="utf-8")
    (out / "fix-list.csv").write_text(to_csv(res), encoding="utf-8")
    (out / "fix-list.json").write_text(to_json(res), encoding="utf-8")
    (out / "fix-list.html").write_text(html_report(res), encoding="utf-8")
    return out / "fix-list.html"


def _print(res: Result) -> None:
    print(res.headline)
    for r in res.top_items[:10]:
        flags = ("KEV " if r.kev else "") + ("internet" if r.internet_facing else "")
        print(f"  {r.rank:>2}. {r.score:>3}  {r.finding.host:<15} {r.finding.name[:52]:<52} {flags}")
    if len(res.top_items) > 10:
        print(f"  ... {len(res.top_items) - 10} more in the report")


def _load_kev(path: str | None) -> tuple[Kev, str]:
    p = Path(path) if path else DEFAULT_KEV
    if p.exists():
        kev = Kev.load(p)
        return kev, f"CISA KEV: {len(kev)} CVEs" + (f" (catalog {kev.version})" if kev.version else "")
    if path:
        raise FileNotFoundError(f"KEV file not found: {path}")
    print("No KEV catalog found; run `vulnprio update-kev` for the strongest ranking signal.", file=sys.stderr)
    return Kev.empty(), "CISA KEV: not loaded"


def cmd_rank(a: argparse.Namespace) -> int:
    try:
        kev, info = _load_kev(a.kev)
        inv = Inventory.load(a.assets) if a.assets else Inventory.empty()
        res = build([Path(f) for f in a.files], inv, kev, a.top, a.min_cvss, info)
    except Exception as exc:  # noqa: BLE001 - report any input problem plainly
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _print(res)
    print(f"\nReport: {write(res, Path(a.out))}")
    if a.fail_on_kev and any(r.kev for r in res.ranked):
        return 2
    return 0


def cmd_update_kev(a: argparse.Namespace) -> int:
    try:
        kev = download(a.out, a.url)
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not update KEV: {exc}", file=sys.stderr)
        return 1
    print(f"Saved {len(kev)} CVEs to {a.out}" + (f" (catalog {kev.version})" if kev.version else ""))
    return 0


def cmd_demo(a: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parents[2] / "samples"
    if not root.exists():
        print("samples/ not found; run the demo from a clone of the repository.", file=sys.stderr)
        return 1
    kev = Kev.load(root / "kev-sample.json")
    res = build(sorted((root / "scans").iterdir()), Inventory.load(root / "assets.csv"), kev, 20, 0.1,
                f"CISA KEV: sample subset of {len(kev)} CVEs")
    _print(res)
    print(f"\nReport: {write(res, Path(a.out))}")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(prog="vulnprio", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("rank", help="Rank findings from one or more scan reports")
    r.add_argument("files", nargs="+", help="OpenVAS XML/CSV or Nessus .nessus/CSV files")
    r.add_argument("--assets", help="Asset inventory CSV (host, name, criticality, internet_facing, owner)")
    r.add_argument("--kev", help=f"KEV JSON file (default {DEFAULT_KEV})")
    r.add_argument("--top", type=int, default=20)
    r.add_argument("--min-cvss", type=float, default=0.1, help="Drop findings below this CVSS unless they are in KEV")
    r.add_argument("--out", default="reports")
    r.add_argument("--fail-on-kev", action="store_true", help="Exit with code 2 if any finding is in KEV")
    r.set_defaults(func=cmd_rank)
    u = sub.add_parser("update-kev", help="Download the CISA KEV catalog")
    u.add_argument("--out", default=str(DEFAULT_KEV))
    u.add_argument("--url", default=KEV_URL)
    u.set_defaults(func=cmd_update_kev)
    d = sub.add_parser("demo", help="Rank the bundled sample scans")
    d.add_argument("--out", default="reports")
    d.set_defaults(func=cmd_demo)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    raise SystemExit(main())
