"""HTML, Markdown, CSV and JSON outputs."""

from __future__ import annotations

import csv
import html
import io
import json
from dataclasses import dataclass

from .model import Campaign, Ranked


@dataclass
class Result:
    ranked: list[Ranked]
    campaigns: list[Campaign]
    top: int
    headline: str
    points: list[str]
    summary_source: str
    sources: list[str]
    kev_info: str
    inventory_size: int

    @property
    def top_items(self) -> list[Ranked]:
        return self.ranked[: self.top]


def _host(r: Ranked) -> str:
    f = r.finding
    name = r.asset.name if r.asset else (f.hostname or "")
    return f"{f.host} ({name})" if name and name != f.host else f.host


def _flags(r: Ranked) -> list[str]:
    out = []
    if r.kev:
        out.append("KEV")
    if r.ransomware:
        out.append("ransomware")
    if r.internet_facing:
        out.append("internet")
    if r.asset is None:
        out.append("unknown asset")
    return out


def markdown(res: Result) -> str:
    out = [f"# Vulnerability fix list", "", f"**{res.headline}**", ""]
    out += [f"- {p}" for p in res.points]
    out += ["", f"_Inputs: {', '.join(res.sources)}. {res.kev_info}. Inventory: {res.inventory_size} entries. "
                f"Summary by {res.summary_source}._", "", f"## Top {len(res.top_items)} to fix", "",
            "| # | Score | Fix within | Host | Finding | Port | CVSS | Why |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for r in res.top_items:
        f = r.finding
        why = "; ".join(r.reasons[1:]) or "CVSS only"
        out.append(f"| {r.rank} | {r.score} | {r.deadline_days} days | {_host(r)} | {f.name} | {f.port} | {f.cvss:.1f} | {why} |")
    if res.campaigns:
        out += ["", "## Fixes that clear several hosts", "", "| Fix | Hosts | Findings | Total score | Fix within |",
                "| --- | --- | --- | --- | --- |"]
        for c in res.campaigns[:10]:
            out.append(f"| {c.title} | {len(c.hosts)} | {len(c.items)} | {c.score} | {c.deadline_days} days |")
    out += ["", "## How to fix the top items", ""]
    for r in res.top_items:
        out += [f"**{r.rank}. {r.finding.name}** on {_host(r)}", "", r.finding.solution or "See the scanner report.", ""]
    return "\n".join(out).rstrip() + "\n"


def to_csv(res: Result) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["rank", "score", "fix_within_days", "host", "hostname", "asset", "owner", "criticality", "internet_facing",
                "port", "finding", "cvss", "cves", "in_kev", "ransomware", "reasons", "solution", "scanner", "id", "source"])
    for r in res.ranked:
        f, a = r.finding, r.asset
        w.writerow([r.rank, r.score, r.deadline_days, f.host, f.hostname or "", a.name if a else "", (a.owner or "") if a else "",
                    a.criticality if a else "", "yes" if r.internet_facing else ("no" if a else "unknown"), f.port, f.name,
                    f"{f.cvss:.1f}", " ".join(f.cves), " ".join(r.kev), "yes" if r.ransomware else "", "; ".join(r.reasons),
                    f.solution or "", f.scanner, f.vuln_id, f.source_file])
    return buf.getvalue()


def to_json(res: Result) -> str:
    def item(r: Ranked) -> dict:
        f = r.finding
        return {"rank": r.rank, "score": r.score, "fix_within_days": r.deadline_days, "host": f.host, "hostname": f.hostname,
                "asset": r.asset.name if r.asset else None, "owner": r.asset.owner if r.asset else None,
                "internet_facing": r.internet_facing if r.asset else None, "port": f.port, "finding": f.name,
                "cvss": f.cvss, "cves": f.cves, "kev": r.kev, "ransomware": r.ransomware, "reasons": r.reasons,
                "solution": f.solution, "scanner": f.scanner, "id": f.vuln_id}

    return json.dumps({
        "headline": res.headline, "points": res.points, "summary_source": res.summary_source, "sources": res.sources,
        "kev": res.kev_info, "top": [item(r) for r in res.top_items], "all": [item(r) for r in res.ranked],
        "campaigns": [{"fix": c.title, "solution": c.solution, "hosts": c.hosts, "findings": len(c.items), "score": c.score,
                       "fix_within_days": c.deadline_days} for c in res.campaigns],
    }, indent=2, ensure_ascii=False)


_CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#17181c;--muted:#5d6068;--line:#e3e3df;--chip:#efefec;
--kev:#b42318;--net:#8a4b00;--ok:#2f6f3e;--bar:#c2410c}
@media (prefers-color-scheme:dark){:root{--bg:#111214;--card:#1a1b1f;--ink:#eeeff1;--muted:#a2a5ad;--line:#2c2e33;--chip:#26282d;
--kev:#ff8b80;--net:#f2b54a;--ok:#7bd88f;--bar:#fb923c}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 16px 64px}h1{font-size:28px;margin:0 0 4px}h2{font-size:19px;margin:32px 0 12px}
.lead{font-size:18px;font-weight:600;margin:12px 0 4px}.muted{color:var(--muted);font-size:13px}ul{padding-left:20px;margin:8px 0}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:12px}
table{width:100%;border-collapse:collapse;min-width:820px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:13px}tr:last-child td{border-bottom:0}td.n{font-variant-numeric:tabular-nums;white-space:nowrap}
.score{display:flex;align-items:center;gap:8px}.score i{display:block;height:6px;border-radius:3px;background:var(--bar)}
.chip{display:inline-block;font-size:11px;font-weight:600;border-radius:999px;padding:1px 8px;margin:0 4px 4px 0;background:var(--chip)}
.chip.KEV,.chip.ransomware{color:var(--kev)}.chip.internet{color:var(--net)}.why{color:var(--muted);font-size:13px}
.host{white-space:nowrap}
"""


def html_report(res: Result) -> str:
    e = html.escape
    top_score = max((r.score for r in res.top_items), default=1) or 1
    rows = []
    for r in res.top_items:
        f = r.finding
        chips = "".join(f'<span class="chip {e(x.split()[0])}">{e(x)}</span>' for x in _flags(r))
        rows.append(
            f'<tr><td class=n>{r.rank}</td><td class=n><div class=score><i style="width:{int(60 * r.score / top_score)}px"></i>{r.score}</div></td>'
            f"<td class=n>{r.deadline_days} days</td><td class=host>{e(_host(r))}<br><span class=muted>{e(f.port)}</span></td>"
            f"<td>{e(f.name)}<br>{chips}<div class=why>{e('; '.join(r.reasons))}</div></td><td class=n>{f.cvss:.1f}</td></tr>")
    camp = ""
    if res.campaigns:
        crow = "".join(f"<tr><td>{e(c.title)}<div class=why>{e(c.solution[:220])}</div></td><td class=n>{len(c.hosts)}</td>"
                       f"<td class=n>{len(c.items)}</td><td class=n>{c.score}</td><td class=n>{c.deadline_days} days</td></tr>"
                       for c in res.campaigns[:10])
        camp = (f"<h2>Fixes that clear several hosts</h2><div class=wrap><table><thead><tr><th>Fix</th><th>Hosts</th><th>Findings</th>"
                f"<th>Total score</th><th>Fix within</th></tr></thead><tbody>{crow}</tbody></table></div>")
    points = "".join(f"<li>{e(p)}</li>" for p in res.points)
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>Vulnerability fix list</title><style>{_CSS}</style></head><body><main><h1>Vulnerability fix list</h1>"
            f'<p class="lead">{e(res.headline)}</p><ul>{points}</ul>'
            f'<p class="muted">Inputs: {e(", ".join(res.sources))}. {e(res.kev_info)}. Inventory: {res.inventory_size} entries. '
            f"Summary by {e(res.summary_source)}.</p>"
            f"<h2>Top {len(res.top_items)} to fix</h2><div class=wrap><table><thead><tr><th>#</th><th>Score</th><th>Fix within</th>"
            f"<th>Host</th><th>Finding and why it ranks here</th><th>CVSS</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
            f"{camp}</main></body></html>\n")
