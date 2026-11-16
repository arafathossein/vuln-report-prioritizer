"""Scanner report parsers.

XML is parsed with defusedxml: scan reports come from other systems and
other people, and a plain XML parser can be abused (entity expansion,
external entities). A report that tries either is refused.
"""

from __future__ import annotations

from pathlib import Path

from ..model import Finding
from . import csvfmt, nessus, openvas


def detect(path: Path, head: str) -> str:
    h = head.lstrip()[:4000]
    if "<NessusClientData_v2" in h:
        return "nessus"
    if h.startswith("<") and ("<report" in h or "<get_reports_response" in h):
        return "openvas"
    first = h.splitlines()[0] if h else ""
    if "Plugin ID" in first and "Host" in first:
        return "nessus-csv"
    if "NVT OID" in first or ("IP" in first and "NVT Name" in first):
        return "openvas-csv"
    raise ValueError(f"{path.name}: not a recognised OpenVAS or Nessus report (XML or CSV export)")


def parse_file(path: str | Path) -> list[Finding]:
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    kind = detect(path, text)
    if kind == "nessus":
        found = nessus.parse_xml(text)
    elif kind == "openvas":
        found = openvas.parse_xml(text)
    else:
        found = csvfmt.parse(text, kind)
    for f in found:
        f.source_file = path.name
    return found
