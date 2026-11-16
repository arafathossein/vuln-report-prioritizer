"""CSV exports from Nessus and OpenVAS/Greenbone.

Column names differ between versions, so each field is looked up by a few
known header names.
"""

from __future__ import annotations

import csv
import io
import re

from ..model import Finding

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _get(row: dict, *names: str) -> str:
    for n in names:
        v = row.get(n)
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def _score(*values: str) -> float:
    for v in values:
        try:
            return max(0.0, min(10.0, float(v)))
        except (TypeError, ValueError):
            continue
    return 0.0


_RISK = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "none": 0.0, "log": 0.0}


def parse(text: str, kind: str) -> list[Finding]:
    rows = csv.DictReader(io.StringIO(text))
    out = []
    for row in rows:
        if kind == "nessus-csv":
            host = _get(row, "Host", "IP Address")
            if not host:
                continue
            risk = _get(row, "Risk").lower()
            score = _score(_get(row, "CVSS v3.0 Base Score"), _get(row, "CVSS v2.0 Base Score", "CVSS"))
            if score == 0.0:
                score = _RISK.get(risk, 0.0)
            proto, port = _get(row, "Protocol") or "tcp", _get(row, "Port") or "0"
            out.append(Finding(
                scanner="nessus", host=host, hostname=_get(row, "FQDN", "DNS Name") or None, port=f"{port}/{proto}",
                name=_get(row, "Name", "Plugin Name") or "Unnamed plugin", vuln_id=_get(row, "Plugin ID"),
                cvss=score, cves=sorted({c.upper() for c in CVE.findall(_get(row, "CVE"))}),
                solution=_get(row, "Solution") or None, summary=_get(row, "Synopsis") or None,
                exploit_available=_get(row, "Exploit?", "Exploitable").lower() in ("true", "yes"),
            ))
        else:
            host = _get(row, "IP", "Host")
            if not host:
                continue
            port, proto = _get(row, "Port"), _get(row, "Port Protocol") or "tcp"
            out.append(Finding(
                scanner="openvas", host=host, hostname=_get(row, "Hostname") or None,
                port=f"{port}/{proto}" if port else f"general/{proto}",
                name=_get(row, "NVT Name", "Name") or "Unnamed result", vuln_id=_get(row, "NVT OID", "OID"),
                cvss=_score(_get(row, "CVSS", "Severity Score")),
                cves=sorted({c.upper() for c in CVE.findall(_get(row, "CVEs", "CVE"))}),
                solution=_get(row, "Solution") or None, summary=_get(row, "Summary") or None,
            ))
    return out
