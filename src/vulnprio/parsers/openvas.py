"""OpenVAS / Greenbone XML reports (the XML report format, or a raw get_reports response)."""

from __future__ import annotations

import re

from defusedxml import ElementTree as ET

from ..model import Finding

CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def _text(el, path: str) -> str | None:
    x = el.find(path)
    return x.text.strip() if x is not None and x.text and x.text.strip() else None


def _float(v: str | None) -> float:
    try:
        return max(0.0, min(10.0, float(v)))
    except (TypeError, ValueError):
        return 0.0


def _tag(tags: str | None, key: str) -> str | None:
    for part in (tags or "").split("|"):
        k, _, v = part.partition("=")
        if k.strip() == key and v.strip():
            return v.strip()
    return None


def parse_xml(text: str) -> list[Finding]:
    root = ET.fromstring(text)
    out = []
    for r in root.iter("result"):
        nvt = r.find("nvt")
        host_el = r.find("host")
        if nvt is None or host_el is None:
            continue
        host = (host_el.text or "").strip()
        if not host:
            continue
        sev = _float(_text(r, "severity"))
        if sev == 0.0:
            sev = _float(_text(nvt, "cvss_base"))
        cves = [ref.get("id", "").upper() for ref in nvt.iter("ref") if ref.get("type", "").lower() == "cve"]
        if not cves:  # older reports: <cve>CVE-a, CVE-b</cve>
            cves = [c.upper() for c in CVE.findall(_text(nvt, "cve") or "")]
        tags = _text(nvt, "tags")
        out.append(Finding(
            scanner="openvas",
            host=host,
            hostname=_text(host_el, "hostname"),
            port=_text(r, "port") or "general/tcp",
            name=_text(nvt, "name") or _text(r, "name") or "Unnamed result",
            vuln_id=nvt.get("oid", ""),
            cvss=sev,
            cves=sorted(set(cves)),
            solution=_text(nvt, "solution") or _tag(tags, "solution"),
            summary=_tag(tags, "summary"),
        ))
    return out
