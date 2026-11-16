"""Nessus / Tenable .nessus (v2) files."""

from __future__ import annotations

from defusedxml import ElementTree as ET

from ..model import Finding

# Nessus severity 0-4 when no CVSS score is present
_SEV_FALLBACK = {"0": 0.0, "1": 3.0, "2": 5.0, "3": 7.5, "4": 9.5}


def _text(el, tag: str) -> str | None:
    x = el.find(tag)
    return x.text.strip() if x is not None and x.text and x.text.strip() else None


def parse_xml(text: str) -> list[Finding]:
    root = ET.fromstring(text)
    out = []
    for host in root.iter("ReportHost"):
        props = {t.get("name"): (t.text or "").strip() for t in host.iter("tag")}
        ip = props.get("host-ip") or host.get("name", "")
        fqdn = props.get("host-fqdn") or props.get("netbios-name") or (host.get("name") if host.get("name") != ip else None)
        for item in host.iter("ReportItem"):
            score = None
            for tag in ("cvss3_base_score", "cvss_base_score"):
                v = _text(item, tag)
                if v:
                    try:
                        score = float(v)
                        break
                    except ValueError:
                        pass
            if score is None:
                score = _SEV_FALLBACK.get(item.get("severity", "0"), 0.0)
            out.append(Finding(
                scanner="nessus",
                host=ip,
                hostname=fqdn,
                port=f"{item.get('port', '0')}/{item.get('protocol', 'tcp')}",
                name=item.get("pluginName", "Unnamed plugin"),
                vuln_id=item.get("pluginID", ""),
                cvss=max(0.0, min(10.0, score)),
                cves=sorted({c.text.strip().upper() for c in item.findall("cve") if c.text}),
                solution=_text(item, "solution"),
                summary=_text(item, "synopsis"),
                exploit_available=(_text(item, "exploit_available") or "").lower() == "true",
            ))
    return out
