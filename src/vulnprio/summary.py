"""A short summary for whoever approves the downtime.

Built from the ranking by default. Optionally rewritten by any
OpenAI-compatible model (a local Ollama works); internal addresses and
hostnames are masked before anything is sent.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re

import httpx

from .model import Campaign, Ranked

log = logging.getLogger("vulnprio")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                               "169.254.0.0/16", "100.64.0.0/10")]


def mask(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            return m.group(0)
        return "[internal]" if any(ip in n for n in _INTERNAL) else m.group(0)

    return _IP.sub(sub, text)


def rule_summary(ranked: list[Ranked], campaigns: list[Campaign], top: int) -> tuple[str, list[str]]:
    if not ranked:
        return "No findings above the threshold", []
    head = ranked[:top]
    kev = [r for r in head if r.kev]
    internet = [r for r in head if r.internet_facing]
    headline = f"{len(ranked)} findings ranked; {len(kev)} of the top {len(head)} are known to be exploited"
    lines = [f"{len(internet)} of the top {len(head)} are on internet-facing hosts."]
    urgent = [r for r in head if r.deadline_days <= 7]
    if urgent:
        lines.append(f"{len(urgent)} should be fixed within 7 days: known exploited and reachable from the internet.")
    if campaigns:
        c = campaigns[0]
        lines.append(f"Biggest single fix: {c.title}, on {len(c.hosts)} hosts ({len(c.items)} findings).")
    return headline, lines


_SYSTEM = """You write a short briefing for an IT manager who approves maintenance windows.
You get the top-ranked vulnerability findings (with the reasons they ranked high) and the fixes that clear several hosts.
Reply with JSON only: {"headline": str (max 110 chars), "points": [str, ...] (3-5 items)}.
Each point is one plain sentence: what to fix, where, and why now. Use only the facts given.
Do not claim anything is exploited unless the input says it is in CISA KEV."""


def llm_summary(ranked: list[Ranked], campaigns: list[Campaign], top: int, base_url: str, api_key: str, model: str,
                masking: bool = True, client: httpx.Client | None = None) -> tuple[str, list[str]]:
    def host(r: Ranked) -> str:
        label = r.asset.name if r.asset else (r.finding.hostname or r.finding.host)
        return mask(label) if masking else label

    payload = {
        "top": [{"rank": r.rank, "finding": r.finding.name, "host": host(r), "score": r.score, "reasons": r.reasons,
                 "fix_within_days": r.deadline_days} for r in ranked[:top]],
        "campaigns": [{"fix": c.title, "hosts": len(c.hosts), "findings": len(c.items)} for c in campaigns[:5]],
    }
    if masking:
        payload = json.loads(mask(json.dumps(payload)))
    client = client or httpx.Client(timeout=90)
    resp = client.post(
        f"{base_url.rstrip('/')}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
        json={"model": model, "temperature": 0.1, "response_format": {"type": "json_object"},
              "messages": [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": json.dumps(payload)}]},
    )
    resp.raise_for_status()
    content = re.sub(r"^```(?:json)?\s*|\s*```$", "", resp.json()["choices"][0]["message"]["content"].strip())
    data = json.loads(content)
    headline = str(data["headline"]).strip()[:140]
    points = [str(p).strip() for p in data.get("points", []) if str(p).strip()][:5]
    if not headline or not points:
        raise ValueError("empty summary")
    return headline, points


def summarise(ranked, campaigns, top: int, llm: dict | None = None) -> tuple[str, list[str], str]:
    if llm and llm.get("base_url") and ranked:
        try:
            h, p = llm_summary(ranked, campaigns, top, llm["base_url"], llm.get("api_key", ""),
                               llm.get("model", "llama3.1:8b"), llm.get("mask", True), llm.get("client"))
            return h, p, "model"
        except Exception as exc:  # noqa: BLE001 - any model failure falls back
            log.warning("model summary failed: %s", exc)
            h, p = rule_summary(ranked, campaigns, top)
            return h, p, "rules (model failed)"
    h, p = rule_summary(ranked, campaigns, top)
    return h, p, "rules"
