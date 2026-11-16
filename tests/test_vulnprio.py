import json
from pathlib import Path

import httpx
import pytest
from defusedxml import DefusedXmlException, EntitiesForbidden

from vulnprio.assets import Inventory
from vulnprio.cli import main
from vulnprio.kev import KEV_MIRROR, KEV_URL, Kev, download
from vulnprio.model import Finding
from vulnprio.parsers import detect, parse_file
from vulnprio.report import html_report, markdown, to_csv, to_json
from vulnprio.score import campaigns, rank, score_one
from vulnprio.summary import mask, summarise

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
OPENVAS = SAMPLES / "scans" / "internal-openvas.xml"
NESSUS = SAMPLES / "scans" / "external-nessus.nessus"


@pytest.fixture
def kev():
    return Kev.load(SAMPLES / "kev-sample.json")


@pytest.fixture
def inv():
    return Inventory.load(SAMPLES / "assets.csv")


def f(host="10.0.0.1", cvss=5.0, cves=(), name="x", vid="1", **kw):
    return Finding("openvas", host, None, "443/tcp", name, vid, cvss, list(cves), **kw)


# ---------- parsers ----------

def test_openvas_xml():
    found = parse_file(OPENVAS)
    assert len(found) == 10
    zl = found[0]
    assert (zl.host, zl.hostname, zl.port, zl.cvss) == ("10.20.1.10", "dc01.corp.example", "445/tcp", 10.0)
    assert zl.cves == ["CVE-2020-1472"] and zl.solution.startswith("Install the August 2020")
    assert found[2].cves == ["CVE-2017-0144", "CVE-2017-0145"]
    assert found[0].summary.startswith("The Netlogon protocol")


def test_nessus_xml():
    found = parse_file(NESSUS)
    assert len(found) == 7
    forti = next(x for x in found if x.vuln_id == "900201")
    assert (forti.host, forti.hostname, forti.cvss, forti.exploit_available) == ("203.0.113.20", "vpn.example.com", 9.8, True)
    info = next(x for x in found if x.vuln_id == "19506")
    assert info.cvss == 0.0


def test_nessus_csv(tmp_path):
    p = tmp_path / "n.csv"
    p.write_text('Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution\n'
                 '97833,CVE-2017-0144,9.3,Critical,10.1.1.5,tcp,445,MS17-010,SMB flaw,desc,Patch it\n'
                 '97833,CVE-2017-0145,9.3,Critical,10.1.1.5,tcp,445,MS17-010,SMB flaw,desc,Patch it\n'
                 '11111,,,Medium,10.1.1.6,tcp,80,Thing,,,\n')
    found = parse_file(p)
    assert len(found) == 3 and found[0].port == "445/tcp" and found[0].cvss == 9.3
    assert found[2].cvss == 5.0  # from the Risk column when no score


def test_openvas_csv(tmp_path):
    p = tmp_path / "o.csv"
    p.write_text("IP,Hostname,Port,Port Protocol,CVSS,Severity,NVT Name,Summary,NVT OID,CVEs,Solution\n"
                 '10.2.2.2,srv,443,tcp,7.5,High,Weak ciphers,sum,1.3.6.1.4.1.25623.1.0.1,"CVE-2016-2183,CVE-2016-6329",Fix TLS\n')
    (x,) = parse_file(p)
    assert x.cves == ["CVE-2016-2183", "CVE-2016-6329"] and x.port == "443/tcp" and x.hostname == "srv"


def test_unknown_file_is_refused(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello\n")
    with pytest.raises(ValueError, match="not a recognised"):
        parse_file(p)


def test_xml_entity_attacks_are_refused(tmp_path):
    p = tmp_path / "evil.xml"
    p.write_text('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
                 '<report><results><result><host>&b;</host><nvt oid="1"><name>x</name></nvt></result></results></report>')
    with pytest.raises((EntitiesForbidden, DefusedXmlException)):
        parse_file(p)


def test_detect():
    assert detect(NESSUS, NESSUS.read_text()) == "nessus"
    assert detect(OPENVAS, OPENVAS.read_text()) == "openvas"


# ---------- inventory and KEV ----------

def test_inventory_most_specific_match_wins(tmp_path):
    p = tmp_path / "a.csv"
    p.write_text("host,name,criticality,internet_facing\n10.0.0.0/8,Corp,low,no\n10.1.0.0/16,Site,medium,no\n"
                 "10.1.2.3,Billing,critical,yes\nmail.example.com,Mail,high,yes\n")
    i = Inventory.load(p)
    assert i.find("10.1.2.3").name == "Billing"
    assert i.find("10.1.9.9").name == "Site"
    assert i.find("10.9.9.9").name == "Corp"
    assert i.find("192.0.2.1", "MAIL.example.com").name == "Mail"
    assert i.find("192.0.2.1") is None


def test_inventory_rejects_bad_criticality(tmp_path):
    p = tmp_path / "a.csv"
    p.write_text("host,name,criticality,internet_facing\n10.0.0.1,X,urgent,no\n")
    with pytest.raises(ValueError, match="criticality"):
        Inventory.load(p)


def test_kev_sample_is_real_format(kev):
    assert "CVE-2021-44228" in kev and "cve-2021-44228" in kev
    assert kev.get("CVE-2021-44228").ransomware is True
    assert kev.get("CVE-2023-44487").ransomware is False
    assert "CVE-2023-48795" not in kev


def test_kev_rejects_wrong_file():
    with pytest.raises(ValueError):
        Kev.from_json({"hello": 1})


def _kev_payload(n):
    return {"catalogVersion": "test", "vulnerabilities": [{"cveID": f"CVE-2020-{i:05d}", "knownRansomwareCampaignUse": "Unknown"}
                                                          for i in range(n)]}


def test_kev_download_falls_back_to_mirror(tmp_path):
    seen = []

    def handler(req):
        seen.append(str(req.url))
        if "cisa.gov" in str(req.url):
            return httpx.Response(403)
        return httpx.Response(200, json=_kev_payload(150))

    kev = download(tmp_path / "kev.json", client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert len(kev) == 150 and seen == [KEV_URL, KEV_MIRROR]
    assert (tmp_path / "kev.json").exists()


def test_kev_download_refuses_suspiciously_small_catalog(tmp_path):
    good = tmp_path / "kev.json"
    good.write_text(json.dumps(_kev_payload(500)))
    client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=_kev_payload(3))))
    with pytest.raises(ValueError, match="refusing"):
        download(good, client=client)
    assert len(Kev.load(good)) == 500  # working copy untouched


# ---------- scoring ----------

def test_score_is_explained(kev, inv):
    r = score_one(Finding("nessus", "203.0.113.20", None, "443/tcp", "Forti", "1", 9.8, ["CVE-2018-13379"], exploit_available=True),
                  inv, kev)
    assert r.score == 98 + 60 + 15 + 30 + 30
    assert r.reasons == ["CVSS 9.8", "In CISA KEV (CVE-2018-13379)", "Used in ransomware campaigns", "Internet-facing",
                         "Critical asset (VPN gateway)"]
    assert r.deadline_days == 7


def test_exploit_bonus_only_without_kev(kev):
    no_kev = score_one(f(cvss=8.0, exploit_available=True), Inventory.empty(), kev)
    assert no_kev.score == 80 + 15 and "Public exploit available" in no_kev.reasons


def test_unknown_host_gets_a_nudge_only_when_an_inventory_exists(kev, inv):
    assert "Host not in the asset inventory" in score_one(f(host="10.99.0.1"), inv, kev).reasons
    assert score_one(f(host="10.99.0.1"), Inventory.empty(), kev).reasons == ["CVSS 5.0"]


@pytest.mark.parametrize("cvss, cves, host, days", [
    (9.8, ["CVE-2018-13379"], "203.0.113.20", 7),   # KEV + internet
    (8.1, ["CVE-2017-0144"], "10.20.2.41", 14),     # KEV inside
    (9.5, [], "203.0.113.10", 14),                  # critical CVSS on internet host
    (7.5, [], "10.20.2.41", 30),
    (5.0, [], "10.20.2.41", 90),
])
def test_deadlines(kev, inv, cvss, cves, host, days):
    assert score_one(f(host=host, cvss=cvss, cves=cves), inv, kev).deadline_days == days


def test_rank_drops_info_but_keeps_kev_with_zero_score(kev):
    ranked = rank([f(cvss=0.0, name="info"), f(cvss=0.0, cves=["CVE-2021-44228"], name="kev-no-score")], Inventory.empty(), kev)
    assert [r.finding.name for r in ranked] == ["kev-no-score"]


def test_rank_deduplicates_across_scans(kev):
    a = f(cvss=7.0, cves=["CVE-2017-0144"])
    b = f(cvss=8.1, cves=["CVE-2017-0144"])
    ranked = rank([a, b], Inventory.empty(), kev)
    assert len(ranked) == 1 and ranked[0].finding.cvss == 8.1


def test_sample_ranking_order(kev, inv):
    ranked = rank(parse_file(OPENVAS) + parse_file(NESSUS), inv, kev)
    names = [r.finding.name for r in ranked]
    assert names[0] == "Fortinet FortiOS SSL VPN Path Traversal"
    assert names[1].startswith("Microsoft Windows Netlogon")
    assert "OS Detection Consolidation and Reporting" not in names and "Nessus Scan Information" not in names
    assert [r.rank for r in ranked] == list(range(1, len(ranked) + 1))
    # a KEV finding on a low-value lab box still outranks a non-KEV finding on the payroll database
    lab = next(r for r in ranked if "Log4Shell" in r.finding.name)
    payroll = next(r for r in ranked if r.finding.host == "10.20.1.30")
    assert lab.rank < payroll.rank


def test_campaign_groups_one_fix_across_hosts(kev, inv):
    camps = campaigns(rank(parse_file(OPENVAS) + parse_file(NESSUS), inv, kev))
    ms17 = next(c for c in camps if "MS17-010" in c.title)
    assert ms17.hosts == ["10.20.2.41", "10.20.2.57", "10.20.2.63"] and ms17.deadline_days == 14
    assert all(len(c.hosts) >= 2 for c in camps)


# ---------- summary and reports ----------

def test_mask_only_internal():
    assert mask("10.20.1.10 and 203.0.113.20 and 192.168.1.1") == "[internal] and 203.0.113.20 and [internal]"


def test_rule_summary(kev, inv):
    ranked = rank(parse_file(OPENVAS) + parse_file(NESSUS), inv, kev)
    h, points, src = summarise(ranked, campaigns(ranked), 20)
    assert src == "rules" and h.startswith("15 findings ranked; 9 of the top 15")
    assert any("within 7 days" in p for p in points)


def test_model_summary_sees_no_internal_ips(kev, inv):
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(
            {"headline": "Patch the VPN gateway first", "points": ["a", "b", "c"]})}}]})

    ranked = rank(parse_file(OPENVAS) + parse_file(NESSUS), inv, kev)
    h, p, src = summarise(ranked, campaigns(ranked), 20,
                          {"base_url": "http://llm.test/v1", "client": httpx.Client(transport=httpx.MockTransport(handler))})
    assert src == "model" and h == "Patch the VPN gateway first"
    assert "10.20." not in seen["body"]
    assert "203.0.113.20" in seen["body"] or "VPN gateway" in seen["body"]  # public facts still go through


def test_model_failure_falls_back(kev, inv):
    ranked = rank(parse_file(OPENVAS), inv, kev)
    _, _, src = summarise(ranked, [], 20, {"base_url": "http://x/v1",
                                            "client": httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))})
    assert src == "rules (model failed)"


def test_reports(kev, inv, tmp_path):
    assert main(["rank", str(OPENVAS), str(NESSUS), "--assets", str(SAMPLES / "assets.csv"),
                 "--kev", str(SAMPLES / "kev-sample.json"), "--top", "5", "--out", str(tmp_path)]) == 0
    data = json.loads((tmp_path / "fix-list.json").read_text())
    assert len(data["top"]) == 5 and len(data["all"]) == 15
    rows = (tmp_path / "fix-list.csv").read_text().strip().splitlines()
    assert len(rows) == 16
    md = (tmp_path / "fix-list.md").read_text()
    assert "| 1 |" in md and "Fixes that clear several hosts" in md


def test_html_escapes(kev):
    from vulnprio.report import Result
    r = rank([f(name="<script>x</script>", cvss=9.0)], Inventory.empty(), kev)
    res = Result(r, [], 20, "h", [], "rules", ["a"], "k", 0)
    assert "<script>x" not in html_report(res)


def test_cli_fail_on_kev_and_missing_kev(tmp_path):
    args = ["rank", str(NESSUS), "--kev", str(SAMPLES / "kev-sample.json"), "--out", str(tmp_path)]
    assert main(args + ["--fail-on-kev"]) == 2
    assert main(["rank", str(NESSUS), "--kev", str(tmp_path / "nope.json"), "--out", str(tmp_path)]) == 1


def test_cli_demo(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    assert main(["demo", "--out", str(tmp_path)]) == 0
    assert (tmp_path / "fix-list.html").exists()
