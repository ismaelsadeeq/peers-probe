#!/usr/bin/env python3
"""Merge the full census into one table:
UA x service flags x connect latency x headers latency x ASN x OS.

Inputs:
  data/blockcensus.json  harvest.py results (UA, flags, connect_ms, headers_ms)
  data/raw_census.json   getrawaddrman (mapped_as ASN by IP)
  /tmp/census_os.xml     nmap -O results (optional; OS by IP)
Outputs:
  data/census_merged.csv, data/census_merged.json (summary)
"""
import json, os, xml.etree.ElementTree as ET, csv
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repo root (src/..)
D = lambda *p: os.path.join(HERE, "data", *p)

census = json.load(open(D("blockcensus.json")))
raw = json.load(open(D("raw_census.json")))
asn_by_ip = {e["address"]: e.get("mapped_as")
             for t in ("new", "tried") for e in raw.get(t, {}).values()}
country_by_ip = {e["address"]: e.get("country", "")
                 for t in ("new", "tried") for e in raw.get(t, {}).values()}

ASN_ORG = {14593:"SpaceX Starlink",3320:"Deutsche Telekom",7018:"AT&T",8881:"1&1 Versatel",
 212238:"Datacamp/CDN77",24940:"Hetzner",16509:"AWS",14618:"AWS",701:"Verizon",3209:"Vodafone DE",
 6805:"Telefonica DE",9009:"M247",1267:"WindTre IT",4134:"China Telecom",396982:"Google Cloud",
 16276:"OVH",14061:"DigitalOcean",20473:"Vultr",51167:"Contabo",63949:"Akamai/Linode",
 8075:"Microsoft",15169:"Google",24961:"myLoc",60068:"Datacamp",0:"(unmapped)"}

os_by_ip = {}
try:
    for h in ET.parse("/tmp/census_os.xml").getroot().findall("host"):
        ipel = h.find("address[@addrtype='ipv4']") or h.find("address[@addrtype='ipv6']")
        os_ = h.find("os")
        if ipel is None or os_ is None:
            continue
        m = os_.findall("osmatch")
        if m and int(m[0].get("accuracy", "0")) >= 70:
            os_by_ip[ipel.get("addr")] = m[0].get("name")
except (FileNotFoundError, ET.ParseError):
    print("(OS xml missing or still being written — OS column will be blank)")

def os_class(name):
    s = (name or "").lower()
    for k, l in [("linux","Linux"),("windows","Windows"),("bsd","BSD"),
                 ("mac os","macOS"),("android","Android"),("solaris","Solaris")]:
        if k in s:
            return l
    return "Other/Device" if name else "Unknown"

ok = [r for r in census if r.get("ok")]
impl = Counter()
for r in ok:
    u = r["user_agent"]
    impl["Knots" if "Knots" in u else "Core" if "Satoshi" in u else "Other"] += 1
asn_c = Counter(asn_by_ip.get(r["ip"]) for r in ok)
os_c = Counter(os_class(os_by_ip.get(r["ip"])) for r in ok)

print(f"reachable peers: {len(ok)}")
print(f"impl split: " + ", ".join(f"{k}={v}" for k, v in impl.most_common()))
print("\ntop ASNs among reachable peers:")
for a, c in asn_c.most_common(15):
    print(f"  AS{a!s:<8} {c:4}  {ASN_ORG.get(a,'')}")
print("\nOS classes among reachable peers:")
for k, c in os_c.most_common():
    print(f"  {k:14} {c}")
scanned = sum(1 for r in ok if r["ip"] in os_by_ip)
print(f"  (confident OS match: {scanned}/{len(ok)})")

# full joined CSV
with open(D("census_merged.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ip","user_agent","impl","service_names","connect_ms",
                "headers_ms","headers_count","asn","asn_org","country","os","os_class"])
    for r in ok:
        a = asn_by_ip.get(r["ip"])
        osn = os_by_ip.get(r["ip"], "")
        u = r["user_agent"]
        w.writerow([r["ip"], u,
                    "Knots" if "Knots" in u else "Core" if "Satoshi" in u else "Other",
                    "|".join(r.get("service_names", [])), r.get("connect_ms",""),
                    r.get("headers_ms",""), r.get("headers_count",""),
                    a, ASN_ORG.get(a,""), country_by_ip.get(r["ip"],""),
                    osn, os_class(osn)])

summary = dict(
    reachable=len(ok), total_scanned=len(census),
    impl=dict(impl), top_asn=[[a,c,ASN_ORG.get(a,"")] for a,c in asn_c.most_common(20)],
    os=dict(os_c),
    user_agents=dict(Counter(r["user_agent"] for r in ok).most_common(40)))
json.dump(summary, open(D("census_merged.json"),"w"), indent=2)
print(f"\n[saved] {D('census_merged.csv')} + {D('census_merged.json')}")
