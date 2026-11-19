#!/usr/bin/env python3
"""Generate the full research analysis (ANALYSIS.md) from all collected data."""
import os, json, xml.etree.ElementTree as ET
from collections import Counter

census = json.load(open("data/blockcensus.json"))   # shipped; `ok` entries = reachable census
raw = json.load(open("data/raw_census.json"))
asn_type = {int(k): v for k, v in json.load(open("data/asn_type.json")).items()}
asn_by_ip = {e["address"]: e.get("mapped_as")
             for t in ("new", "tried") for e in raw.get(t, {}).values()}
ok = [r for r in census if r.get("ok")]
N = len(ok)

ASN_ORG = {14593:"SpaceX Starlink",3320:"Deutsche Telekom",7018:"AT&T",8881:"1&1 Versatel",
 212238:"Datacamp/CDN77",24940:"Hetzner",16509:"AWS",14618:"AWS",701:"Verizon",3209:"Vodafone DE",
 6805:"Telefonica DE",9009:"M247",1267:"WindTre IT",4134:"China Telecom",396982:"Google Cloud",
 16276:"OVH",14061:"DigitalOcean",20473:"Vultr",51167:"Contabo",63949:"Akamai/Linode",8075:"Microsoft"}
COARSE={'Cable/DSL/ISP':'Residential/ISP','Content':'Content/Hosting','Network Services':'Hosting/Svcs',
 'NSP':'Transit/Backbone','Enterprise':'Enterprise','Educational/Research':'Education',
 'Non-Profit':'Non-Profit','Government':'Government'}

# OS map
osm = {}
for h in ET.parse("data/nmap_os_v4_2026-11-11.xml").getroot().findall("host"):
    ipel = h.find("address[@addrtype='ipv4']"); os_ = h.find("os")
    if ipel is None or os_ is None: continue
    m = os_.findall("osmatch")
    if not m or int(m[0].get("accuracy", "0")) < 70: continue
    oc = m[0].find("osclass")
    nm = m[0].get("name", "").lower()
    cls = ('Windows' if 'windows' in nm else 'Linux' if 'linux' in nm else 'BSD' if 'bsd' in nm
           else 'macOS' if 'mac os' in nm else 'Android' if 'android' in nm else 'Device')
    osm[ipel.get("addr")] = (cls, oc.get("type","") if oc is not None else "",
                             oc.get("vendor","") if oc is not None else "")

def netclass(ip):
    a = asn_by_ip.get(ip)
    if not a: return "Unmapped"
    t = asn_type.get(a)
    return COARSE.get(t, "Other") if t is not None else "Not in PeeringDB"
def impl(u): return "Knots" if "Knots" in u else "Core" if "Satoshi" in u else "Other"
def thr(r): return (r["headers_bytes"]/1024)/(r["headers_ms"]/1000) if r.get("headers_ms",0)>0 and r.get("headers_bytes") else None
def pct(xs,p):
    xs=sorted(x for x in xs if x is not None); return xs[min(len(xs)-1,int(len(xs)*p))] if xs else None

def bar(frac, width=24):
    return "█"*int(frac*width) + "·"*(width-int(frac*width))

L=[]
def w(s=""): L.append(s)

w("# Bitcoin P2P Network Census — Research Analysis")
w()
w(f"*Vantage: single mainnet node (`/data/bitcoin`), asmap enabled. Generated from a direct-handshake census of its addrman.*")
w()
w("## Methodology")
w()
w("Instrumentation built for this study:")
w("1. addrman V5 user-agent persistence — patched Bitcoin Core to record each peer's "
  "user agent (learned at the version handshake, via `AddrMan::Good`) and persist it in `peers.dat` "
  "(new disk format `V5_USERAGENT`), exposed through `getrawaddrman`.")
w("2. Feeler-at-scale — `-feelerinterval` / `-maxfeeler` knobs + a sweep-mode loop speedup, so Core's "
  "own (reputation-safe) feeler mechanism harvests user agents across addrman.")
w("3. Direct census — a standalone, tested P2P prober (`peer_probe.py`, 17 unit + integration tests, "
  "cross-checked against Core's `test_framework`) that handshakes every addrman address, recording "
  "user agent, service flags, connect latency, and a `getheaders` serving-latency probe.")
w("4. Enrichment — ASN via Core's embedded asmap (`mapped_as`), network type via PeeringDB "
  "(`info_type`, 92% coverage), OS via nmap -O TCP/IP fingerprinting of the reachable set.")
w()
w("## 1. Reachability")
w()
total = len(census)
w(f"- Addresses probed: {total:,} (IPv4 addrman)")
w(f"- Reachable (completed handshake): {N:,} ({100*N/total:.1f}%)")
w(f"- The ~92% unreachable are stale/offline addrman entries — explains why passive feeler harvesting "
  f"plateaus quickly (random draws mostly hit dead addresses).")
w()
w("## 2. Implementation & versions")
w()
impls = Counter(impl(r["user_agent"]) for r in ok)
for k,c in impls.most_common():
    w(f"- {k}: {c:,} ({100*c/N:.0f}%)  `{bar(c/N)}`")
vers = Counter()
for r in ok:
    u=r["user_agent"]
    if u.startswith("/Satoshi:"): vers[u.split(':')[1].split('/')[0].split('(')[0]]+=1
w()
w(f"- Distinct user agents: {len(set(r['user_agent'] for r in ok))}")
w("- Top Core versions: " + ", ".join(f"`{v}` ({c})" for v,c in vers.most_common(8)))
w()
w("## 3. Service flags")
w()
flg=Counter()
for r in ok:
    for f in r.get("service_names",[]): flg[f]+=1
for k,c in flg.most_common():
    tag = " *(non-core)*" if k in("REDUCED_DATA","BLAKE2B","REPLACE_BY_FEE","UTREEXO","UTREEXO_ARCHIVE","LIBRE_RELAY","XTHIN") else ""
    if c>=3: w(f"- {k}: {100*c//N}%{tag}")
w()
w("## 4. Network type (PeeringDB, 92% coverage)")
w()
nc=Counter(netclass(r["ip"]) for r in ok)
for k,c in nc.most_common():
    w(f"- {k}: {c:,} ({100*c/N:.1f}%)  `{bar(c/N)}`")
asn=Counter(asn_by_ip.get(r["ip"]) for r in ok if asn_by_ip.get(r["ip"]))
w()
w("Top ASNs among reachable peers:")
for a,c in asn.most_common(10):
    w(f"- AS{a} {ASN_ORG.get(a,'')}: {c}")
w()
w("## 5. Latency / serving speed (active probe)")
w()
cm=[r.get("connect_ms") for r in ok]; hm=[r.get("headers_ms") for r in ok]
tp=[thr(r) for r in ok]
w(f"- TCP connect RTT: p50 {pct(cm,.5):.0f} ms, p90 {pct(cm,.9):.0f} ms")
w(f"- `getheaders`→2000 headers: p50 {pct(hm,.5):.0f} ms, p90 {pct(hm,.9):.0f} ms (n={sum(1 for x in hm if x)})")
w(f"- Serving throughput (headers): p50 {pct(tp,.5):.0f} KB/s, p90 {pct(tp,.9):.0f} KB/s")
w()
w("## 6. Operating system (nmap -O)")
w()
osc=Counter(osm[r["ip"]][0] for r in ok if r["ip"] in osm)
matched=sum(osc.values())
w(f"Confident matches: {matched}/{N} ({100*matched//N}%). Of those classified:")
for k,c in osc.most_common():
    w(f"- {k}: {c} ({100*c//matched}%)")
devtypes=Counter(osm[r["ip"]][1] for r in ok if r["ip"] in osm and osm[r["ip"]][1] not in("general purpose",""))
w()
w("Non-general-purpose device types (the long tail): " +
  ", ".join(f"{k}×{c}" for k,c in devtypes.most_common()))
w()
w("## 7. Resource profiling (composite proxy)")
w()
DC_pdb = lambda ip: netclass(ip) in ("Content/Hosting","Hosting/Svcs")
tps=sorted(t for t in tp if t); slow_thresh=tps[len(tps)//4]
reasons=Counter(); flagged=0
for r in ok:
    f=set(r.get("service_names",[])); sig=[]
    if "NETWORK_LIMITED" in f and "NETWORK" not in f: sig.append("pruned")
    if "REDUCED_DATA" in f: sig.append("reduced_data")
    t=thr(r)
    if t and t<slow_thresh and not DC_pdb(r["ip"]): sig.append("slow-serve")
    if "Apollo" in r["user_agent"]: sig.append("appliance")
    dt=osm.get(r["ip"],("","",""))[1]
    if dt in("router","WAP","storage-misc","broadband router","switch","firewall"): sig.append("device")
    if sig:
        flagged+=1
        for s in sig: reasons[s]+=1
w(f"- Peers with >=1 low-resource signal: {flagged} ({100*flagged//N}%)")
for k,c in reasons.most_common():
    w(f"  - {k}: {c}")
w()
w("## 8. Cross-dimensional correlations")
w()
withtp=sorted(((thr(r),i,r) for i,r in enumerate(ok) if thr(r) is not None),key=lambda x:x[0],reverse=True)
qn=len(withtp)//4
def cohort(rows):
    m=len(rows); ic=Counter(impl(r["user_agent"]) for r in rows); ncc=Counter(netclass(r["ip"]) for r in rows)
    return (f"impl {', '.join(f'{k} {100*v//m}%' for k,v in ic.most_common(3))}; "
            f"net {', '.join(f'{k} {100*v//m}%' for k,v in ncc.most_common(3))}; "
            f"connect p50 {pct([r.get('connect_ms') for r in rows],.5):.0f}ms")
w(f"Fast quartile (serve p50 {pct([t for t,_,_ in withtp[:qn]],.5):.0f} KB/s): "+cohort([r for _,_,r in withtp[:qn]]))
w()
w(f"Slow quartile (serve p50 {pct([t for t,_,_ in withtp[-qn:]],.5):.0f} KB/s): "+cohort([r for _,_,r in withtp[-qn:]]))
w()
w("## 9. Key findings")
w()
w("1. Only ~8% of addrman is reachable — the address book is dominated by dead/stale entries; "
  "live nodes are a small, measurable subset.")
w("2. Speed is determined by hosting, not software. Fast nodes are hosting/transit (datacenter); "
  "slow nodes are residential. Clean, strong correlation across the quartiles.")
w("3. Knots skews residential/low-resource (~11% overall, but over-represented in slow/embedded cohorts).")
w("4. ~1/3 of reachable nodes carry a low-resource signal (pruned, slow-serve, or embedded-device).")
w("5. Bitcoin runs on everything — besides servers, the census found phones, NAS boxes, routers, "
  "a firewall, a VoIP adapter, and dedicated Apollo appliances.")
w("6. ASN concentration in a handful of hosts (Hetzner, Google, AWS, OVH, DigitalOcean) is the "
  "structural fragility worth watching for partition resistance — the exact thing asmap bucketing targets.")
w()
w("---")
w("*Artifacts: `census.json`, `census_merged.csv`, `peer_analysis.{csv,json}`. "
  "Tooling: `peer_probe.py` (+tests), `harvest.py`, `merge_census.py`. "
  "Instrumentation branch: `persist-user-agent`.*")

open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "docs", "ANALYSIS.md"), "w").write("\n".join(L))
print("\n".join(L))
