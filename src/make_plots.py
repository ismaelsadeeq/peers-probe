#!/usr/bin/env python3
"""Generate report figures (SVG) from data/."""
import json, os
from collections import Counter, defaultdict
import svgplot as sp

os.makedirs("results/figures", exist_ok=True)
D = "data/"
import ipaddress
def _routable(ip):
    """A real reachable node must have a globally-routable address. Excludes
    poisoned addrman entries like 1111:1111::1 (reserved IPv6 space)."""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a in ipaddress.ip_network("2000::/3") if a.version == 6 else a.is_global
    except ValueError:
        return False
bc = [r for r in json.load(open(D+"blockcensus.json")) if r.get("ok") and _routable(r["ip"])]
# dedupe by IP: 57 reachable hosts listen on a second port (8,592 endpoints -> 8,535
# distinct IPs). Every figure counts distinct nodes, matching the report's prose.
_seen = {}
for _r in bc: _seen.setdefault(_r["ip"], _r)
bc = list(_seen.values())
raw = json.load(open(D+"raw_census.json"))
asn_by_ip = {e["address"]: e.get("mapped_as") for t in ("new","tried") for e in raw.get(t,{}).values()}
country_by_ip = {e["address"]: e.get("country","") for t in ("new","tried") for e in raw.get(t,{}).values()}
# also load ASN+country from census_merged.csv, which has near-complete coverage
# (8,588/8,593 geolocated). raw_census seeds many IPs with an empty country/None ASN,
# so fill whenever the current value is missing OR blank, not only when the key is absent.
import csv
for r in csv.DictReader(open(D+"census_merged.csv")):
    ip = r["ip"]
    if not asn_by_ip.get(ip) and r.get("asn") and r["asn"] not in ("0","None",""):
        asn_by_ip[ip] = int(r["asn"])
    if not country_by_ip.get(ip) and r.get("country"):
        country_by_ip[ip] = r["country"]
asn_type = {int(k): v for k, v in json.load(open(D+"asn_type.json")).items()}
COARSE = {"Cable/DSL/ISP":"Residential","Content":"Hosting","Network Services":"Hosting",
          "NSP":"Transit","Enterprise":"Enterprise","Educational/Research":"Education"}
def nclass(ip):
    a = asn_by_ip.get(ip); t = asn_type.get(a) if a else None
    return COARSE.get(t, "Other") if t is not None else "Unmapped"
def vt(ua):
    if "Satoshi:" not in ua: return None
    v = ua.split("Satoshi:")[1].split("/")[0].split("(")[0]
    n = [int(x) for x in v.split(".") if x.isdigit()]; return tuple(n) if n else None
def em(t): return t[1] if t and t[0]==0 and len(t)>1 else (t[0] if t else None)
def band(t):
    e = em(t)
    if e is None: return None
    if e>=26: return "v26+"
    if 21<=e<=25: return "v0.21-25"
    if e in (19,20): return "v0.19-20"
    if e in (16,17,18): return "v0.16-18"
    if e in (14,15) or (e==13 and len(t)>2 and t[2]>=1): return "v0.13.1-15"
    if e==13: return "v0.13.0"
    if e==12: return "v0.12"
    return "<v0.12"
def impl(ua): return "Knots" if "Knots" in ua else "Core" if "Satoshi" in ua else "Other"

figs = {}

# 1. version bands — distinct-version counts per band are computed, not hardcoded
_vpb = defaultdict(set)
bands = Counter()
for r in bc:
    t = vt(r["user_agent"]); b = band(t)
    if b: bands[b] += 1; _vpb[b].add(t)
order = ["v26+","v0.21-25","v0.19-20","v0.16-18","v0.13.1-15","v0.13.0","v0.12","<v0.12"]
blabel = lambda b: f"{b} ({len(_vpb[b])} vers)" if len(_vpb[b]) > 1 else b
items = [(blabel(b), bands[b]) for b in order if b in bands]
n_vers = sum(len(s) for s in _vpb.values()); n_bands = len(bands)
figs["version_bands"] = sp.barh("Versions collapse into behavioral bands (no user agent)", items,
    unit=" nodes", color="#2b6cb0",
    note=f"{n_vers} distinct versions -> {n_bands} bands; exact version detectable for 0% without the UA")

# 2. AS concentration: node% vs bandwidth%
node_as, bw_as = Counter(), Counter()
for r in bc:
    a = asn_by_ip.get(r["ip"])
    if a: node_as[a]+=1
    if a and r.get("block_mbps"): bw_as[a]+=r["block_mbps"]
def cum(d):
    s = sorted(d.values(), reverse=True); tot=sum(s) or 1; acc=0; out=[(0,0)]
    for i,v in enumerate(s,1): acc+=v; out.append((i, 100*acc/tot))
    return out
nc = cum(node_as)[:51]; bwc = cum(bw_as)[:51]
_tn = sum(node_as.values()) or 1; _tb = sum(bw_as.values()) or 1
as_top1_node = round(100 * node_as.most_common(1)[0][1] / _tn)
as_top1_bw = round(100 * bw_as.most_common(1)[0][1] / _tb)
as_top10_node = round(100 * sum(v for _, v in node_as.most_common(10)) / _tn)
figs["as_concentration"] = sp.lines("AS concentration: nodes vs serving capacity",
    {"% of nodes":[(i,v) for i,v in nc], "% of bandwidth":[(i,v) for i,v in bwc]},
    xlabel="top-k ASes", ylabel="cumulative %", xticks=[0,10,20,30,40,50],
    note=f"capacity is more centralized than node count (top-1 AS ~{as_top1_node}% nodes but ~{as_top1_bw}% bandwidth)")

# 3. block throughput CDF by network class
def cdf(vals):
    v = sorted(vals); n=len(v) or 1; return [(v[i], 100*(i+1)/n) for i in range(0,len(v),max(1,len(v)//60))]
import statistics as _stats
series = {}; _med = {}
for cls in ("Hosting","Residential","Transit"):
    vals = [r["block_mbps"] for r in bc if r.get("block_mbps") and nclass(r["ip"])==cls]
    if len(vals) > 10: series[cls] = cdf(vals); _med[cls] = _stats.median(vals)
_ratio = _med["Hosting"] / _med["Residential"] if _med.get("Residential") else 0
figs["throughput_cdf"] = sp.lines("Block-serving throughput CDF by network class",
    series, xlabel="Mbps", ylabel="% of peers <= x",
    xticks=[0,25,50,75,100,150,200],
    note=f"hosting serves ~{_ratio:.1f}x faster than residential (medians {_med['Hosting']:.0f} vs {_med['Residential']:.0f} Mbps)")

# 4. implementation + network type
def impl_detail(ua):
    if "Knots" in ua: return "Knots"
    if "btcd" in ua: return "btcd"
    if "CKCoinD" in ua: return "CKCoinD"
    if "Ghost" in ua: return "Ghost"
    if "Prometheus" in ua: return "Prometheus"
    if "BitcoinUnlimited" in ua: return "Bitcoin Unlimited"
    if "libbitcoin" in ua: return "libbitcoin"
    if "utreexod" in ua: return "utreexod"
    if "bitcoin-rs" in ua or "Rustoshi" in ua: return "Rust impl"
    if "Classic" in ua: return "Bitcoin Classic"
    if "Ladybug" in ua: return "Ladybug"
    if "Satoshi" in ua: return "Core"
    return ua.split(":")[0].strip("/") if "/" in ua else "unknown"
impls = Counter(impl_detail(r["user_agent"]) for r in bc)
impl_items = [(k,v) for k,v in impls.most_common() if v >= 1]
figs["implementation"] = sp.barh_cols("Implementation (reachable nodes)",
    impl_items, cols=2, color="#a67fd6",
    note="every implementation seen; Core dominates, btcd is the largest alternative")
ncls = Counter(nclass(r["ip"]) for r in bc)
nt_cov = round(100 * (len(bc) - ncls.get("Unmapped", 0)) / len(bc))
figs["network_type"] = sp.barh(f"Network type (PeeringDB, {nt_cov}% coverage)",
    [(k,v) for k,v in ncls.most_common()], unit="", color="#38a169",
    note="ASN = network vantage, not identity (tunnel/VPN/Tor)")

# 4b. country distribution (top 15)
countries = Counter(country_by_ip.get(r["ip"],"") for r in bc)
countries.pop("", None)  # drop unknown
top_countries = countries.most_common(15)
if top_countries:
    figs["country_distribution"] = sp.barh("Reachable nodes by country (top 15)",
        top_countries, unit=" nodes", color="#dd6b20",
        note="geographic distribution of directly-probed IPv4+IPv6 nodes")

# 4c. country by continent — one chart per continent
def flag(cc):
    """Convert 2-letter country code to flag emoji."""
    if not cc or len(cc) != 2: return ""
    return chr(0x1F1E6 + ord(cc[0]) - ord('A')) + chr(0x1F1E6 + ord(cc[1]) - ord('A'))

CONT_CODES = {
    "Europe": "DE FR NL GB CH CZ SE AT PL RO LT CY BG UA ES IT PT NO FI DK BE SI LV EE SK IS HU GR IE HR RS MT AD LI GG FO LU BY MD EU RE".split(),
    "N. America": "US CA MX PA CR GT BZ SV KN PR DO AG AI".split(),
    "S. America": "BR AR CO CL VE UY BO PE".split(),
    "Asia": "KR SG CN JP HK TW TH MY IN ID AE KW TR IL OM PK AZ VN PH KZ QA SA KH MO IR KG GE".split(),
    "Africa": "ZA AO SC".split(),
    "Oceania": "AU NZ".split(),
    "Russia": "RU".split(),
}
CONT_MAP = {}
for cont, codes in CONT_CODES.items():
    for cc in codes: CONT_MAP[cc] = cont

from collections import defaultdict
by_cont = defaultdict(list)
for cc, n in countries.most_common():
    cont = CONT_MAP.get(cc, "Other")
    by_cont[cont].append((f"{flag(cc)} {cc}", n))

cont_totals = {c: sum(n for _, n in items) for c, items in by_cont.items()}
cont_order = sorted(cont_totals, key=lambda c: -cont_totals[c])
total_nodes = sum(cont_totals.values())

# one figure per continent (cap the long tail so the charts stay compact)
CONT_COLORS = {"Europe":"#58c4dd","N. America":"#f0ac5f","Asia":"#83c167",
               "S. America":"#a67fd6","Oceania":"#5cd0b3","Africa":"#fc6255","Russia":"#f5d547","Other":"#8b98a8"}
for cont in cont_order:
    items = by_cont[cont]
    t = cont_totals[cont]
    slug = cont.lower().replace(". ","_").replace(" ","_")
    ncols = 1 if len(items) <= 13 else 2 if len(items) <= 26 else 3
    figs[f"country_{slug}"] = sp.barh_cols(
        f"{cont}: {t} nodes ({round(100*t/total_nodes,1)}%)",
        items, cols=ncols, color=CONT_COLORS.get(cont, "#58c4dd"),
        note=f"{len(items)} countries" + (f"; {54-len(items)} of 54 African countries have zero nodes" if cont == "Africa" else ""))

# 4d. continent summary
cont_items = [(c, cont_totals[c]) for c in cont_order]
if cont_items:
    figs["continent_distribution"] = sp.barh("Reachable nodes by continent",
        cont_items, unit=" nodes", color="#805ad5",
        note=f"{len(countries)} countries total; Africa: {cont_totals.get('Africa',0)} nodes ({round(100*cont_totals.get('Africa',0)/total_nodes,1)}%)")

# 5. asmap eclipse collapse (top ASes by netgroup span in new table)
#    IPv4 uses /16 prefixes, IPv6 uses /32 prefixes — both are "netgroups"
as16 = defaultdict(set)
for e in raw.get("new",{}).values():
    a = e.get("mapped_as"); ip = e["address"]; net = e.get("network", "ipv4")
    if not a:
        continue
    if net == "ipv4" and ip.count(".")==3:
        as16[a].add("v4:" + ".".join(ip.split(".")[:2]))        # /16
    elif net == "ipv6" and ":" in ip:
        parts = ip.split(":")
        as16[a].add("v6:" + ":".join(parts[:2]))                # /32
ORG = {7018:"AT&T",16509:"AWS",3320:"Deutsche Telekom",4134:"China Telecom",701:"Verizon",
       14593:"Starlink",24940:"Hetzner",16276:"OVH"}
top = sorted(((len(v),a) for a,v in as16.items()), reverse=True)[:8]
figs["asmap_collapse"] = sp.barh("asmap eclipse benefit: netgroups collapsed to 1 per AS",
    [(f"AS{a} {ORG.get(a,'')}", n) for n,a in top], unit=" netgroups", color="#e53e3e",
    note="asmap turns each AS's many netgroups (IPv4 /16 + IPv6 /32) into ONE")

# 6. reachable nodes by network, from our OWN direct probe across all four networks.
#    (This single figure replaces the old IPv4-vs-IPv6 chart AND the Bitnodes
#    "by network" chart, which disagreed on IPv6 — one consistent view, our data.)
n_ipv4 = sum(1 for r in bc if ":" not in r["ip"])
n_ipv6 = sum(1 for r in bc if ":" in r["ip"])
net_counts = [("IPv4", n_ipv4), ("IPv6", n_ipv6)]
for _f, _label in ((D+"onion_census.json", "onion"), (D+"i2p_census.json", "I2P")):
    try:
        _d = json.load(open(_f))
        net_counts.append((_label, sum(1 for r in _d if r.get("ok"))))
    except FileNotFoundError:
        pass
net_counts.sort(key=lambda kv: -kv[1])
_tot = sum(v for _, v in net_counts)
figs["reachable_by_network"] = sp.barh("Reachable listening nodes by network (direct probe)",
    net_counts, unit="", color="#58c4dd",
    note=f"{_tot:,} nodes we handshaked ourselves across all four networks; listening nodes only")

# 7. onion vs clearnet comparison (from direct probe data)
try:
    onion_data = json.load(open(D+"onion_census.json"))
    onion_ok = [r for r in onion_data if r.get("ok")]
    if onion_ok:
        def _pruned(r):
            svc = r.get("service_names", [])
            return "NETWORK_LIMITED" in svc and "NETWORK" not in [s for s in svc if s != "NETWORK_LIMITED"]
        def _vuln(r):
            ua = r.get("user_agent","")
            if "Satoshi:" not in ua: return False
            v = ua.split("Satoshi:")[1].split("/")[0].split("(")[0]
            parts = [int(x) for x in v.split(".") if x.isdigit()]
            if not parts: return False
            e = parts[1] if parts[0]==0 and len(parts)>1 else parts[0]
            return e < 25
        def _v2(r): return "P2P_V2" in r.get("service_names",[])
        def _knots(r): return "Knots" in r.get("user_agent","")

        cl_n, on_n = len(bc), len(onion_ok)
        R = lambda x: round(x, 1)
        items = [
            ("pruned · clearnet", R(100*sum(_pruned(r) for r in bc)/cl_n)),
            ("pruned · onion", R(100*sum(_pruned(r) for r in onion_ok)/on_n)),
            ("vuln<v25 · clearnet", R(100*sum(_vuln(r) for r in bc)/cl_n)),
            ("vuln<v25 · onion", R(100*sum(_vuln(r) for r in onion_ok)/on_n)),
            ("P2P_V2 · clearnet", R(100*sum(_v2(r) for r in bc)/cl_n)),
            ("P2P_V2 · onion", R(100*sum(_v2(r) for r in onion_ok)/on_n)),
            ("Knots · clearnet", R(100*sum(_knots(r) for r in bc)/cl_n)),
            ("Knots · onion", R(100*sum(_knots(r) for r in onion_ok)/on_n)),
        ]
        figs["onion_vs_clearnet"] = sp.barh(
            "Onion vs clearnet: direct probe comparison",
            items, unit="%", color="#a371f7",
            note="onion nodes are less pruned, less vulnerable, more current (direct probe, not Bitnodes)")

        # 8. data source contribution
        # count per-source from the blockcensus (addrman IPs vs KIT/achow)
        n_total = len(bc)
        n_ok = len([r for r in bc if r.get("ok")])
        figs["data_sources"] = sp.barh(
            "Census data sources: total reachable nodes",
            [("clearnet (IPv4+IPv6)", n_ok),
             ("onion (Tor direct)", len(onion_ok))],
            unit=" nodes", color="#38a169",
            note=f"clearnet from addrman+KIT+achow/fishfoo ({n_total:,} probed); onion via 4 Tor instances")
except FileNotFoundError:
    pass  # onion data not available yet

# 9. CVE exposure: each advisory's share of the network, colored by severity.
try:
    exp = json.load(open("results/exposure_map.json"))
    SEV_COLOR = {"Critical":"#fc6255", "High":"#f0ac5f", "Med":"#f5d547", "Low":"#8b98a8"}
    def _sev(t):
        for s in SEV_COLOR:
            if f"({s})" in t: return s
        return "Low"
    cves = [(k, v) for k, v in exp.items() if isinstance(v, dict) and "exposed_pct" in v]
    cves.sort(key=lambda kv: kv[1]["exposed_pct"])          # ascending so biggest exposure is on top
    cve_items, cve_colors = [], []
    for k, v in cves:
        cond = {"ratelimit22": ", practical", "nonlinux": ", non-Linux"}.get(v.get("condition", ""), "")
        cve_items.append((f"{k} (fix v{v.get('fixed_in','?')}{cond})", v["exposed_pct"]))
        cve_colors.append(SEV_COLOR[_sev(v.get("type", ""))])
    figs["cve_exposure"] = sp.barh("CVE exposure: observed share of the network below each fix line",
        cve_items, width=880, pad_left=320, unit="%", colors=cve_colors,
        note="nodes already patched by a backport release are excluded; severity red Critical, orange High, amber Med, grey Low")
except FileNotFoundError:
    pass

for name, svg in figs.items():
    open(f"results/figures/{name}.svg","w").write(svg)
    print("wrote", f"results/figures/{name}.svg")
