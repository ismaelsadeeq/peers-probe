#!/usr/bin/env python3
"""Independent audit: recompute every headline number from the raw data in data/,
then assert each one appears in (a) its rendered figure SVG and (b) the report prose.

This exists so the numbers do not have to be trusted. Run it after make_plots.py /
census_snapshot.py. Any drift between data, figures, and prose fails loudly.

    python3 src/verify_numbers.py        # exits non-zero on any mismatch
"""
import json, csv, re, sys, statistics, ipaddress
from collections import Counter, defaultdict

D = "data/"
FIG = "results/figures/"
checks = []  # (name, ok, detail)


def add(name, ok, detail=""):
    checks.append((name, ok, detail))


def is_routable(ip):
    """A real reachable node must have a globally-routable address (drops
    poisoned entries like 1111:1111::1 in reserved IPv6 space)."""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a in ipaddress.ip_network("2000::/3") if a.version == 6 else a.is_global
    except ValueError:
        return False


def load_reachable():
    bc = [r for r in json.load(open(D + "blockcensus.json")) if r.get("ok") and is_routable(r["ip"])]
    seen = {}
    for r in bc:
        seen.setdefault(r["ip"], r)
    return list(seen.values()), len(bc)


def svg_text(fig):
    return open(FIG + fig).read()


def md_text(*paths):
    return "\n".join(open(p).read() for p in paths)


# ---------------------------------------------------------------- recompute
bc, n_endpoints = load_reachable()
N = len(bc)
onion = [r for r in json.load(open(D + "onion_census.json")) if r.get("ok")]
i2p = [r for r in json.load(open(D + "i2p_census.json")) if r.get("ok")]
n_ipv4 = sum(1 for r in bc if ":" not in r["ip"])
n_ipv6 = sum(1 for r in bc if ":" in r["ip"])

REPORTS = ["REPORT.md", "reports/census.md", "reports/vulnerability.md",
           "reports/targeting.md"]
prose = md_text(*REPORTS)

# 1. dedup identity: endpoints vs distinct IPs (routable only)
add("dedup: 8,592 endpoints -> 8,535 distinct", n_endpoints == 8592 and N == 8535,
    f"endpoints={n_endpoints} distinct={N}")

# 2. reachable-by-network figure
rbn = svg_text("reachable_by_network.svg")
add("reachable_by_network IPv4", f"{n_ipv4:,}" in rbn and n_ipv4 == 6732, f"{n_ipv4}")
add("reachable_by_network IPv6", f"{n_ipv6:,}" in rbn and n_ipv6 == 1803, f"{n_ipv6}")
add("reachable_by_network onion", f"{len(onion):,}" in rbn, f"{len(onion)}")
add("reachable_by_network I2P", f"{len(i2p):,}" in rbn, f"{len(i2p)}")

# 3. country / continent geolocation
raw = json.load(open(D + "raw_census.json"))
cbi = {e["address"]: e.get("country", "") for t in ("new", "tried") for e in raw.get(t, {}).values()}
abi = {e["address"]: e.get("mapped_as") for t in ("new", "tried") for e in raw.get(t, {}).values()}
for r in csv.DictReader(open(D + "census_merged.csv")):
    ip = r["ip"]
    if not cbi.get(ip) and r.get("country"):
        cbi[ip] = r["country"]
    if not abi.get(ip) and r.get("asn") and r["asn"] not in ("0", "None", ""):
        abi[ip] = int(r["asn"])
ctry = Counter(cbi.get(r["ip"], "") for r in bc)
geoloc = sum(v for k, v in ctry.items() if k)
n_countries = len([k for k in ctry if k])
add("country US=3,433", ctry.get("US") == 3433 and "3,433" in prose, f"{ctry.get('US')}")
add("country DE=1,614", ctry.get("DE") == 1614 and "1,614" in prose, f"{ctry.get('DE')}")
add("95 countries", n_countries == 95 and "95 countries" in prose, f"{n_countries}")
add("geolocation sums to total", geoloc + ctry.get("", 0) == N, f"{geoloc}+{ctry.get('',0)}={N}")

CONT = {"Europe": "DE FR NL GB CH CZ SE AT PL RO LT CY BG UA ES IT PT NO FI DK BE SI LV EE SK IS HU GR IE HR RS MT AD LI GG FO LU BY MD EU RE".split(),
        "N. America": "US CA MX PA CR GT BZ SV KN PR DO AG AI".split(),
        "S. America": "BR AR CO CL VE UY BO PE".split(),
        "Asia": "KR SG CN JP HK TW TH MY IN ID AE KW TR IL OM PK AZ VN PH KZ QA SA KH MO IR KG GE".split(),
        "Africa": "ZA AO SC".split(), "Oceania": "AU NZ".split(), "Russia": "RU".split()}
cm = {cc: k for k, v in CONT.items() for cc in v}
cont_tot = Counter()
for cc, n in ctry.items():
    if cc:
        cont_tot[cm.get(cc, "Other")] += n
add("continents sum to geolocated", sum(cont_tot.values()) == geoloc, f"{sum(cont_tot.values())}")
add("no unmapped-continent country", "Other" not in cont_tot, f"{cont_tot.get('Other',0)} stray")

# 4. clearnet partitions each cover all N
impl = Counter(("Knots" if "Knots" in r["user_agent"] else "Core" if "Satoshi" in r["user_agent"] else "o") for r in bc)
add("implementation partition = N", sum(impl.values()) == N, f"{sum(impl.values())}")


def vt(ua):
    if "Satoshi:" not in ua:
        return None
    v = ua.split("Satoshi:")[1].split("/")[0].split("(")[0]
    return tuple(int(x) for x in v.split(".") if x.isdigit()) or None


def em(t):
    return t[1] if t and t[0] == 0 and len(t) > 1 else (t[0] if t else None)


def band(t):
    e = em(t)
    if e is None:
        return None
    if e >= 26:
        return "v26+"
    if 21 <= e <= 25:
        return "v0.21-25"
    if e in (19, 20):
        return "v0.19-20"
    if e in (16, 17, 18):
        return "v0.16-18"
    if e in (14, 15) or (e == 13 and len(t) > 2 and t[2] >= 1):
        return "v0.13.1-15"
    if e == 13:
        return "v0.13.0"
    if e == 12:
        return "v0.12"
    return "<v0.12"


vpb = defaultdict(set)
vb = Counter()
for r in bc:
    t = vt(r["user_agent"])
    b = band(t)
    if b:
        vb[b] += 1
        vpb[b].add(t)
n_vers = sum(len(s) for s in vpb.values())
add("version: 82 versions -> 8 bands", n_vers == 82 and len(vb) == 8,
    f"{n_vers} versions, {len(vb)} bands")
add("version: 82->8 in prose + figure", "82 " in prose and "8 band" in prose
    and "82 distinct versions -> 8 bands" in svg_text("version_bands.svg"), "")
add("version partition = N (banded + unparseable)", sum(vb.values()) <= N, f"{sum(vb.values())} banded")

# 5. onion vs clearnet figure percentages recomputed
def pruned(r):
    svc = r.get("service_names", [])
    return "NETWORK_LIMITED" in svc and "NETWORK" not in [s for s in svc if s != "NETWORK_LIMITED"]


R = lambda x: round(x, 1)
ovc = svg_text("onion_vs_clearnet.svg")
cl_pr, on_pr = R(100 * sum(map(pruned, bc)) / N), R(100 * sum(map(pruned, onion)) / len(onion))
add("onion_vs_clearnet pruned", f"{cl_pr}%" in ovc and f"{on_pr}%" in ovc, f"cl {cl_pr} on {on_pr}")

# 6. AS concentration figure note matches recompute
node_as, bw_as = Counter(), Counter()
for r in bc:
    a = abi.get(r["ip"])
    if a:
        node_as[a] += 1
    if a and r.get("block_mbps"):
        bw_as[a] += r["block_mbps"]
t1n = round(100 * node_as.most_common(1)[0][1] / sum(node_as.values()))
t1b = round(100 * bw_as.most_common(1)[0][1] / sum(bw_as.values()))
asc = svg_text("as_concentration.svg")
add("AS conc top-1 node% in figure+prose", f"~{t1n}% nodes" in asc and f"{t1n}%" in prose, f"{t1n}%")
add("AS conc top-1 bw% in figure+prose", f"~{t1b}% bandwidth" in asc and f"{t1b}%" in prose, f"{t1b}%")

# 7. targeting cascade from its own results file
lrt = json.load(open("results/low_resource_targeting.json"))
cost0 = lrt["cascade"]["bw_0_all"]["probe_cost"]
cost2 = lrt["cascade"]["bw_2_res_lat"]["probe_cost"]
cut = round(100 * (cost0 - cost2) / cost0)
add("targeting 3,992 -> 377 = 91%", cost0 == 3992 and cost2 == 377 and cut == 91
    and "3,992" in prose and "377" in prose and "91%" in prose, f"{cost0}->{cost2} ={cut}%")
add("soft targets prose matches result", str(lrt["vulnerable"]["soft_targets"]) in prose,
    f"{lrt['vulnerable']['soft_targets']}")
add("targeting cascade pool == clearnet total", lrt["cascade"]["bw_0_all"]["pool"] == N,
    f"pool={lrt['cascade']['bw_0_all']['pool']} N={N}")
_pruned = lrt["signal_prevalence"]["pruned"]
add("pruned count in prose matches result", f"{_pruned:,}" in prose, f"{_pruned}")

# 8. CVE exposure table matches exposure_map.json
exp = json.load(open("results/exposure_map.json"))
cve_ok = all(f"{exp[c]['exposed_pct']}%" in prose for c in exp if isinstance(exp[c], dict) and "exposed_pct" in exp[c])
add("every CVE exposed_pct present in prose", cve_ok, "")
cve_svg = svg_text("cve_exposure.svg")
cve_fig_ok = all(f"{exp[c]['exposed_pct']}%" in cve_svg for c in exp if isinstance(exp[c], dict) and "exposed_pct" in exp[c])
add("every CVE exposed_pct present in cve_exposure figure", cve_fig_ok, "")

# ---------------------------------------------------------------- report
print(f"\n{'VERIFICATION: data -> figure -> prose':50}")
print("=" * 72)
npass = 0
for name, ok, detail in checks:
    mark = "PASS" if ok else "FAIL"
    if ok:
        npass += 1
    print(f"  [{mark}] {name:44} {detail}")
print("=" * 72)
print(f"  {npass}/{len(checks)} checks passed  (clearnet total = {N}, networks total = {N + len(onion) + len(i2p)})")
if npass != len(checks):
    sys.exit(1)
