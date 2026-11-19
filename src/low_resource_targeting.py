#!/usr/bin/env python3
"""Targetability of resource-constrained nodes, split into two orthogonal axes.

Research question (defensive, measurement-only):
  An adversary who wants to preferentially attack resource-constrained nodes
  needs to *find* them cheaply. How well do passive, low-cost network signals
  single out the constrained cohort -- and does that cheap signal predict the
  expensively-measured ground truth (block throughput)?

Key refinement from the latency reference profiles (latency_profile.py): the
constraint signals do NOT point the same way. `pruned` nodes are *lower* latency
than average (people prune to save disk on cheap fast VPS), while residential /
appliance / Knots / embedded nodes are higher latency and lower bandwidth. So we
score TWO orthogonal axes instead of one:

  BANDWIDTH axis  -- residential AS, appliance UA, Knots, embedded OS, slow TCP
                     RTT. Predicts low block throughput. Target of a bandwidth/
                     CPU-exhaustion attack.
  DISK axis       -- the pruned service flag. A declared limited-disk node; the
                     target of a historic-block / disk-pressure attack. It does
                     NOT imply low bandwidth (these nodes are often fast VPS).

Inputs (already collected; no new network activity):
  data/census_merged.csv, data/blockcensus.csv, data/asn_type.json

Outputs:
  results/low_resource_targeting.{txt,json} + figures in results/figures/
"""
from __future__ import annotations
import csv, json, os, statistics as st
from collections import Counter
from exposure_map import version_tuple, era_major

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repo root (src/..)
D = lambda *p: os.path.join(HERE, "data", *p)
R = lambda *p: os.path.join(HERE, "results", *p)

RESIDENTIAL_CLASSES = {"Cable/DSL/ISP"}          # PeeringDB "eyeball" networks
APPLIANCE_TOKENS = ("futurebit", "apollo", "umbrel", "mynode",
                    "raspiblitz", "start9", "ronin", "nodl")
VULN_ERA = 25                 # below this era: unpatched remote-crash (35202/52919)
LAT_SLOW_MS = [0.0]           # p75 of connect_ms, filled in at load time

# ---------------------------------------------------------------- load + join
import ipaddress
def is_routable(ip):
    """A real reachable node must have a globally-routable address. Excludes
    poisoned addrman entries like 1111:1111::1 (reserved IPv6 space)."""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a in ipaddress.ip_network("2000::/3") if a.version == 6 else a.is_global
    except ValueError:
        return False

def load():
    asn_type = json.load(open(D("asn_type.json")))
    merged = {r["ip"]: r for r in csv.DictReader(open(D("census_merged.csv"))) if is_routable(r["ip"])}
    block = {r["ip"]: r for r in csv.DictReader(open(D("blockcensus.csv")))}
    nodes = []
    for ip, m in merged.items():
        mbps = block.get(ip, {}).get("block_mbps")
        nodes.append({
            "ip": ip, "ua": m["user_agent"], "impl": m["impl"], "svc": m["service_names"],
            "asn": m["asn"], "pdb_class": asn_type.get(m["asn"], "Unmapped"),
            "os": m.get("os", ""), "os_class": m.get("os_class", "Unknown"),
            "era": era_major(version_tuple(m["user_agent"])),
            "connect_ms": float(m["connect_ms"]) if m.get("connect_ms") else None,
            "headers_ms": float(m["headers_ms"]) if m.get("headers_ms") else None,
            "mbps": float(mbps) if mbps else None,
            "slash16": ".".join(ip.split(".")[:2]) if ":" not in ip else ip,
        })
    lats = sorted(n["connect_ms"] for n in nodes if n["connect_ms"] is not None)
    LAT_SLOW_MS[0] = lats[int(len(lats) * 0.75)]   # "slow" = top-quartile RTT
    return nodes

# --------------------------------------------------------------- the two axes
def pruned(n):      # DISK axis: NETWORK_LIMITED without full NETWORK -> limited disk
    s = n["svc"]
    return "NETWORK_LIMITED" in s and "NETWORK" not in s.replace("NETWORK_LIMITED", "")

def residential(n): return n["pdb_class"] in RESIDENTIAL_CLASSES
def appliance(n):   return any(t in n["ua"].lower() for t in APPLIANCE_TOKENS)
def knots(n):       return "knots" in n["ua"].lower()
def device(n):
    oc, o = n["os_class"], n["os"].lower()
    return oc in ("Other/Device", "Android") or "openwrt" in o or "router" in o
def slow_latency(n):
    return n["connect_ms"] is not None and n["connect_ms"] >= LAT_SLOW_MS[0]

BW_SIGNALS = {"residential": residential, "appliance": appliance,
              "knots": knots, "device": device, "slow_latency": slow_latency}
DISK_SIGNALS = {"pruned": pruned}
ALL_SIGNALS = {**DISK_SIGNALS, **BW_SIGNALS}

def bw_score(n):   return sum(1 for f in BW_SIGNALS.values() if f(n))
def naive_score(n):return sum(1 for f in ALL_SIGNALS.values() if f(n))  # old combined
def vulnerable(n): return n["era"] is not None and n["era"] < VULN_ERA

# ------------------------------------------------------------------- helpers
def pctile(xs, p):
    xs = sorted(xs); return xs[min(len(xs)-1, int(len(xs)*p))] if xs else float("nan")
def med(xs): return round(st.median(xs), 1) if xs else None

def gradient(nodes, scorefn):
    """score -> {n, served, median_mbps, serve_rate} for a given scoring fn."""
    out = {}
    for s in sorted({scorefn(n) for n in nodes}):
        grp = [n for n in nodes if scorefn(n) == s]
        gs = [n["mbps"] for n in grp if n["mbps"] is not None]
        out[s] = {"n": len(grp), "served": len(gs), "median_mbps": med(gs),
                  "serve_rate": round(100*len(gs)/len(grp), 1)}
    return out

# ------------------------------------------------------------------- analysis
def main():
    nodes = load()
    N = len(nodes)
    served = [n for n in nodes if n["mbps"] is not None]
    served_ips = {n["ip"] for n in served}
    out = {"n_nodes": N, "n_served": len(served), "lat_slow_ms": LAT_SLOW_MS[0]}
    lines = []
    def p(s=""): lines.append(s); print(s)

    p(f"RESOURCE-CONSTRAINED TARGETABILITY  (n={N}, {len(served)} served; slow-RTT>={LAT_SLOW_MS[0]:.0f}ms)")
    p("=" * 74)

    # --- A. signal prevalence, by axis ---
    p("\nA. Signal prevalence by axis (DISK vs BANDWIDTH)")
    for axis, sigs in (("DISK", DISK_SIGNALS), ("BANDWIDTH", BW_SIGNALS)):
        for k, f in sigs.items():
            c = sum(1 for n in nodes if f(n))
            p(f"   [{axis:9}] {k:14} {c:5}  ({100*c/N:4.1f}%)")
    out["signal_prevalence"] = {k: sum(1 for n in nodes if f(n)) for k, f in ALL_SIGNALS.items()}

    # --- B. bandwidth sub-score sharpens the gradient vs the naive combined score ---
    p("\nB. Bandwidth sub-score vs measured throughput (pruned REMOVED from the axis)")
    bw = gradient(nodes, bw_score)
    naive = gradient(nodes, naive_score)
    p(f"   bw-score {'n':>7}{'median Mbps':>13}{'serve%':>8}      naive-score (incl pruned)")
    for s in sorted(set(bw) | set(naive)):
        b = bw.get(s); nv = naive.get(s)
        bstr = f"{b['n']:>7}{str(b['median_mbps']):>13}{b['serve_rate']:>7}%" if b else " "*28
        nstr = f"  | score {s}: {nv['median_mbps']} Mbps (n={nv['n']})" if nv else ""
        p(f"   {s:<8}{bstr}{nstr}")
    # spread = how far top vs bottom band separate (bigger = sharper targeting signal)
    def spread(g):
        meds = [v["median_mbps"] for v in g.values() if v["median_mbps"]]
        return round(max(meds)/min(meds), 2) if len(meds) > 1 and min(meds) else None
    p(f"   => top/bottom Mbps spread: bw-score {spread(bw)}x  vs  naive {spread(naive)}x "
      f"(higher = cleaner separation)")
    out["bw_gradient"], out["naive_gradient"] = bw, naive
    out["spread_bw"], out["spread_naive"] = spread(bw), spread(naive)

    # --- C. bandwidth targeting rule precision/recall ---
    mbps_all = [n["mbps"] for n in served]
    q1 = pctile(mbps_all, 0.25)
    slow = {n["ip"] for n in served if n["mbps"] <= q1}   # ground-truth slow
    p(f"\nC. Bandwidth targeting rule  (ground-truth slow = served & <= p25 = {q1:.1f} Mbps)")
    for thr in (1, 2):
        picked = {n["ip"] for n in nodes if bw_score(n) >= thr}
        ps = picked & served_ips
        tp = len(picked & slow)
        prec = 100*tp/len(ps) if ps else 0
        rec = 100*tp/len(slow) if slow else 0
        p(f"   bw-score>={thr}: pool={len(picked)}  precision={prec:.1f}%  recall={rec:.1f}%")
        out[f"bw_rule_ge_{thr}"] = {"pool": len(picked), "precision": round(prec,1), "recall": round(rec,1)}
    out["slow_p25_mbps"] = round(q1, 1)

    # --- D. the DISK axis is orthogonal: pruned nodes are FAST ---
    p("\nD. Disk axis is orthogonal to bandwidth (pruned != slow)")
    pr = [n for n in nodes if pruned(n)]
    res = [n for n in nodes if residential(n)]
    def axis_stat(grp):
        lat = [n["connect_ms"] for n in grp if n["connect_ms"] is not None]
        mb = [n["mbps"] for n in grp if n["mbps"] is not None]
        return med(lat), med(mb)
    for label, grp in (("pruned (disk)", pr), ("residential (bandwidth)", res), ("all", nodes)):
        lat, mb = axis_stat(grp)
        p(f"   {label:26} n={len(grp):5}  median RTT={lat}ms  median Mbps={mb}")
    out["disk_vs_bw"] = {"pruned": axis_stat(pr), "residential": axis_stat(res), "all": axis_stat(nodes)}

    # --- E. two cascades, cheap filters first ---
    p("\nE. Adversary cascades (cheap filters first, probe survivors)")
    def stage(name, pool, probe_only=True):
        ps = pool & served_ips
        cost = len(ps) if probe_only else 0
        tp = len(pool & slow)
        prec = 100*tp/len(ps) if ps else 0
        rec = 100*tp/len(slow) if slow else 0
        p(f"     {name:30} pool={len(pool):5} probe_cost={cost:5} prec={prec:4.1f}% rec={rec:4.1f}%")
        return {"pool": len(pool), "probe_cost": cost, "precision": round(prec,1), "recall": round(rec,1)}
    p("   BANDWIDTH-exhaustion  (residential AS free -> slow RTT cheap -> block probe):")
    casc = {}
    casc["bw_0_all"]     = stage("probe all", {n["ip"] for n in nodes})
    casc["bw_1_res"]     = stage("+ residential AS (free)", {n["ip"] for n in nodes if residential(n)})
    casc["bw_2_res_lat"] = stage("+ slow TCP RTT (cheap)",
                                 {n["ip"] for n in nodes if residential(n) and slow_latency(n)})
    saved = len(served) - casc["bw_2_res_lat"]["probe_cost"]
    p(f"     => free+cheap pre-filter cuts probe budget {100*saved/len(served):.0f}% "
      f"({len(served)} -> {casc['bw_2_res_lat']['probe_cost']})")
    p("   DISK-exhaustion  (pruned flag is free and self-declared -> no probe needed):")
    casc["disk_pruned"] = stage("pruned flag (free)", {n["ip"] for n in nodes if pruned(n)}, probe_only=False)
    out["cascade"] = casc

    # --- F. vulnerable clients x metadata (softest targets) ---
    vuln = [n for n in nodes if vulnerable(n)]
    p(f"\nF. Vulnerable clients (era < v{VULN_ERA}) x metadata")
    vserved = [n["mbps"] for n in vuln if n["mbps"] is not None]
    allserved = [n["mbps"] for n in served]
    p(f"   vulnerable: {len(vuln)} ({100*len(vuln)/N:.1f}%)  median {med(vserved)} Mbps vs all {med(allserved)} Mbps")
    pc = lambda f, grp: round(100*sum(f(n) for n in grp)/len(grp), 1)
    p(f"   pruned {pc(pruned,vuln)}% (all {pc(pruned,nodes)}%) | residential {pc(residential,vuln)}% (all {pc(residential,nodes)}%) | device {pc(device,vuln)}% (all {pc(device,nodes)}%)")
    p("   by version: " + ", ".join(f"v{e}({c})" for e, c in Counter(n["era"] for n in vuln).most_common(6)))
    soft = [n for n in vuln if bw_score(n) >= 2 or pruned(n)]
    p(f"   softest targets (vulnerable AND constrained on either axis): {len(soft)}")
    out["vulnerable"] = {"n": len(vuln), "pct": round(100*len(vuln)/N,1), "median_mbps": med(vserved),
                         "soft_targets": len(soft), "by_version": Counter(n["era"] for n in vuln).most_common()}

    # ------------------------------------------------------------- persist + figures
    os.makedirs(R(), exist_ok=True)
    open(R("low_resource_targeting.txt"), "w").write("\n".join(lines) + "\n")
    json.dump(out, open(R("low_resource_targeting.json"), "w"), indent=2)
    make_figures(nodes, bw, naive, casc, vuln, pr, res)
    p("\n[saved] results/low_resource_targeting.{txt,json} + figures")

# ------------------------------------------------------------------- figures
def make_figures(nodes, bw, naive, casc, vuln, pr, res):
    import svgplot
    figdir = R("figures"); os.makedirs(figdir, exist_ok=True)
    save = lambda name, svg: open(os.path.join(figdir, name), "w").write(svg)

    save("targeting_bw_gradient.svg", svgplot.barh(
        "Bandwidth sub-score vs measured throughput (pruned excluded)",
        [(f"bw-score {s} (n={bw[s]['n']})", bw[s]["median_mbps"] or 0, f"{bw[s]['serve_rate']:.0f}% serve")
         for s in sorted(bw)],
        unit=" Mbps", color="#2b6cb0",
        note="residential+appliance+Knots+embedded+slow-RTT; no bandwidth probe"))

    save("targeting_cascade.svg", svgplot.barh(
        "Bandwidth-exhaustion cascade: free+cheap filters shrink the probe budget",
        [("probe all", casc["bw_0_all"]["probe_cost"], f"{casc['bw_0_all']['precision']:.0f}% prec"),
         ("+ residential AS (free)", casc["bw_1_res"]["probe_cost"], f"{casc['bw_1_res']['precision']:.0f}% prec"),
         ("+ slow TCP RTT (cheap)", casc["bw_2_res_lat"]["probe_cost"], f"{casc['bw_2_res_lat']['precision']:.0f}% prec")],
        unit=" probes", color="#dd6b20",
        note="residential+latency pre-filter cuts block requests, raises precision"))

    # the orthogonality picture: disk cohort is fast, bandwidth cohort is slow
    def stat(grp, key):
        xs = [n[key] for n in grp if n[key] is not None]; return med(xs) or 0
    save("axis_split.svg", svgplot.barh(
        "Disk vs bandwidth axis are orthogonal (pruned nodes are fast)",
        [("pruned RTT (ms)", stat(pr, "connect_ms")), ("residential RTT (ms)", stat(res, "connect_ms")),
         ("pruned Mbps", stat(pr, "mbps")), ("residential Mbps", stat(res, "mbps"))],
        unit="", color="#38a169",
        note="pruned = disk-limited but low-latency VPS; residential = bandwidth-limited"))

    pc = lambda f, grp: round(100*sum(f(n) for n in grp)/len(grp), 1)
    save("vuln_profile.svg", svgplot.barh(
        "Vulnerable nodes (<v25) vs network: a different, hosted cohort",
        [("pruned · vuln", pc(pruned, vuln)), ("pruned · all", pc(pruned, nodes)),
         ("residential · vuln", pc(residential, vuln)), ("residential · all", pc(residential, nodes)),
         ("device · vuln", pc(device, vuln)), ("device · all", pc(device, nodes))],
        unit="%", color="#e53e3e",
        note="vulnerable cohort is faster and less residential -> set-and-forget hosted nodes"))

    save("vuln_by_version.svg", svgplot.barh(
        "Vulnerable nodes by Bitcoin Core release era (<v25)",
        [(f"v{e}", c) for e, c in sorted(Counter(n["era"] for n in vuln).items(), reverse=True)],
        unit=" nodes", color="#805ad5",
        note="old set-and-forget nodes; user agent is the high-value signal here"))

if __name__ == "__main__":
    main()
