#!/usr/bin/env python3
"""Cross-network census from a Bitnodes snapshot (covers IPv6/onion/I2P we can't probe).

Our direct prober is IPv4-only (no IPv6 egress, no Tor/I2P). A public crawler
snapshot already handshaked every reachable node on every network and recorded its
user agent, services, height, and ASN. This ingests that snapshot with our own
tooling (peer_probe.decode_services + the exposure_map version->CVE logic) and
breaks the network down by version, service flags, and AS, per network type.

What the snapshot HAS: UA, version, services, height, ASN, country (all networks).
What it does NOT have: latency and block throughput -- those stay IPv4-only, from
our direct probe.

  data/bitnodes_latest.json  (curl https://bitnodes.io/api/v1/snapshots/latest/)
  -> results/census_snapshot.{txt,json}
"""
from __future__ import annotations
import json, os
from collections import Counter
import peer_probe as pp
from exposure_map import version_tuple, era_major, CVES

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = lambda *p: os.path.join(HERE, "data", *p)
R = lambda *p: os.path.join(HERE, "results", *p)

APPLIANCE = ("futurebit", "apollo", "umbrel", "mynode", "raspiblitz", "start9", "nodl")

def net_of(addr):
    if ".onion" in addr: return "onion"
    if ".i2p" in addr:   return "i2p"
    if addr.startswith("["): return "ipv6"
    return "ipv4" if addr.count(":") == 1 else "cjdns"

def pruned(svc):   # NETWORK_LIMITED set, full NETWORK not
    return bool(svc & (1 << 10)) and not (svc & (1 << 0))

def load():
    d = json.load(open(D("bitnodes_latest.json")))
    rows = []
    for addr, info in d["nodes"].items():
        ua = info[1] or ""
        rows.append({
            "net": net_of(addr), "ua": ua, "svc": info[3] or 0,
            "era": era_major(version_tuple(ua)), "height": info[4],
            "asn": info[11] if len(info) > 11 else None,
            "country": info[7] if len(info) > 7 else None,
        })
    return d.get("timestamp"), rows

def main():
    ts, rows = load()
    N = len(rows)
    nets = ["ipv4", "ipv6", "onion", "i2p"]
    lines = []
    def p(s=""): lines.append(s); print(s)

    p(f"CROSS-NETWORK CENSUS  (Bitnodes snapshot ts={ts}, {N} reachable nodes)")
    p("=" * 74)
    p("NOTE: publicly-reachable (listening) nodes only. Nodes behind NAT that do not")
    p("      accept inbound connections are the network majority and are invisible to")
    p("      every crawler, including this one.")
    bynet = Counter(r["net"] for r in rows)
    p("reachable by network: " + ", ".join(f"{k} {v} ({100*v/N:.1f}%)" for k, v in bynet.most_common()))

    out = {"timestamp": ts, "total": N, "by_network": dict(bynet), "per_net": {}}

    for net in nets:
        g = [r for r in rows if r["net"] == net]
        if not g: continue
        eras = [r["era"] for r in g if r["era"]]
        pr = sum(1 for r in g if pruned(r["svc"]))
        app = sum(1 for r in g if any(t in r["ua"].lower() for t in APPLIANCE))
        kn = sum(1 for r in g if "knots" in r["ua"].lower())
        vuln = sum(1 for e in eras if e < 25)                       # <v25 unpatched remote crash
        p(f"\n--- {net}  (n={len(g)}) ---")
        p(f"  pruned (disk-limited): {100*pr/len(g):4.1f}%   Knots: {100*kn/len(g):4.1f}%   appliance: {100*app/len(g):4.1f}%")
        p(f"  vulnerable (<v25):     {100*vuln/max(1,len(eras)):4.1f}%   (n with parseable version: {len(eras)})")
        topv = Counter(f"v{e}" for e in eras).most_common(6)
        p(f"  top versions: " + ", ".join(f"{k}({c})" for k, c in topv))
        if net in ("ipv4", "ipv6"):
            asns = Counter(r["asn"] for r in g if r["asn"]).most_common(5)
            p(f"  top ASNs: " + ", ".join(f"AS{a}({c})" for a, c in asns))
            ctry = Counter(r["country"] for r in g if r["country"]).most_common(5)
            p(f"  top countries: " + ", ".join(f"{a}({c})" for a, c in ctry))
        out["per_net"][net] = {"n": len(g), "pruned_pct": round(100*pr/len(g), 1),
                               "knots_pct": round(100*kn/len(g), 1), "appliance_pct": round(100*app/len(g), 1),
                               "vuln_lt_v25_pct": round(100*vuln/max(1, len(eras)), 1),
                               "versioned": len(eras), "top_versions": topv}

    # CVE exposure by network (using the same advisory fix-lines as the IPv4 study)
    p("\n--- CVE exposure (share of versioned nodes below the fix line), by network ---")
    p(f"  {'advisory':16}{'fixed<':8}" + "".join(f"{n:>8}" for n in nets))
    out["cve_by_net"] = {}
    for cve, desc, fixstr, fix, bp, special, flaggable, trigger, pr in CVES:
        fixed = fix[1] if fix[0] == 0 else fix[0]      # major fix line (Bitnodes view is era-level)
        row = {}
        cells = ""
        for net in nets:
            eras = [r["era"] for r in rows if r["net"] == net and r["era"]]
            pct = 100 * sum(e < fixed for e in eras) / max(1, len(eras))
            row[net] = round(pct, 1); cells += f"{pct:7.1f}%"
        p(f"  {cve:16}v{fixed:<7}{cells}")
        out["cve_by_net"][cve] = row

    os.makedirs(R(), exist_ok=True)
    open(R("census_snapshot.txt"), "w").write("\n".join(lines) + "\n")
    json.dump(out, open(R("census_snapshot.json"), "w"), indent=2)

    # figures
    import svgplot
    figdir = R("figures"); os.makedirs(figdir, exist_ok=True)
    save = lambda n, svg: open(os.path.join(figdir, n), "w").write(svg)
    present = [n for n in nets if n in out["per_net"]]
    # NB: the "reachable nodes by network" count chart now comes from our own direct
    # probe (make_plots.py -> reachable_by_network.svg); the Bitnodes network mix is
    # a different, under-sampled view of IPv6, so we no longer publish it as a count.
    save("census_pruned_by_net.svg", svgplot.barh(
        "Pruned (disk-limited) share by network",
        [(n, out["per_net"][n]["pruned_pct"]) for n in present], unit="%", color="#38a169",
        note="IPv6 is the most pruned cohort; onion/I2P the least"))
    save("census_vuln_by_net.svg", svgplot.barh(
        "Vulnerable (version < v25) share by network",
        [(n, out["per_net"][n]["vuln_lt_v25_pct"]) for n in present], unit="%", color="#e53e3e",
        note="IPv6 more exposed than IPv4; onion/I2P barely exposed"))
    p("\n[saved] results/census_snapshot.{txt,json} + 3 figures")

if __name__ == "__main__":
    main()
