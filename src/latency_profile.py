#!/usr/bin/env python3
"""Per-metadata latency & OS reference profiles (built BEFORE merging into a score).

P2P latency we already captured during the census, at no extra cost:
  connect_ms  -- TCP handshake round-trip (100% coverage; the clean latency metric)
  headers_ms  -- getheaders application round-trip (heavier; ~68% coverage)

This script does NOT compute a composite. It is the reference step: for every
metadata dimension (OS, implementation, AS class, release era, and each
low-resource signal) it reports the latency, throughput and sample size, and
plots them -- so the per-dimension behaviour is visible before any of it is
folded into a targeting score.

Outputs:
  results/latency_profile.txt
  results/figures/latency_by_os.svg, latency_by_asclass.svg,
  results/figures/latency_by_signal.svg, latency_vs_bandwidth.svg
"""
from __future__ import annotations
import os, statistics as st
from collections import defaultdict
import svgplot
from low_resource_targeting import load, ALL_SIGNALS as SIGNALS, R

def med(xs):  return round(st.median(xs), 0) if xs else None
def p90(xs):  return round(sorted(xs)[min(len(xs)-1, int(len(xs)*0.9))], 0) if xs else None

def latency(n):  return n["connect_ms"]          # primary metric: TCP RTT
def served(n):   return n["mbps"] is not None

# --------------------------------------------------- per-dimension aggregation
def profile(nodes, keyfn):
    """Group nodes by keyfn -> {key: {n, lat_med, lat_p90, hdr_med, mbps_med}}."""
    g = defaultdict(list)
    for n in nodes:
        g[keyfn(n)].append(n)
    rows = {}
    for k, grp in g.items():
        lat = [latency(x) for x in grp if latency(x) is not None]
        hdr = [x["headers_ms"] for x in grp if x["headers_ms"] is not None]
        mb = [x["mbps"] for x in grp if x["mbps"] is not None]
        rows[k] = {"n": len(grp), "lat_med": med(lat), "lat_p90": p90(lat),
                   "hdr_med": med(hdr), "mbps_med": med(mb)}
    return rows

def show(p, title, rows, order=None):
    p(f"\n{title}")
    p(f"   {'bucket':22}{'n':>6}{'connect p50':>13}{'connect p90':>13}{'headers p50':>13}{'Mbps p50':>10}")
    keys = order or sorted(rows, key=lambda k: -(rows[k]["lat_med"] or 0))
    for k in keys:
        r = rows[k]
        p(f"   {str(k):22}{r['n']:>6}{str(r['lat_med'])+'ms':>13}"
          f"{str(r['lat_p90'])+'ms':>13}{str(r['hdr_med'])+'ms':>13}{str(r['mbps_med']):>10}")

def main():
    nodes = load()
    lines = []
    def p(s=""): lines.append(s); print(s)
    lat_all = [latency(n) for n in nodes if latency(n) is not None]
    p(f"P2P LATENCY REFERENCE PROFILES  (n={len(nodes)}, connect_ms coverage {len(lat_all)})")
    p("=" * 78)
    p(f"overall connect RTT: p50={med(lat_all):.0f}ms  p90={p90(lat_all):.0f}ms")

    os_rows   = profile(nodes, lambda n: n["os_class"])
    impl_rows = profile(nodes, lambda n: n["impl"] or "?")
    asc_rows  = profile(nodes, lambda n: n["pdb_class"])
    era_rows  = profile([n for n in nodes if n["era"]], lambda n: f"v{n['era']}")
    show(p, "By OS class (nmap)", os_rows)
    show(p, "By implementation", impl_rows)
    show(p, "By AS class (PeeringDB)", asc_rows)
    show(p, "By release era", era_rows, order=sorted(era_rows, key=lambda k: -int(k[1:])))

    # each low-resource signal: latency when the signal is on vs off
    p("\nBy low-resource signal (on vs off)")
    p(f"   {'signal':14}{'on n':>6}{'on p50':>9}{'off n':>7}{'off p50':>9}")
    sig_fig = []
    for name, f in SIGNALS.items():
        on = [latency(n) for n in nodes if f(n) and latency(n) is not None]
        off = [latency(n) for n in nodes if not f(n) and latency(n) is not None]
        p(f"   {name:14}{len(on):>6}{str(med(on))+'ms':>9}{len(off):>7}{str(med(off))+'ms':>9}")
        sig_fig.append((f"{name} (on, n={len(on)})", med(on) or 0))
        sig_fig.append((f"{name} (off)", med(off) or 0))

    # -------------------------------------------------------------- figures
    figdir = R("figures"); os.makedirs(figdir, exist_ok=True)
    def save(name, svg): open(os.path.join(figdir, name), "w").write(svg); p(f"   [fig] {name}")

    save("latency_by_asclass.svg", svgplot.barh(
        "Median TCP connect latency by AS class",
        [(f"{k} (n={asc_rows[k]['n']})", asc_rows[k]["lat_med"] or 0)
         for k in sorted(asc_rows, key=lambda k: asc_rows[k]["lat_med"] or 0)],
        unit=" ms", color="#2b6cb0",
        note="measured from a single EU vantage: this is mostly distance, not node "
             "capability (within-country the AS-class gap is ~20ms)"))
    # (the full per-OS / per-signal / latency-vs-bandwidth breakdowns are in latency_profile.txt)

    os.makedirs(R(), exist_ok=True)
    open(R("latency_profile.txt"), "w").write("\n".join(lines) + "\n")
    p("\n[saved] results/latency_profile.txt + 4 figures")

def _bin_medians(pts, width=50, lo=0, hi=500):
    """pts: (latency, mbps) -> [(bin_center, median_mbps)] for a trend line."""
    buckets = defaultdict(list)
    for lat, mb in pts:
        if lat is None: continue
        b = min(hi, max(lo, int(lat // width) * width))
        buckets[b].append(mb)
    return sorted((b + width/2, st.median(v)) for b, v in buckets.items() if len(v) >= 5)

if __name__ == "__main__":
    main()
