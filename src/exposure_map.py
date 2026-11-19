#!/usr/bin/env python3
"""Map reachable nodes to the published CVEs their version is exposed to.

This is a measurement, not an exploitation tool. We observe each node's full
version from its user agent (e.g. 29.5.0, 30.4.0, 32.0.0), and for every advisory
we know the exact release that fixed it AND the point releases it was backported
to. A node is exposed to an advisory only if its version is below the fix and
below the backport line for its own release series. Because we can see the full
version, this is the precise exposed set, not a major-rounded upper bound.

Two advisories need extra conditions:
  CVE-2024-52919  address-rate-limiting from v22 makes the overflow impractical,
                  so the practical exposure is <v22, not <v29.
  CVE-2026-117350 affects non-Linux nodes only, so we intersect with the nmap OS.

Note on v32: Bitcoin Core 32.0 was tagged but never released; the first 32-series
release is 32.1, which is why the v32 advisories' fix line is 32.1 and the few
nodes advertising 32.0.0 (pre-release tag builds) are below it.

Usage:  python3 exposure_map.py      # reads data/blockcensus.json (+ census_merged.csv for OS)
"""
import json
import csv
import os
import ipaddress

# One row per remotely-triggerable advisory. Severity and trigger verified against
# https://bitcoincore.org/en/security-advisories/ (Nov 2026).
#   cve, description(+severity), fix-version label, fix tuple, {series-major: backport min tuple},
#   special condition, behaviour-flaggable, trigger, fix PR / notes
CVES = (
    ("CVE-2018-17144", "inflation / assert DoS (Critical)",    "0.16.3", (0, 16, 3), {},                                None,         "YES",     "block",       "PR #14247 (0.16.3)"),
    ("CVE-2024-52912", "timestamp-overflow net-split (Med)",   "0.21.0", (0, 21, 0), {},                                None,         "YES",     "p2p msg",     "fixed 0.21.0"),
    ("CVE-2024-35202", "blocktxn assert crash (High)",         "25.0",   (25, 0, 0), {},                                None,         "PARTIAL", "p2p msg",     "PR #26898 (v25.0)"),
    ("CVE-2024-52911", "script interpreter crash (Critical)",  "29.0",   (29, 0, 0), {},                                None,         "NO",      "crafted block", "fixed v29.0"),
    ("CVE-2024-52919", "addrman 32-bit id overflow (Low)",     "29.0",   (29, 0, 0), {},                                "ratelimit22","NO",     "p2p msg",     "PR #30568 (v29.0); rate-limited since v22"),
    ("CVE-2025-46598", "CPU DoS via unconfirmed txs (Med)",    "30.0",   (30, 0, 0), {},                                None,         "NO",      "p2p msg",     "fixed v30.0"),
    ("CVE-2025-54604", "disk fill via spoofed self-conn (Med)", "30.0",  (30, 0, 0), {29: (29, 1, 0)},                  None,         "NO",      "p2p msg",     "fixed v30.0; backported 29.1"),
    ("CVE-2025-54605", "disk fill via invalid blocks (Med)",   "30.0",   (30, 0, 0), {29: (29, 1, 0)},                  None,         "NO",      "block",       "fixed v30.0; backported 29.1"),
    ("CVE-2025-62861", "TRUC eviction corrupts mempool (Med)", "30.0",   (30, 0, 0), {28: (28, 3, 0), 29: (29, 2, 0)}, None,         "NO",      "reorg",       "fixed v30.0; backported 28.3/29.2"),
    ("CVE-2025-62860", "Tor whitelist bypass (High)",          "30.0",   (30, 0, 0), {28: (28, 3, 0), 29: (29, 2, 0)}, None,         "NO",      "p2p msg",     "fixed v30.0; backported 28.3/29.2"),
    ("CVE-2025-62859", "compact block witness stall (Med)",    "30.0",   (30, 0, 0), {29: (29, 2, 0)},                  None,         "NO",      "p2p msg",     "fixed v30.0; backported 29.2"),
    ("CVE-2026-117349", "OOM via paused peer queues (Med)",    "32.1",   (32, 1, 0), {29: (29, 5, 0), 30: (30, 4, 0), 31: (31, 2, 0)}, None,       "NO", "p2p msg",     "fixed v32.1; backported 29.5/30.4/31.2"),
    ("CVE-2026-117350", "OOM via TCP urgent data (Med)",       "32.1",   (32, 1, 0), {29: (29, 5, 0), 30: (30, 4, 0), 31: (31, 2, 0)}, "nonlinux", "NO", "p2p msg",     "fixed v32.1; backported 29.5/30.4/31.2; non-Linux only"),
    ("CVE-2026-117346", "undo file overflow crash (Low)",      "32.1",   (32, 1, 0), {29: (29, 5, 0), 30: (30, 4, 0), 31: (31, 2, 0)}, None,       "NO", "miner reorg", "fixed v32.1; backported 29.5/30.4/31.2"),
)


def routable(ip):
    """Reachable nodes must have a globally-routable address."""
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a in ipaddress.ip_network("2000::/3") if a.version == 6 else a.is_global
    except ValueError:
        return False


def version_tuple(user_agent):
    """'/Satoshi:0.21.1/' -> (0, 21, 1) padded to 3; non-Satoshi -> None."""
    if "Satoshi:" not in user_agent:
        return None
    text = user_agent.split("Satoshi:")[1].split("/")[0].split("(")[0]
    numbers = tuple(int(part) for part in text.split(".") if part.isdigit())
    return (numbers + (0, 0, 0))[:3] if numbers else None


def era_major(version):
    """Release era as one number: 0.21.x -> 21, 25.1.0 -> 25; None if unknown.
    Kept for the Bitnodes cross-network table in census_snapshot.py."""
    if not version:
        return None
    return version[1] if version[0] == 0 and len(version) > 1 else version[0]


def load_nodes(path):
    """Deduped routable reachable nodes as (version_tuple, os_class). os_class
    comes from census_merged.csv when present (only CVE-2026-117350 needs it)."""
    records = [r for r in json.load(open(path)) if r.get("ok") and routable(r["ip"])]
    seen = {}
    for r in records:
        seen.setdefault(r["ip"], r)
    os_by_ip = {}
    try:
        for r in csv.DictReader(open("data/census_merged.csv")):
            os_by_ip[r["ip"]] = r.get("os_class", "") or ""
    except FileNotFoundError:
        pass
    nodes = []
    for ip, r in seen.items():
        v = version_tuple(r["user_agent"])
        if v:
            nodes.append((v, os_by_ip.get(ip, "")))
    return nodes


def is_patched(v, fix, backports):
    """A node is patched if it is at or above the fix, or at or above the backport
    line for its own release series."""
    if v >= fix:
        return True
    return v[0] in backports and v >= backports[v[0]]


def exposed_count(nodes, fix, backports, special):
    if special == "ratelimit22":                       # practical exposure is pre-rate-limit (<v22)
        return sum(1 for v, _ in nodes if v < (22, 0, 0))
    if special == "nonlinux":                           # affects non-Linux nodes only
        known_non_linux = ("Windows", "BSD", "macOS", "Android", "Solaris", "Other/Device")
        return sum(1 for v, o in nodes if not is_patched(v, fix, backports) and o in known_non_linux)
    return sum(1 for v, _ in nodes if not is_patched(v, fix, backports))


def report(nodes):
    total = len(nodes)
    pct = lambda n: 100 * n / total
    lines = [
        f"reachable nodes with a parseable Satoshi version: {total} (deduped, routable)",
        "",
        "PRECISE exposure per advisory (full version compared to fix line + backports):",
        f"{'CVE':<16}{'type':<36}{'fix':<8}{'exposed':<15}{'flag':<9}{'trigger':<14}notes",
    ]
    for cve, desc, fixstr, fix, bp, special, flaggable, trigger, pr in CVES:
        n = exposed_count(nodes, fix, bp, special)
        lines.append(f"{cve:<16}{desc:<36}v{fixstr:<6}{n:>5} ({pct(n):4.1f}%)  {flaggable:<9}{trigger:<14}{pr}")
    lines += [
        "",
        "Backports and the rate-limit/OS conditions are applied, so these are the observed",
        "exposed set, not a major-version upper bound. OS for CVE-2026-117350 is from our nmap",
        "scan plus the ViniciusCestarii node-OS dataset; only KNOWN non-Linux nodes are counted",
        "(unknown-OS nodes are excluded), so that one is a lower bound.",
    ]
    return "\n".join(lines)


def upper_bound_count(nodes, fix):
    """Naive major-rounded exposure: era below the fix's major, ignoring backports
    and extra conditions. This is the number the precise method improves on."""
    major = fix[1] if fix[0] == 0 else fix[0]
    return sum(1 for v, _ in nodes if era_major(v) < major)


def summary_json(nodes):
    total = len(nodes)
    out = {}
    for cve, desc, fixstr, fix, bp, special, flaggable, trigger, pr in CVES:
        n = exposed_count(nodes, fix, bp, special)
        out[cve] = {
            "fixed_in": fixstr,
            "fixed_below_vmajor": fix[1] if fix[0] == 0 else fix[0],
            "type": desc,
            "trigger": trigger,
            "backported": {str(k): ".".join(map(str, v)) for k, v in bp.items()},
            "condition": special or "",
            "behavior_flaggable": flaggable,
            "fix_pr": pr,
            "exposed_nodes": n,
            "exposed_pct": round(100 * n / total, 1),
            "upper_bound_pct": round(100 * upper_bound_count(nodes, fix) / total, 1),
        }
    out["_meta"] = {"versioned_nodes": total}
    return out


def main(path="data/blockcensus.json"):
    nodes = load_nodes(path)
    txt = report(nodes)
    print(txt)
    os.makedirs("results", exist_ok=True)
    open("results/exposure_map.txt", "w").write(txt + "\n")
    json.dump(summary_json(nodes), open("results/exposure_map.json", "w"), indent=2)
    print("\n[saved] results/exposure_map.{txt,json}")


if __name__ == "__main__":
    main()
