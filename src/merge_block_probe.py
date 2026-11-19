#!/usr/bin/env python3
"""Merge Phase 1 (fast census) + Phase 2 (block probe) without data loss.

Phase 1 gives us UA, service flags, ping, headers for every reachable host.
Phase 2 reconnects to probe block throughput — but some peers evict us before
the block arrives. This script preserves Phase 1 data as the base and only
ADDS block-related fields from Phase 2. It never overwrites a successful field
with a failure.

It also audits the merge for anomalies:
  - hosts reachable in Phase 1 but unreachable in Phase 2 (stale)
  - hosts where Phase 2 got a different UA than Phase 1 (identity mismatch)
  - false-positive rate (Phase 2 ok but no useful data)

Usage:  python3 src/merge_block_probe.py /tmp/census_full.json /tmp/block_probe.json
"""
import json, sys, os, csv

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = lambda *p: os.path.join(HERE, "data", *p)

BLOCK_FIELDS = ("block_ms", "block_bytes", "block_mbps", "block_status")


def merge(phase1_path, phase2_path):
    p1 = json.load(open(phase1_path))
    p2 = json.load(open(phase2_path))

    # index Phase 2 by IP
    p2_by_ip = {r["ip"]: r for r in p2}

    # audit counters
    total = ok_p1 = enriched = stale = ua_mismatch = p2_only_dc = 0
    mismatches = []

    merged = []
    for r in p1:
        total += 1
        if not r["ok"]:
            merged.append(r)
            continue
        ok_p1 += 1

        # look for Phase 2 data for this host
        p2r = p2_by_ip.get(r["ip"])
        if p2r and p2r.get("ok"):
            # check UA consistency
            if p2r.get("user_agent") and r.get("user_agent"):
                if p2r["user_agent"] != r["user_agent"]:
                    ua_mismatch += 1
                    mismatches.append((r["ip"], r["user_agent"], p2r["user_agent"]))

            # merge block fields from Phase 2 into Phase 1 base
            for field in BLOCK_FIELDS:
                if field in p2r:
                    r[field] = p2r[field]

            # upgrade ping/headers if Phase 2 got them and Phase 1 didn't
            for field in ("ping_ms", "headers_ms", "headers_count", "headers_bytes"):
                if p2r.get(field) and not r.get(field):
                    r[field] = p2r[field]

            enriched += 1
        elif p2r and not p2r.get("ok"):
            # Phase 2 couldn't even handshake — keep Phase 1 data, mark block as stale
            r["block_status"] = "stale_p2"
            stale += 1
        elif p2r is None:
            # host wasn't in Phase 2 target list (shouldn't happen if we extracted correctly)
            pass

        merged.append(r)

    # also count Phase 2 hosts that handshaked but got no block
    for r in p2:
        if r.get("ok") and r.get("block_status") in ("disconnected", "no_response"):
            p2_only_dc += 1

    return merged, {
        "total": total,
        "ok_p1": ok_p1,
        "enriched_with_block": enriched,
        "stale_in_p2": stale,
        "ua_mismatch": ua_mismatch,
        "p2_disconnected": p2_only_dc,
        "mismatches": mismatches[:10],  # sample
    }


def main():
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <phase1.json> <phase2.json>")
        sys.exit(1)

    p1_path, p2_path = sys.argv[1], sys.argv[2]
    merged, audit = merge(p1_path, p2_path)

    ok = [r for r in merged if r["ok"]]
    served = sum(1 for r in ok if r.get("block_status") == "served")

    print(f"=== MERGE AUDIT ===")
    print(f"  Phase 1 total:       {audit['total']}")
    print(f"  Phase 1 reachable:   {audit['ok_p1']}")
    print(f"  Enriched with block: {audit['enriched_with_block']}")
    print(f"  Stale in Phase 2:    {audit['stale_in_p2']} (reachable in P1 but not P2)")
    print(f"  P2 disconnected:     {audit['p2_disconnected']} (handshaked but no block)")
    print(f"  UA mismatch:         {audit['ua_mismatch']}")
    if audit["mismatches"]:
        print(f"  sample mismatches:")
        for ip, ua1, ua2 in audit["mismatches"][:5]:
            print(f"    {ip}: P1={ua1} vs P2={ua2}")
    print(f"\n  Final: {len(ok)} reachable, {served} served block")

    # save
    json.dump(merged, open(D("blockcensus.json"), "w"), indent=2)
    with open(D("blockcensus.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "port", "ok", "user_agent", "services",
                    "service_names", "start_height", "connect_ms", "ping_ms",
                    "headers_ms", "headers_count", "block_ms", "block_bytes",
                    "block_mbps", "block_status", "error"])
        for r in merged:
            w.writerow([r["ip"], r["port"], r["ok"], r.get("user_agent", ""),
                        r.get("services", ""), "|".join(r.get("service_names", [])),
                        r.get("start_height", ""), r.get("connect_ms", ""),
                        r.get("ping_ms", ""),
                        r.get("headers_ms", ""), r.get("headers_count", ""),
                        r.get("block_ms", ""), r.get("block_bytes", ""),
                        r.get("block_mbps", ""), r.get("block_status", ""),
                        r.get("error", "")])
    print(f"\n[saved] {D('blockcensus.json')} + {D('blockcensus.csv')}")


if __name__ == "__main__":
    main()
