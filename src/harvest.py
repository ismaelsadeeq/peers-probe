#!/usr/bin/env python3
"""CLI: politely harvest user agents + service flags (+ optional headers-speed)
from a sample of addrman addresses.

Examples:
  python3 harvest.py --rawaddrman /tmp/raw_all.json --sample 200 --headers
  python3 harvest.py --targets hosts.txt --concurrency 12 --out /tmp/harvest
"""
import argparse, json, csv, sys, time
from collections import Counter
import peer_probe as pp


def load_targets(args):
    if args.targets:
        out = []
        for line in open(args.targets):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # handle [ipv6]:port and ipv4:port
            if line.startswith("["):
                # bracketed IPv6: [addr]:port
                bracket_end = line.index("]")
                ip = line[1:bracket_end]
                rest = line[bracket_end+1:]
                port = int(rest.lstrip(":") or "8333")
            else:
                ip, port = (line.rsplit(":", 1) + ["8333"])[:2]
                port = int(port)
            out.append((ip, port))
        return out
    raw = json.load(open(args.rawaddrman))
    seen, out = set(), []
    for tbl in ("tried", "new"):          # prefer tried (more likely online)
        for e in raw.get(tbl, {}).values():
            network = e.get("network", "ipv4")
            allowed = {"ipv4", "ipv6"}
            if args.socks_proxy:
                allowed.add("onion")           # Tor routing available
            if network not in allowed:
                continue
            if args.ipv4_only and network != "ipv4":
                continue
            key = (e["address"], e.get("port", 8333))
            if key in seen:
                continue
            seen.add(key)
            out.append((e["address"], int(e.get("port", 8333))))
    return out


def sample(targets, n):
    if n <= 0 or n >= len(targets):
        return targets
    step = len(targets) / n                 # evenly spaced for variety
    return [targets[int(i * step)] for i in range(n)]


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--rawaddrman", help="getrawaddrman JSON dump")
    src.add_argument("--targets", help="file of ip[:port] per line")
    ap.add_argument("--sample", type=int, default=0, help="0 = all")
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--headers", action="store_true", help="also time a getheaders response")
    ap.add_argument("--ping", action="store_true", help="also time a ping/pong round trip (app-layer RTT)")
    ap.add_argument("--block-hash", help="hex block hash to download from each peer (bandwidth probe, MB/s)")
    ap.add_argument("--no-witness", action="store_true", help="request non-witness block")
    ap.add_argument("--ipv4-only", action="store_true", default=False,
                        help="skip IPv6 addresses (default: probe both IPv4 and IPv6)")
    ap.add_argument("--socks-proxy", help="SOCKS5 proxy host:port for Tor routing (e.g. 127.0.0.1:9050)")
    ap.add_argument("--out", default="/tmp/harvest")
    args = ap.parse_args()

    targets = sample(load_targets(args), args.sample)
    print(f"probing {len(targets)} hosts  (concurrency={args.concurrency}, "
          f"timeout={args.timeout}s, headers={args.headers})", file=sys.stderr)

    done = [0]
    def progress(r):
        done[0] += 1
        if done[0] % 25 == 0:
            print(f"  ...{done[0]}/{len(targets)}", file=sys.stderr)

    bh = bytes.fromhex(args.block_hash)[::-1] if args.block_hash else None  # hex -> internal LE
    proxy = None
    if args.socks_proxy:
        h, p = args.socks_proxy.rsplit(":", 1)
        proxy = (h, int(p))
    t0 = time.monotonic()
    results = pp.run_harvest(targets, concurrency=args.concurrency,
                             timeout=args.timeout, do_headers=args.headers,
                             do_ping=args.ping, block_hash=bh,
                             witness=not args.no_witness, on_result=progress,
                             socks_proxy=proxy)
    dt = time.monotonic() - t0

    ok = [r for r in results if r["ok"]]
    print(f"\n=== harvest complete in {dt:.1f}s ===")
    print(f"reachable: {len(ok)}/{len(results)} ({100*len(ok)//max(1,len(results))}%)")

    uas = Counter(r["user_agent"] for r in ok)
    print(f"\n--- user agents ({len(uas)} distinct) ---")
    for ua, c in uas.most_common(20):
        print(f"  {c:4}  {ua}")

    flags = Counter()
    for r in ok:
        for n in r.get("service_names", []):
            flags[n] += 1
    print("\n--- service flags ---")
    for n, c in flags.most_common():
        print(f"  {n:16} {c:4}  {100*c//max(1,len(ok))}%")

    if args.headers:
        spd = sorted(r["headers_ms"] for r in ok if "headers_ms" in r)
        if spd:
            pct = lambda p: spd[min(len(spd) - 1, int(len(spd) * p))]
            print(f"\n--- getheaders response time ({len(spd)} peers) ---")
            print(f"  p50={pct(.5):.0f}ms  p90={pct(.9):.0f}ms  "
                  f"min={spd[0]:.0f}ms  max={spd[-1]:.0f}ms")

    if args.ping:
        png = sorted(r["ping_ms"] for r in ok if "ping_ms" in r)
        if png:
            pct = lambda p: png[min(len(png) - 1, int(len(png) * p))]
            print(f"\n--- ping/pong RTT ({len(png)} peers) ---")
            print(f"  p50={pct(.5):.0f}ms  p90={pct(.9):.0f}ms  min={png[0]:.0f}ms  max={png[-1]:.0f}ms")

    if args.block_hash:
        from collections import Counter as _C
        st = _C(r.get("block_status", "handshake_fail") for r in results)
        print(f"\n--- block-request outcome ({len(results)} targets) ---")
        for k, c in st.most_common():
            print(f"  {k:16} {c}")
        served = [r for r in ok if r.get("block_mbps")]
        mbps = sorted((r["block_mbps"] for r in served), reverse=True)
        print(f"\n--- block download ({len(served)}/{len(ok)} served a block) ---")
        if mbps:
            pc = lambda p: mbps[min(len(mbps) - 1, int(len(mbps) * p))]
            print(f"  Mbps  p50={pc(.5):.1f}  p90={pc(.1):.1f}  p10={pc(.9):.1f}  "
                  f"max={mbps[0]:.1f}  min={mbps[-1]:.2f}")
            sz = next((r["block_bytes"] for r in served), 0)
            print(f"  (block size ~{sz/1e6:.2f} MB; total downloaded ~{sum(r['block_bytes'] for r in served)/1e9:.2f} GB)")

    # artifacts
    with open(args.out + ".json", "w") as f:
        json.dump(results, f, indent=2)
    with open(args.out + ".csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "port", "ok", "user_agent", "services",
                    "service_names", "start_height", "connect_ms", "ping_ms",
                    "headers_ms", "headers_count", "block_ms", "block_bytes",
                    "block_mbps", "block_status", "error"])
        for r in results:
            w.writerow([r["ip"], r["port"], r["ok"], r.get("user_agent", ""),
                        r.get("services", ""), "|".join(r.get("service_names", [])),
                        r.get("start_height", ""), r.get("connect_ms", ""),
                        r.get("ping_ms", ""),
                        r.get("headers_ms", ""), r.get("headers_count", ""),
                        r.get("block_ms", ""), r.get("block_bytes", ""),
                        r.get("block_mbps", ""), r.get("block_status", ""),
                        r.get("error", "")])
    print(f"\n[saved] {args.out}.json / {args.out}.csv")


if __name__ == "__main__":
    main()
