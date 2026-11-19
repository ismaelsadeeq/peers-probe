#!/usr/bin/env python3
"""Tier-1 network-security analyses (all data-ready):
 1. Eclipse-resistance audit (C1 Heilman / C3 Erebus) from live addrman + asmap.
 2. Capacity-weighted AS/prefix partition surface (C2 Apostolaki / C5).
 3. LinkingLion-style surveillance detector (F1) on live inbound peers + census.
Caveat baked in: ASN = network vantage, not identity (tunnels/VPN/Tor)."""
import json, os
from collections import Counter, defaultdict

D = "data/"
addr = json.load(open(D + "raw_census.json"))          # getrawaddrman snapshot (shipped)
asn_type = {int(k): v for k, v in json.load(open(D + "asn_type.json")).items()}
bc = json.load(open(D + "blockcensus.json"))
# Section 3 (the LinkingLion surveillance detector) needs a LIVE inbound-peer
# snapshot only your own node can produce. To run it, drop a getpeerinfo dump at
# data/peers.json:   bitcoin-cli getpeerinfo > data/peers.json
PEERS_FILE = D + "peers.json"
peers = json.load(open(PEERS_FILE)) if os.path.exists(PEERS_FILE) else None
bw_by_ip = {r["ip"]: r["block_mbps"] for r in bc if r.get("block_mbps")}

def sep(t): print("\n" + "=" * 64 + f"\n {t}\n" + "=" * 64)

# ---------------- 1. ECLIPSE RESISTANCE ----------------
sep("1. ECLIPSE-RESISTANCE AUDIT (addrman + asmap)")
new = list(addr.get("new", {}).values())
tried = list(addr.get("tried", {}).values())
print(f"addrman: {len(new)} new, {len(tried)} tried")

# ASN vs /16 netgroup diversity in the NEW table (where injection happens)
def slash16(ip): return ".".join(ip.split(".")[:2]) if ip.count(".") == 3 else ip.rsplit(":", 4)[0]
asn_n = Counter(e.get("mapped_as") for e in new if e.get("mapped_as"))
s16_n = Counter(slash16(e["address"]) for e in new if e.get("network") == "ipv4")
unmapped = sum(1 for e in new if not e.get("mapped_as"))
print(f"distinct /16 groups: {len(s16_n)}   distinct ASNs: {len(asn_n)}   ASN-0/unmapped: {unmapped} ({100*unmapped//max(1,len(new))}%)")

# asmap collapse: how many /16s does a single ASN span? (= netgroups asmap denies a 1-AS attacker)
as_to_16 = defaultdict(set)
for e in new:
    if e.get("mapped_as") and e.get("network") == "ipv4":
        as_to_16[e["mapped_as"]].add(slash16(e["address"]))
collapse = sorted(((len(v), a) for a, v in as_to_16.items()), reverse=True)[:5]
print("top ASNs by /16 span (asmap collapses each to ONE netgroup vs many under /16):")
for n16, a in collapse:
    print(f"  AS{a:<8} spans {n16} distinct /16 groups  -> /16 bucketing gives attacker {n16} groups, asmap gives 1")

# single-AS flood surface: top AS share of the new table
print("\nsingle-entity flood surface (share of NEW table by ASN):")
for a, c in asn_n.most_common(5):
    pct = 100 * c / len(new)
    print(f"  AS{a:<8} {c:5}  ({pct:4.1f}% of new table)  {'ISP' if asn_type.get(a)=='Cable/DSL/ISP' else asn_type.get(a,'?')}")

# ---------------- 2. CAPACITY-WEIGHTED PARTITION ----------------
sep("2. AS / PREFIX PARTITION SURFACE (capacity-weighted)  [ASN=vantage, not identity]")
ok = [r for r in bc if r.get("ok")]
asn_of = {}
raw = json.load(open(D + "raw_census.json"))
for t in ("new", "tried"):
    for e in raw.get(t, {}).values():
        asn_of[e["address"]] = e.get("mapped_as")
node_as, bw_as = Counter(), Counter()
node_24, bw_24 = Counter(), Counter()
# capped bandwidth to blunt the fast-tail: cap each node at the p90
allbw = sorted(bw_by_ip.values()); p90 = allbw[int(len(allbw)*0.9)] if allbw else 0
cbw_as = Counter()
for r in ok:
    a = asn_of.get(r["ip"]); p24 = ".".join(r["ip"].split(".")[:3])
    if a: node_as[a] += 1
    b = bw_by_ip.get(r["ip"], 0)
    if a and b: bw_as[a] += b; cbw_as[a] += min(b, p90)
    node_24[p24] += 1
    if b: bw_24[p24] += b
def cum(d, tot, k):
    s = sorted(d.values(), reverse=True); return 100*sum(s[:k])/tot if tot else 0
N, BW, CBW = sum(node_as.values()), sum(bw_as.values()), sum(cbw_as.values())
print(f"{'top-k AS':<10}{'% nodes':>9}{'% bandwidth':>13}{'% bw(capped p90)':>18}")
for k in (1, 3, 5, 10, 20):
    print(f"{k:<10}{cum(node_as,N,k):8.1f}%{cum(bw_as,BW,k):12.1f}%{cum(cbw_as,CBW,k):17.1f}%")
N24, BW24 = sum(node_24.values()), sum(bw_24.values())
print(f"\n/24 prefix concentration: top-10 = {cum(node_24,N24,10):.1f}% nodes, {cum(bw_24,BW24,10):.1f}% bandwidth "
      f"(of {len(node_24)} prefixes)")

# ---------------- 3. LINKINGLION DETECTOR ----------------
sep("3. LINKINGLION-STYLE SURVEILLANCE DETECTOR")
if peers is None:
    print("inbound-peer analysis skipped: no data/peers.json.")
    print("to run it, provide a live snapshot:  bitcoin-cli getpeerinfo > data/peers.json")
else:
    inbound = [p for p in peers if p.get("inbound")]
    # signature: inbound, relays tx, but never served us data (synced_blocks==-1) and low recv
    suspects = []
    for p in inbound:
        sig = []
        if p.get("relaytxes"): sig.append("relay")
        if p.get("synced_blocks", 0) == -1 and p.get("synced_headers", 0) <= 0: sig.append("no-data-given")
        if p.get("bytesrecv", 1e9) < 5000: sig.append("low-recv")
        if p.get("connection_type") == "inbound" and len(sig) >= 2:
            suspects.append((p["addr"], p.get("subver",""), p.get("mapped_as",""), sig))
    print(f"inbound peers: {len(inbound)}")
    print(f"peers matching surveillance signature (relay-set + no-data + low-recv): {len(suspects)}")
    for a, ua, asn, sig in suspects[:12]:
        print(f"  {a:24} AS{asn!s:<7} {ua[:22]:22} {','.join(sig)}")
    # /24 clustering of inbound (sybil ranges)
    in24 = Counter(".".join(p["addr"].rsplit(":",1)[0].split(".")[:3]) for p in inbound if p["addr"].count(".")==3)
    clustered = [(k,c) for k,c in in24.most_common(6) if c>1]
    print("\ninbound /24 ranges with multiple connections (sybil clustering):")
    for k,c in clustered: print(f"  {k}.0/24 : {c} inbound")
# census-side: ASes advertising many distinct UAs (spoofing signature, cf AS401476)
as_uas = defaultdict(set)
for r in ok:
    if asn_of.get(r["ip"]): as_uas[asn_of[r["ip"]]].add(r["user_agent"])
spoofy = sorted(((len(v), a) for a,v in as_uas.items()), reverse=True)[:5]
print("\ncensus-side: ASNs with most distinct user agents (multi-UA/spoof signature):")
for n,a in spoofy: print(f"  AS{a:<8} {n} distinct UAs")
