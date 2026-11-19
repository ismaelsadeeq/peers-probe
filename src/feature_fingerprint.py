#!/usr/bin/env python3
"""Confidence-weighted, behavior-only version bounding (UA-independent).

Signal confidence (see analysis):
  HIGH  automatic protocol messages (wtxidrelay/sendaddrv2/sendcmpct/feefilter/
        sendheaders) — faking them means implementing the behavior. Their ABSENCE
        is authoritative (modern nodes always emit them).
  MED   active probes: witness-serve (getdata) and an active BIP324 v2 handshake
        detection (v2 responder replies with a 64-byte ellswift key; v1 disconnects).
  LOW   advertised service flags (P2P_V2 etc.) — toggleable + malleable in relay.
        Used only as tie-breakers, never for the firm floor.

Every signal is a one-sided LOWER bound: presence => floor; absence of MED/LOW is
ignored; absence of a HIGH marker (e.g. no wtxidrelay) => firmly < its version.

Usage: python3 feature_fingerprint.py <targets> <recent_block_hash_hex> [max] [conc]
"""
import sys, socket, time, io, struct, json, os
from concurrent.futures import ThreadPoolExecutor, as_completed
import peer_probe as pp

FEATURE_MSGS = {"wtxidrelay", "sendaddrv2", "sendheaders", "sendcmpct", "feefilter", "sendtxrcncl"}


def probe_v2(ip, port, timeout=6):
    """Active BIP324 detection: send non-magic bytes; v2 responder sends back its
    64-byte ellswift key (+garbage); v1-only node disconnects with no data.
    Returns True (v2), False (v1-only), or None (ambiguous/unreachable)."""
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=timeout); s.settimeout(timeout)
        buf = bytearray(os.urandom(64)); buf[0] = 0x00  # ensure != network magic (0xf9..)
        s.sendall(bytes(buf))
        got = b""; dl = time.monotonic() + timeout
        while len(got) < 64 and time.monotonic() < dl:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            got += chunk
        if len(got) >= 64:
            return True
        if len(got) == 0:
            return False
        return None
    except Exception:
        return None
    finally:
        if s:
            try: s.close()
            except Exception: pass


def infer(proto, svc, feats, witness_served, v2_active):
    """Return (firm_floor, best_floor). firm = HIGH signals only."""
    firm = 0
    if "sendheaders" in feats: firm = max(firm, 12)
    if "sendcmpct" in feats or "feefilter" in feats: firm = max(firm, 13)
    if "wtxidrelay" in feats or "sendaddrv2" in feats: firm = max(firm, 21)
    if "sendtxrcncl" in feats: firm = max(firm, 28)
    best = firm
    if witness_served: best = max(best, 13)   # MED (active)
    if v2_active is True: best = max(best, 26)  # MED (active)
    # LOW advertised flags: tie-breakers only, never raise firm floor
    if "P2P_V2" in svc: best = max(best, 26)
    if "COMPACT_FILTERS" in svc: best = max(best, 19)
    if "NETWORK_LIMITED" in svc: best = max(best, 16)
    return firm, best


def fingerprint(ip, port, block_hash, timeout=8):
    r = {"ip": ip, "ok": False}
    s = None
    try:
        s = socket.create_connection((ip, port), timeout=timeout); s.settimeout(timeout)
        rd = pp._reader(s)
        s.sendall(pp.make_message("version", pp.build_version_payload(
            services=pp.NODE_WITNESS, timestamp=int(time.time()))))
        feats = set(); proto = None; svc = []; ua = None
        dl = time.monotonic() + timeout
        while time.monotonic() < dl:
            c, p = pp.parse_message(rd)
            if c == "version":
                v = pp.parse_version_payload(p); proto, svc, ua = v["version"], v["service_names"], v["user_agent"]
            elif c == "ping": s.sendall(pp.make_message("pong", p))
            elif c in FEATURE_MSGS: feats.add(c)
            elif c == "verack": break
        if proto is None: raise ValueError("no version")
        s.sendall(pp.make_message("verack", b""))
        witness_served = False
        if block_hash:
            s.sendall(pp.make_message("getdata", pp.build_getdata_payload([(pp.MSG_WITNESS_BLOCK, block_hash)])))
            dl2 = time.monotonic() + timeout
            while time.monotonic() < dl2:
                c, p = pp.parse_message(rd)
                if c == "ping": s.sendall(pp.make_message("pong", p)); continue
                if c == "block": witness_served = True; break
                if c == "notfound": break
        try: s.close()
        except Exception: pass
        v2 = probe_v2(ip, port)   # separate connection
        firm, best = infer(proto, svc, feats, witness_served, v2)
        r.update(ok=True, proto=proto, services=svc, features=sorted(feats),
                 witness_served=witness_served, v2_active=v2, user_agent=ua,
                 p2pv2_flag=("P2P_V2" in svc), firm_floor=firm, best_floor=best)
    except Exception as e:
        r["error"] = f"{type(e).__name__}: {e}"
    finally:
        if s:
            try: s.close()
            except Exception: pass
    return r


def ua_major(ua):
    try:
        if "Satoshi:" in ua: return int(ua.split("Satoshi:")[1].split(".")[0])
    except Exception: pass
    return None


def main():
    tf, bh_hex = sys.argv[1], sys.argv[2]
    maxt = int(sys.argv[3]) if len(sys.argv) > 3 else 150
    conc = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    bh = bytes.fromhex(bh_hex)[::-1]
    targets = []
    for line in open(tf):
        line = line.strip()
        if line:
            ip, port = (line.rsplit(":", 1) + ["8333"])[:2]; targets.append((ip, int(port)))
    targets = targets[:maxt]
    res = []
    with ThreadPoolExecutor(max_workers=conc) as ex:
        futs = [ex.submit(fingerprint, ip, p, bh) for ip, p in targets]
        for f in as_completed(futs): res.append(f.result())
    ok = [r for r in res if r.get("ok")]
    from collections import Counter
    print(f"fingerprinted: {len(ok)}/{len(targets)}")
    print("\nFIRM floor (HIGH-confidence automatic msgs only):")
    for fl, c in Counter(r["firm_floor"] for r in ok).most_common():
        print(f"  >= v{fl:<3} {c}")

    # P2P_V2 flag vs active v2 probe (demonstrate flag unreliability)
    flag_yes = [r for r in ok if r["p2pv2_flag"]]
    act_yes = [r for r in ok if r["v2_active"] is True]
    flag_no_act_yes = sum(1 for r in ok if not r["p2pv2_flag"] and r["v2_active"] is True)
    flag_yes_act_no = sum(1 for r in ok if r["p2pv2_flag"] and r["v2_active"] is False)
    print(f"\nP2P_V2 flag vs ACTIVE v2 handshake:")
    print(f"  advertise flag: {len(flag_yes)}   respond to active v2 probe: {len(act_yes)}")
    print(f"  flag=NO but v2 active (flag under-reports): {flag_no_act_yes}")
    print(f"  flag=YES but v2 refused (v1 fallback/off):  {flag_yes_act_no}")

    # accuracy vs UA
    def acc(key):
        tight = loose = contra = 0
        for r in ok:
            m = ua_major(r["user_agent"])
            if m is None: continue
            fl = r[key]
            if fl > m: contra += 1
            elif m - fl <= 2: tight += 1
            else: loose += 1
        return tight, loose, contra
    for key in ("firm_floor", "best_floor"):
        t, l, c = acc(key)
        print(f"\n{key} vs UA:  tight(<=2) {t}   loose {l}   contradiction {c}")
    # <0.21 detection via the authoritative wtxidrelay/sendaddrv2 absence
    old = [r for r in ok if r["firm_floor"] < 21]
    old_true = sum(1 for r in old if (ua_major(r["user_agent"]) or 99) < 21)
    print(f"\n'<v21' flagged by MISSING wtxidrelay/sendaddrv2: {len(old)}  (UA confirms {old_true})")
    json.dump(res, open("/tmp/feature_fp.json", "w"))


if __name__ == "__main__":
    main()
