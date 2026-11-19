#!/usr/bin/env python3
"""Resolve IP-to-ASN and IP-to-country for all addrman entries.

Uses bulk ip2asn TSV files from iptoasn.com:
  data/ip2asn-v4.tsv   (range_start  range_end  asn  country  description)
  data/ip2asn-v6.tsv   (same format, IPv6)

Adds 'mapped_as' and 'country' fields to every entry in data/raw_census.json.

Usage:  python3 src/resolve_asn.py
"""
import json, os, ipaddress, bisect

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D = lambda *p: os.path.join(HERE, "data", *p)


def load_ip2asn(path):
    """Load a TSV into a sorted list of (start_int, end_int, asn, country)."""
    entries = []
    with open(path) as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) < 4:
                continue
            start = int(ipaddress.ip_address(parts[0]))
            end = int(ipaddress.ip_address(parts[1]))
            asn = int(parts[2])
            country = parts[3] if parts[3] != "None" else ""
            if asn == 0:
                continue  # "Not routed"
            entries.append((start, end, asn, country))
    entries.sort()
    return entries


def lookup(entries, starts, ip_str):
    """Binary-search for the ASN and country of an IP address."""
    try:
        ip_int = int(ipaddress.ip_address(ip_str))
    except ValueError:
        return 0, ""
    idx = bisect.bisect_right(starts, ip_int) - 1
    if idx < 0:
        return 0, ""
    start, end, asn, country = entries[idx]
    if start <= ip_int <= end:
        return asn, country
    return 0, ""


def main():
    print("loading ip2asn tables...")
    v4 = load_ip2asn(D("ip2asn-v4.tsv"))
    v6 = load_ip2asn(D("ip2asn-v6.tsv"))
    v4_starts = [e[0] for e in v4]
    v6_starts = [e[0] for e in v6]
    print(f"  IPv4 ranges: {len(v4)}, IPv6 ranges: {len(v6)}")

    raw = json.load(open(D("raw_census.json")))
    resolved = mapped = countries = 0
    for tbl in ("tried", "new"):
        for e in raw.get(tbl, {}).values():
            addr = e["address"]
            net = e.get("network", "ipv4")
            if net == "ipv4":
                asn, country = lookup(v4, v4_starts, addr)
            elif net == "ipv6":
                asn, country = lookup(v6, v6_starts, addr)
            else:
                asn, country = 0, ""
            e["mapped_as"] = asn
            e["country"] = country
            resolved += 1
            if asn:
                mapped += 1
            if country:
                countries += 1

    json.dump(raw, open(D("raw_census.json"), "w"), indent=2)
    print(f"resolved {resolved} entries, {mapped} ASN ({100*mapped//max(1,resolved)}%), "
          f"{countries} country ({100*countries//max(1,resolved)}%)")
    print(f"[saved] {D('raw_census.json')}")


if __name__ == "__main__":
    main()
