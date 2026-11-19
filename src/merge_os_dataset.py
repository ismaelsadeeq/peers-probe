#!/usr/bin/env python3
"""Backfill census OS coverage from the public node-OS fingerprint dataset.

Our own light nmap pass classified ~22% of nodes (we kept only accuracy>=70);
ViniciusCestarii's monthly nmap OS scan (https://github.com/ViniciusCestarii/
bitcoin-node-os-fingerprint) publishes guesses for far more hosts. Joining it in
by IP lifts our OS coverage to ~91% -- sharpening the `device` signal and the
latency-by-OS profiles.

Policy: keep our own classification where we have one (more conservative, same
scan vantage as the rest of the census); fill every remaining Unknown from the
external dataset. Record provenance in an os_source column.

  data/census_merged.csv            (updated in place; backup kept)
  data/os_scan_2026-10-01.csv       (external dataset)
"""
import csv, os, shutil

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # repo root (src/..)
D = lambda *p: os.path.join(HERE, "data", *p)
MERGED, EXT = D("census_merged.csv"), D("os_scan_2026-10-01.csv")


def main():
    ext = {}
    for r in csv.DictReader(open(EXT)):
        if r["os_class"] and r["os_class"] != "Unknown":
            ext[r["ip_address"]] = (r["os_class"], r.get("accuracy", ""))

    rows = list(csv.DictReader(open(MERGED)))
    fields = rows[0].keys()
    out_fields = list(fields) + (["os_source"] if "os_source" not in fields else [])

    filled = own = 0
    for r in rows:
        oc = r.get("os_class", "Unknown")
        if oc not in ("Unknown", ""):
            r["os_source"] = "own-scan"
            own += 1
        elif r["ip"] in ext:
            r["os_class"] = ext[r["ip"]][0]
            r["os_source"] = "ext-nmap-2026-10"
            filled += 1
        else:
            r["os_source"] = "unknown"

    shutil.copyfile(MERGED, MERGED + ".pre_osbackfill")
    with open(MERGED, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=out_fields)
        w.writeheader(); w.writerows(rows)

    N = len(rows)
    cov = own + filled
    print(f"nodes: {N}")
    print(f"  own-scan OS:        {own} ({100*own/N:.1f}%)")
    print(f"  backfilled (ext):   {filled} ({100*filled/N:.1f}%)")
    print(f"  total OS coverage:  {cov} ({100*cov/N:.1f}%)")
    print(f"[updated] {MERGED}  (backup: census_merged.csv.pre_osbackfill)")


if __name__ == "__main__":
    main()
