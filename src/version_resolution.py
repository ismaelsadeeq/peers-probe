#!/usr/bin/env python3
"""Measure how much the user agent uniquely reveals a node's version.

The idea
--------
A node's exact version is printed in its user agent (for example
``/Satoshi:0.21.1/``). If we ignore the user agent, the only thing an observer can
learn is which protocol features the node speaks. Many different releases speak the
same set of features, so they are indistinguishable from each other once the user
agent is removed. We call each such set of features a "behavioural band".

This script maps every reachable node's true version (taken from its user agent, as
ground truth) to its behavioural band, and then asks: how many distinct versions
collapse into a shared band (so they are *not* detectable without the user agent),
and how many sit alone in a band (so they *are*)?

Usage
-----
    python3 version_resolution.py [path-to-blockcensus.json]

It prints a summary and writes ``results/version_resolution.txt``.
"""
import json
import sys
from collections import Counter
from itertools import groupby

# Each entry is (predicate on the release "era major", human-readable label).
# The first matching predicate wins, so the list is ordered newest-first.
BANDS = (
    (lambda era: era >= 26,            "v26+  (BIP324 v2 + all 0.21 msgs)"),
    (lambda era: 21 <= era <= 25,      "v0.21-25  (wtxidrelay/addrv2, no v2)"),
    (lambda era: era in (19, 20),      "v0.19-0.20  (compact filters, no wtxidrelay)"),
    (lambda era: era in (16, 17, 18),  "v0.16-0.18  (NETWORK_LIMITED)"),
    (lambda era: era in (14, 15),      "v0.13.1-0.15  (segwit)"),
    (lambda era: era == 13,            "v0.13.0  (sendcmpct/feefilter)"),
    (lambda era: era == 12,            "v0.12  (sendheaders)"),
    (lambda era: True,                 "<v0.12"),
)


def version_tuple(user_agent):
    """Parse a Satoshi user agent into a version tuple, or None if it is not one.

    ``/Satoshi:0.21.1/`` -> (0, 21, 1);  ``/Satoshi:25.1.0/`` -> (25, 1, 0).
    """
    if "Satoshi:" not in user_agent:
        return None
    text = user_agent.split("Satoshi:")[1].split("/")[0].split("(")[0]
    numbers = tuple(int(part) for part in text.split(".") if part.isdigit())
    return numbers or None


def era_major(version):
    """Return the release era as a single number: 0.21.x -> 21, 25.1.0 -> 25."""
    if not version:
        return None
    return version[1] if version[0] == 0 and len(version) > 1 else version[0]


def behavioural_band(version):
    """Return the feature band a version falls into (what P2P probing can see)."""
    era = era_major(version)
    if era is None:
        return "non-Satoshi"
    # Segwit first shipped in 0.13.1, so 0.13.0 is a separate band.
    if era == 13 and len(version) > 2 and version[2] >= 1:
        return "v0.13.1-0.15  (segwit)"
    return next(label for predicate, label in BANDS if predicate(era))


def bands_of(records):
    """Group reachable Satoshi nodes into {band: Counter(version -> node_count)}."""
    versions = [v for v in (version_tuple(r["user_agent"]) for r in records) if v]
    labelled = sorted((behavioural_band(v), ".".join(map(str, v))) for v in versions)
    by_band = lambda pair: pair[0]
    return {
        band: Counter(version for _, version in group)
        for band, group in groupby(labelled, key=by_band)
    }


def summarise(records):
    """Pure function: census records -> the printable report string."""
    bands = bands_of(records)
    total = sum(sum(c.values()) for c in bands.values())
    distinct = sum(len(c) for c in bands.values())
    detectable_versions = sum(len(c) == 1 for c in bands.values())
    detectable_nodes = sum(sum(c.values()) for c in bands.values() if len(c) == 1)

    header = [
        f"reachable nodes with Satoshi version: {total}",
        f"distinct exact versions observed: {distinct}",
        f"behavioral bands populated: {len(bands)}",
        f"versions uniquely detectable without UA: {detectable_versions}",
        f"versions NOT detectable without UA: {distinct - detectable_versions}",
        f"nodes with behavior-detectable exact version: {detectable_nodes} "
        f"({100 * detectable_nodes // total}%)",
        f"nodes UA-only for exact version: {total - detectable_nodes} "
        f"({100 * (total - detectable_nodes) // total}%)",
        "\n--- bands ---",
    ]

    def band_line(band, counter):
        nodes = sum(counter.values())
        verdict = "DETECTABLE" if len(counter) == 1 else f"{len(counter)} versions indistinguishable"
        return f"  {band:42} {nodes:4} nodes  [{verdict}]"

    busiest_first = sorted(bands.items(), key=lambda item: -sum(item[1].values()))
    return "\n".join(header + [band_line(b, c) for b, c in busiest_first])


def main(path="data/blockcensus.json"):
    import os
    records = [r for r in json.load(open(path)) if r.get("ok")]
    report = summarise(records)
    print(report)
    os.makedirs("results", exist_ok=True)
    with open("results/version_resolution.txt", "w") as fh:
        fh.write(report + "\n")


if __name__ == "__main__":
    main(*(sys.argv[1:2]))
