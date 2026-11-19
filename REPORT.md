### Metadata-Driven Targeting of the Bitcoin Peer-to-Peer Network

A measurement study based on a direct handshake census of 73,345 unique clearnet addresses (IPv4 + IPv6)
plus 11,586 onion addresses probed via Tor SOCKS5 + 5,967 I2P addresses via i2pd, aggregated from
five sources (addrman, KIT crawler, achownodes, fishfoo, Bitnodes). Figures regenerate with
`src/make_plots.py`; raw data is in `data/`, numeric results in `results/`.

### Overview

How much can a network observer, honest or adversarial, learn about Bitcoin peers from metadata
alone, and how far does that metadata lower the cost of attacking them? The attacks here
(identifying vulnerable software, selecting resource-constrained nodes) are already documented. We
measure how much the metadata lowers their cost and raises their selectivity, and where current
defenses (asmap, peer eviction) still raise the cost.

The 8,535 reachable clearnet nodes span 95 countries but 59% sit in two (US + Germany). Behavioural probing
collapses 82 versions into 8 bands, yet still separates the vulnerable eras. Cascade filtering by
AS class and latency cuts the probe budget 91%. Hosting is concentrated (the largest AS serves
roughly 31% of observed block bandwidth), though we leave its eclipse and partition significance as
an open question.

### Key findings

| Question | Sub-report | Headline |
|---|---|---|
| What does the network look like? | [Census](reports/census.md) | 8,535 clearnet reachable across 95 countries; 59% in US + Germany (clearnet only, onion/I2P not geolocatable); onion barely pruned, almost never vulnerable |
| Which nodes are exposed to known CVEs? | [Vulnerability](reports/vulnerability.md) | 82 versions collapse to 8 behavioural bands; backport-aware exposure is 40-53% for the v30 batch and 82% for v32.1; vulnerable nodes are well-resourced set-and-forget hosts |
| How cheaply can an adversary find weak nodes? | [Targeting](reports/targeting.md) | Residential AS + latency cut probe budget 91% (3,992 to 377); pruned flag is free; hiding the user agent does not help |
| How concentrated is the hosting? | [Census: AS concentration](reports/census.md) | one AS hosts ~10% of nodes but serves ~31% of observed block bandwidth; eclipse/partition significance left open |

### Sub-reports

- [reports/census.md](reports/census.md): The reachable network, geographic concentration, cross-network census (IPv6, onion, I2P), and AS concentration (raw data, open question).
- [reports/vulnerability.md](reports/vulnerability.md): Version bands, CVE exposure table, the vulnerable cohort analysis.
- [reports/targeting.md](reports/targeting.md): Latency profiles, two-axis scoring, cascade filters.

### Limitations

Single vantage point: fine for the census, address-manager, and AS analyses. Self-reported fields
are spoofable. OS
coverage comes from our own nmap -O scan of all 8,535 clearnet nodes: 4,076 confident matches plus
2,056 backfill from the external monthly dataset gives 71% total OS coverage, with 94% agreement on
the 3,087 IPs that overlap both sources. Bandwidth concentration is tail-dominated by a few
high-throughput hosts, so the AS bandwidth shares are sensitive to those outliers. CVE exposure is
computed from each node's full observed version against the advisory's fix line and its backport
releases, so it is the observed exposed set rather than a major-version upper bound; the one
exception is CVE-2026-117350 (non-Linux only), a lower bound that counts only nodes we can confirm
are non-Linux from the OS scan. DNS seeder cross-validation: 9 seeders returned 260 unique IPs; our census covers 78.5% of
those, while seeders cover only 2.4% of our census (they return a small curated subset, not the full
reachable network). All crawler-based figures cover publicly-reachable listening nodes only.

### Reproducing this work

The scripts live in [`src/`](src) (run from the repo root, e.g. `python3 src/make_plots.py`) and are
documented in [`src/README.md`](src/README.md); tests are in [`tests/`](tests). The handshake blends
in as a normal node (standard version message, service flags, nonce); burst request mode fires all
feature-probe messages simultaneously to race peer eviction, bringing the disconnect rate down to
~1%. Latency is measured per peer with `peer_probe.handshake(..., do_ping=True)` or
`harvest.py --ping`, alongside the TCP `connect_ms`. Onion addresses are probed via Tor SOCKS5 with
4 parallel Tor instances. The two-axis targeting analysis and its figures regenerate with
`python3 src/low_resource_targeting.py`. Raw data is in `data/`, results in `results/`, and the
Core instrumentation on the `persist-user-agent` branch. See [README.md](README.md) for the full map.

### References

- Bitcoin Core security advisories: https://bitcoincore.org/en/security-advisories/
- Fix pull requests #26898, #30568, #14247.
- BIP 14 (user agent), BIP 324 (v2 transport), BIP 339 (wtxid relay), BIP 155 (addrv2).
- Heilman et al. (eclipse attacks), Apostolaki et al. (routing attacks), Tran et al.
  (Erebus partitioning).
- Node-OS fingerprint dataset: ViniciusCestarii, bitcoin-node-os-fingerprint (monthly nmap OS scans),
  https://github.com/ViniciusCestarii/bitcoin-node-os-fingerprint, used as backfill alongside our own
  nmap -O scan (71% total OS coverage, 94% agreement on overlapping IPs).
