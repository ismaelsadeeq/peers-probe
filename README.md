### peer-probe

A study of what a network observer can learn about Bitcoin nodes from
metadata, and how that metadata lowers the cost of attacking them.

This is a census of a mainnet node's address manager reachable peers (IPv4 + IPv6),
aggregating their version, OS, AS, latency and throughput, then studying how cheaply an
adversary can single out resource-constrained or vulnerable nodes.

Where to read, in order:

1. [REPORT.md](REPORT.md): overview, key findings table, and links to sub-reports.
2. Sub-reports (each self-contained):
   - [reports/census.md](reports/census.md) -- What does the network look like?
   - [reports/vulnerability.md](reports/vulnerability.md) -- Which nodes are exposed to known CVEs?
   - [reports/targeting.md](reports/targeting.md) -- How cheaply can an adversary find weak nodes?
3. [src/README.md](src/README.md): what every script does and how to run it.

### Which directory is which

| path | contents |
|---|---|
| [reports/](reports) | Sub-reports: census, vulnerability, targeting. Each is self-contained. |
| [src/](src) | The scripts: P2P prober, active probes, enrichment, analysis, plotting. Per-script reference in [src/README.md](src/README.md) |
| [tests/](tests) | Unit and integration tests for the prober, and CVE behavioural-verification tests. |
| [data/](data) | Collected census artifacts and the external node-OS dataset. Large raw dumps are gitignored. |
| [results/](results) | Regenerable analysis outputs: `*.txt`, `*.json`, and `figures/*.svg`. |

### Reproducing

Every analysis output (`results/` and the figures) regenerates from the committed
`data/` snapshots with no live node — run `bash reproduce.sh`. It is byte-stable: a fresh run
produces no diff. The one live-only exception is `tier1.py`'s LinkingLion inbound-peer detector,
which needs `bitcoin-cli getpeerinfo > data/peers.json` (it skips cleanly otherwise). To instead
re-collect a fresh census from a live node, see `src/run_census.sh`. Data provenance is in
[data/README.md](data/README.md).

### License

Licensed under the MIT License — see [LICENSE](LICENSE).
