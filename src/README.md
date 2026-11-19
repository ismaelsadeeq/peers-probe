### src

The measurement and analysis scripts: a census prober, active probes, enrichment and
analysis, plot generation, and CVE verification tests. Pure Python (standard library)
except plotting (self-contained SVG, no deps) and the tests (`pytest`). Network probing
uses mainnet magic by default; the regtest testbed helper overrides it.

### Running

Run the scripts from the repo root:

```sh
python3 src/low_resource_targeting.py     # two-axis targeting
python3 src/latency_profile.py            # latency by dimension
python3 src/make_plots.py                 # report figures

# prober tests
cd tests && PYTHONPATH=../src python3 -m unittest test_peer_probe test_integration
# CVE behavioural tests are pytest-style (see ../tests for a shim runner)
#   pytest tests/test_cve_*.py            # if pytest is installed
```

### Core probing library

### `peer_probe.py`  (+ `test_peer_probe.py`, `test_integration.py`)
The P2P library everything else builds on. Pure serialization separated from I/O.
- Serialization (unit-testable, no network): `ser/deser_compactsize`, `sha256d`,
  `ser_varstr`, `ser_netaddr`, message framing (`make_message`/`parse_message`, magic
  configurable), `build_version_payload`, `parse_version_payload`, `decode_services`
  (Core + non-core flag names), `build_getheaders_payload`, `build_getdata_payload`,
  `MSG_BLOCK`/`MSG_WITNESS_BLOCK`.
- Network layer: `handshake(ip, port, …)`: connect, v1 version/verack (waits for the
  peer's verack, answers pings), records user agent + service flags + protocol version +
  start height + TCP `connect_ms`; optional `do_ping` application-layer RTT (ping/pong,
  `ping_ms`: the quantity Core tracks as min-ping), `do_headers` latency probe, and full-
  block (`getdata`) throughput probe; returns a result dict, never raises. `run_harvest(
  targets, …)`: bounded-concurrency, one-attempt-per-host (no retry churn) pool.
- Tests: `test_peer_probe.py`: 19 unit tests incl. ping/pong framing and a cross-check
  against Bitcoin Core's `test_framework` (`ser_compact_size`, `hash256`). `test_integration.py`
  handshakes the local node as ground truth (skips if none); validates UA recovery, ping,
  headers + block probes.

### Active probes / collectors

### `harvest.py`
CLI over `run_harvest`: harvest user agents + service flags (+ optional `--ping` app-layer
RTT, `--headers` latency and `--block-hash` full-block throughput) from a target list or a
`getrawaddrman` dump. Reports reachability, UA distribution, service-flag mix, ping/headers
latency and MB-s percentiles and a per-host `block_status`; writes `<out>.{json,csv}`.
`python3 harvest.py --rawaddrman data/raw_census.json --sample 0 --concurrency 100 --ping --headers`

### `feature_fingerprint.py`
Confidence-weighted, UA-independent version bounding. Records the automatic feature-
negotiation messages a peer emits (`wtxidrelay`/`sendaddrv2`/`sendcmpct`/`feefilter`/
`sendheaders`), an active witness-block serve test, and an active BIP324 v2-handshake
detection; derives a firm/best version floor and compares to the UA ground truth.
`python3 feature_fingerprint.py <targets> <recent_block_hash_hex> [max] [conc]`

### Enrichment / analysis

### `tier1.py`
Eclipse + routing analysis from live addrman + asmap + PeeringDB: asmap /16→AS netgroup
collapse, capacity-weighted AS/prefix partition surface, and a LinkingLion-style
surveillance detector over inbound peers. Writes `results/tier1.txt`.

### `version_resolution.py`
Maps each reachable node's true version (UA) to its behavioral band and counts how many
versions collapse into shared bands (UA-only) vs. are uniquely behavior-detectable.
`python3 version_resolution.py data/blockcensus.json` → `results/version_resolution.txt`.

### `exposure_map.py`
Fingerprint→CVE exposure (measurement only): per published remotely-triggerable advisory,
the share of reachable nodes affected (upper bound), whether behavior alone could flag
them, and the fix PR. Writes `results/exposure_map.{txt,json}`.

### `latency_profile.py`
Per-metadata latency reference profiles, built before merging into any score. For each
dimension (OS, implementation, AS class, release era, each low-resource signal) reports
`connect_ms`/`headers_ms` percentiles and throughput. Surfaces that latency tracks the
hosting/residential axis and that `pruned` inverts (pruned nodes are fast VPS). Writes
`results/latency_profile.txt` + four `latency_*` figures.

### `low_resource_targeting.py`
Two-axis targetability analysis (reuses `exposure_map` version logic). Scores a bandwidth
axis (residential AS, appliance UA, Knots, embedded OS, slow TCP RTT) and an orthogonal
disk axis (pruned flag); shows the bandwidth sub-score predicts measured throughput, runs
the free→cheap→probe cascade (residential AS → slow RTT → block probe), and cross-references
the vulnerable (<v25) cohort against both axes. Writes `results/low_resource_targeting.{txt,json}`
+ targeting/vuln figures.

### `merge_os_dataset.py`
Backfills census OS coverage by joining the public monthly node-OS nmap scan
(`data/os_scan_2026-10-01.csv`, ViniciusCestarii/bitcoin-node-os-fingerprint) by IP.
Keeps our own classification where present, fills Unknowns from the dataset, records
provenance in an `os_source` column. Raises OS coverage ~22% -> ~91%. Backs up the
original to `census_merged.csv.pre_osbackfill`.

### `merge_census.py`, `gen_analysis.py`
`merge_census.py` joins the census with asmap/PeeringDB/OS into `census_merged.{csv,json}`.
`gen_analysis.py` renders a local, superseded full-dump analysis (`docs/ANALYSIS.md`, gitignored);
the published report lives in `reports/`, so it is not part of `reproduce.sh`.

### `census_snapshot.py`
Cross-network census from a public Bitnodes snapshot (`data/bitnodes_latest.json`), covering
IPv6/onion/I2P that the direct prober cannot reach. Decodes service flags and maps versions to
CVEs per network. Writes `results/census_snapshot.{txt,json}` + `census_*` figures. Listening
nodes only.

### Plots & report

### `svgplot.py`, `make_plots.py`
`svgplot.py` is a dependency-free SVG chart helper (bars, multi-line). `make_plots.py`
reads `data/` and writes the six report figures to `results/figures/`.

### CVE verification tests (behavioral models)
`test_cve_2024_35202.py`, `test_cve_2024_52919.py`, `test_cve_2024_52912.py`,
`test_cve_2018_17144.py`: registry-record checks + vulnerable-vs-fixed behavioral models
(no live node, no trigger payload). `pytest test_cve_*.py` (45 tests).

### Data (`data/`)
Saved artifacts: `census.{json,csv}` (direct census), `blockcensus.{json,csv}` (with block
throughput), `raw_census.json` (`getrawaddrman`), `asn_type.json` (PeeringDB ASN→type),
`peer_analysis.{csv,json}`, `census_merged.{csv,json}`, `feature_fp.json`. Large raw dumps are
gitignored but kept on disk.

### Results (`results/`)
Regenerable outputs: `version_resolution.txt`, `exposure_map.{txt,json}`, `tier1.txt`,
`latency_profile.txt`, `low_resource_targeting.{txt,json}`, and `figures/*.svg`.

### Core instrumentation (branch `persist-user-agent`)
Three atomic commits on Bitcoin Core:
1. `addrman: persist peer user agents (V5_USERAGENT disk format)`: records the UA via
   `AddrMan::Good()` and persists it in `peers.dat`.
2. `rpc: expose user_agent in getrawaddrman`.
3. `net: configurable feeler interval/concurrency + sweep speedup`: `-feelerinterval` /
   `-maxfeeler` (DEBUG_ONLY) + sweep-mode loop speedup.
