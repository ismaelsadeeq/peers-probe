# data

These are the input files the report was computed from. Running reproduce.sh in the repo
root regenerates every analysis output from them, with no live node needed.

## In the repo, in the order they build on each other

- [raw_census.json](raw_census.json) — the node's address-manager dump (getrawaddrman): the
  addresses the node knows, each with its mapped ASN. This is the starting point. From
  bitcoin-cli getrawaddrman, enriched by resolve_asn.py.
- [blockcensus.json](blockcensus.json) / [blockcensus.csv](blockcensus.csv) — the probe of
  those addresses: every address we tried (75,374 IP:port records, 73,345 unique IPs), with its handshake result and a
  block-download throughput measurement. 8,535 distinct routable nodes reachable. From harvest.py.
- [asn_type.json](asn_type.json) — a lookup from ASN to network type (ISP, hosting,
  transit, and so on), from PeeringDB. This is what separates residential home nodes from
  datacenter nodes. Built by resolve_asn.py.
- [nmap_os_v4_2026-11-11.xml](nmap_os_v4_2026-11-11.xml) — our own nmap OS scan of the IPv4
  nodes, run on 2026-11-11.
- [census_merged.csv](census_merged.csv) — the three files above joined into the reachable
  clearnet census: 8,535 routable nodes with version, OS, ASN, country and latency. Built by
  merge_census.py; this is what most of the analysis reads.
- [onion_census.json](onion_census.json) — the onion node census, probed over Tor. From
  harvest.py.
- [bitnodes_latest.json](bitnodes_latest.json) — a snapshot from the Bitnodes crawler, used
  for the cross-network breadth comparison: a continuous crawler sees more onion and I2P
  nodes than our point-in-time probe. From the Bitnodes API.
- [peer_analysis.json](peer_analysis.json) — a small counts-only summary of the census.

The node addresses in these files are public: they are gossiped on the network and listed
by public crawlers.

## Other data used to produce the census above (not in the repo, regenerable with src/run_census.sh)

- The address lists we probed: the crawler dumps from fishfoo, achownodes and Bitnodes, plus
  the raw direct-census records.
- Side measurements the analysis does not read: a direct IPv4 reachability probe, an nmap OS
  scan of the IPv6 nodes, the I2P node census, behavioural version-detection results, and the
  public monthly node-OS dataset (github.com/ViniciusCestarii/bitcoin-node-os-fingerprint).

The observer first-spy records are not census data: each links a transaction to the IP that
announced it first, so they are kept out on purpose. Only aggregate numbers from them appear
in the report.
