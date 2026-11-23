### Targeting: How cheaply can an adversary find weak nodes?

Latency profiles, bandwidth/disk scoring, and cascade filters that cut probe budgets by 91%.

---

### Peer latency, and two kinds of constrained node

To pressure the weakest nodes, how well does cheap passive metadata find them? Latency is the
cheapest: every handshake records `connect_ms` (TCP round-trip) at full coverage, and the prober
also times a ping/pong round trip (Core's min-ping). Measured from a single EU vantage, latency tracks
the hosting/residential divide: datacenter (PeeringDB "Content") nodes answer in 83 ms and serve 35
Mbps, residential (Cable/DSL/ISP) 265 ms and 11 Mbps; by OS, Linux 168 ms vs the device class 256 ms.
But most of that is distance, not node capability. Controlling for geography (same-country
comparison), the ~182 ms latency gap shrinks to about 20 ms and the 3.2x throughput gap to roughly
1.2-1.8x — a real residual difference, but a fraction of the headline. The reason latency and
throughput "look like the same axis seen twice" is itself the confound: the throughput probe times a
single ~1-2 MB block, which over a long RTT barely escapes TCP slow-start (the congestion window
doubles once per RTT), so for such a short transfer the throughput is roughly inversely proportional
to RTT — the same link looks several-fold slower over a long path than a short one, independent of the
access link's real capacity. So the throughput figure is substantially latency in a bandwidth costume. For a fixed-vantage attacker, "slow from here" is still the operative targeting
signal (a far node genuinely is slower to reach and overwhelm from one point); but as a claim about a
node's *resources* it is mostly geography. Neither axis, measured from one vantage, is a clean
capability signal — separating capability from distance needs a handful of distributed vantages and a
per-node best (min-RTT, and a BDP-filling multi-stream transfer rather than one short block).

![latency by AS class](../results/figures/latency_by_asclass.svg)

Profiling per dimension before merging caught one signal pointing the other way: pruned nodes are
faster (170 ms / 17 Mbps vs 207 ms / 14 Mbps overall), and pruning is in fact more common on
hosting/datacenter nodes (30%) than residential (16%), because operators prune to save disk on cheap,
well-connected VPS hosts, not constrained home machines. Pruning is a disk constraint, orthogonal to
the bandwidth constraint the other signals capture — and, being a protocol-declared flag, the one
axis that is location-independent, so it survives the single-vantage caveat above. We score two axes: a bandwidth
axis (residential AS, appliance user agent, Knots, embedded OS, slow latency) and a disk axis (the
pruned flag).

![disk vs bandwidth axis](../results/figures/axis_split.svg)

### Targeting the bandwidth axis

With pruned dropped, the bandwidth sub-score predicts throughput sharply: ranking by it alone, no
block probing, gives a 4.6-fold spread across bandwidth scores. As a targeting rule, a score of one
or more catches 89% of the bottom-quartile-slow nodes at 41% precision; two or more reaches 64%
precision (44% recall).

![bandwidth score gradient](../results/figures/targeting_bw_gradient.svg)

A naive adversary block-downloads from every node that will
serve a block (3,992, about half of reachable) to find the slow quarter. An adversary that filters
the free signals first does less work. Residential AS
(offline from the IP) then slow TCP latency (one handshake, no download) cut the probe budget 91%,
from 3,992 to 377. Latency as the second filter raises precision; the block probe confirms.

![bandwidth cascade](../results/figures/targeting_cascade.svg)

The disk axis needs no probe: the pruned flag is self-declared in the handshake, so the 1,981
limited-disk nodes (the natural target of a historic-block or disk-pressure attack) are enumerable
for free.

The strongest leaks on both axes cannot be removed. The pruned flag is protocol-mandatory: a pruned
node must advertise `NETWORK_LIMITED` so peers do not ask it for old blocks. The residential AS
and its latency are the node's location. Removable signals (appliance string, Knots banner)
barely move targetability, because network class and latency already do the ranking. Hiding the user
agent does not change the bandwidth or disk scoring. Roughly half of nodes refuse to serve a block
to a stranger.

---

[Back to main report](../REPORT.md)
