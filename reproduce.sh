#!/bin/bash
# Regenerate every analysis output from the SHIPPED data/ snapshots — no live node.
# (To re-COLLECT a fresh census from a live node instead, see src/run_census.sh.)
#
# Produces: results/*.txt, results/*.json, results/figures/*.svg, docs/ANALYSIS.md
# Animated GIFs (optional, needs Pillow):
#   nix-shell -p python3Packages.pillow dejavu_fonts --run "python3 src/make_anim.py"
#
# ONE live-only exception: tier1.py section 3 (the LinkingLion inbound-peer
# detector) needs a snapshot only your own node can produce. To include it:
#   bitcoin-cli getpeerinfo > data/peers.json
# Without that file, sections 1-2 and the census-side checks still regenerate.
set -euo pipefail
export PYTHONPATH=src
for s in version_resolution exposure_map low_resource_targeting latency_profile \
         census_snapshot make_plots tier1; do
    echo "== $s =="
    python3 "src/$s.py" >/dev/null
done
echo "== verify_numbers =="
python3 src/verify_numbers.py   # recompute every headline number from data/; fails on any drift
echo "done — outputs in results/ (all from data/, no live node)"
