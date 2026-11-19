#!/bin/bash
# Census automation — run from the repo root.
# Collects fresh census data, resolves ASN+country, runs analysis, regenerates plots.
#
# Cron example (adjust the path to your own checkout):
#   0 3 * * 0 cd /path/to/peer-probe && bash src/run_census.sh >> /tmp/census_cron.log 2>&1
#
# Config via environment (sensible defaults):
#   BITCOIN_CLI       path to bitcoin-cli        (default: bitcoin-cli on PATH)
#   BITCOIN_RPC_ARGS  extra RPC args, e.g. auth  (default: empty -> cookie auth)
set -euo pipefail
DATE=$(date +%Y-%m-%d)
CLI="${BITCOIN_CLI:-bitcoin-cli}"
RPC="${BITCOIN_RPC_ARGS:-}"
export PYTHONPATH=src

echo "=== census run $DATE ==="

# 1. Dump addrman
$CLI $RPC getrawaddrman > data/raw_census.json
echo "addrman dumped"

# 2. Resolve ASN + country
python3 src/resolve_asn.py
echo "ASN resolved"

# 3. Fast census (all networks)
python3 src/harvest.py --rawaddrman data/raw_census.json --sample 0 --ping --headers \
  --concurrency 200 --timeout 4 --out /tmp/census_$DATE

# 4. Block probe on reachable hosts
python3 -c "
import json
ok = [r for r in json.load(open('/tmp/census_${DATE}.json')) if r['ok']]
with open('/tmp/reachable_${DATE}.txt', 'w') as f:
    for r in ok:
        ip = r['ip']
        port = r['port']
        f.write(f'[{ip}]:{port}\n' if ':' in ip else f'{ip}:{port}\n')
print(f'{len(ok)} reachable for block probe')
"
python3 src/harvest.py --targets /tmp/reachable_$DATE.txt --sample 0 --ping --headers \
  --block-hash $(python3 -c "
import subprocess, json
h = json.loads(subprocess.check_output('$CLI $RPC getblockchaininfo', shell=True))['bestblockhash']
print(h)
") --concurrency 50 --timeout 8 --out /tmp/block_$DATE

# 5. Merge Phase 1 + Phase 2
python3 src/merge_block_probe.py /tmp/census_$DATE.json /tmp/block_$DATE.json

# 6. Merge census + OS backfill
python3 src/merge_census.py
python3 src/merge_os_dataset.py

# 7. Run all analysis
python3 src/version_resolution.py
python3 src/exposure_map.py
python3 src/low_resource_targeting.py
python3 src/latency_profile.py
python3 src/census_snapshot.py
python3 src/make_plots.py

echo "=== census $DATE complete ==="
