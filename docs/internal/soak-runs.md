<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Soak run log

Each entry is one full 24-hour soak. Records:
- Date the run started + finished.
- Machine spec (CPU, RAM, kernel).
- Test name + workload.
- RSS / goroutine / FD trajectories (5-min sample interval).
- Pass/fail verdict + any anomalies.

Format goal: an operator should be able to `git log -p
docs/internal/soak-runs.md` and see whether the project is
trending stable, slowly leaking, or got worse with a specific
release.

## How to run

On a stable Linux box (recommended: an idle VPS with ≥ 2 vCPU
and ≥ 4 GB RAM):

```bash
git clone https://github.com/reindertpelsma/userspace-wireguard-socks.git
cd userspace-wireguard-socks

cat > /tmp/uwgs-soak.sh <<'EOF'
#!/bin/bash
set -euo pipefail
cd $(dirname "$0")/userspace-wireguard-socks
export PATH=/usr/local/go/bin:$PATH

stats_loop() {
    local pid=$1 out=/tmp/uwgs-stats.tsv
    echo -e "ts\trss_kb\tvsz_kb\tthreads\tfds\tnet_conns" > "$out"
    while kill -0 "$pid" 2>/dev/null; do
        local ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        local rss vsz threads fds netconns
        rss=$(awk '/^VmRSS:/ {print $2}' /proc/$pid/status 2>/dev/null || echo 0)
        vsz=$(awk '/^VmSize:/ {print $2}' /proc/$pid/status 2>/dev/null || echo 0)
        threads=$(awk '/^Threads:/ {print $2}' /proc/$pid/status 2>/dev/null || echo 0)
        fds=$(ls -1 /proc/$pid/fd 2>/dev/null | wc -l)
        netconns=$(ss -tan state established 2>/dev/null | wc -l)
        echo -e "${ts}\t${rss}\t${vsz}\t${threads}\t${fds}\t${netconns}" >> "$out"
        sleep 300
    done
}

UWGS_SOAK=1 UWGS_SOAK_SECONDS=86400 \
    go test ./tests/soak -run TestLoopbackImpairedChattySOCKSSoak \
    -count=1 -timeout 25h -v &
TEST_PID=$!
sleep 5
ACTUAL_PID=$(pgrep -P $TEST_PID -n soak.test 2>/dev/null || echo $TEST_PID)
stats_loop "$ACTUAL_PID" &
wait "$TEST_PID"
EOF
chmod +x /tmp/uwgs-soak.sh
nohup /tmp/uwgs-soak.sh >/tmp/uwgs-soak.log 2>&1 </dev/null & disown
```

Wait 24 hours, then add the entry below.

## Pass criteria

A soak run "passes" when, over the 24-hour window:

- **RSS** stable after the first hour. Ramp during warm-up is
  expected; sustained growth is not. ≤ 10% drift in the steady
  state is noise; > 30% growth without leveling off is a leak.
- **Threads** stable. Ramp during warm-up is expected; growth
  during steady state is a goroutine leak.
- **FDs** stable. Same.
- **Conntrack table size** reaches a steady state and stops
  growing.
- **Zero `*_drops_total`** counter increments after the first
  30s warm-up (visible in `/metrics` if enabled).
- **Zero panics** in the test log.

## Run log

### 2026-04-28 → 2026-04-29 — first 24h reference baseline

- **Box**: Scaleway VPS at 51.159.237.61. Linux x86_64, 4 vCPU,
  7.7 GB RAM, Go 1.25.0.
- **Test**: `TestLoopbackImpairedChattySOCKSSoak` (24h soak with
  impaired-network chatty SOCKS proxy load).
- **Started**: 2026-04-28T15:26Z (CEST 17:26).
- **Finished**: TBD on the next run-log update.
- **Trajectory** (5-min samples; 8h-in snapshot):
  - RSS warm-up: 45 MB → 60 MB over first 5 min, then stable
    at 62-63 MB through 8h+ in.
  - Threads: 9-10 throughout.
  - FDs: 23 throughout.
  - Net conns: 14-25 oscillating (the test's chatty workload).
- **Verdict**: TBD when the 24h completes. Cron will append.

<!-- Future entries follow this shape: -->
<!--
### YYYY-MM-DD → YYYY-MM-DD — short label

- **Box**: ...
- **Test**: ...
- **Started/Finished**: ...
- **Trajectory**: ...
- **Verdict**: PASS / FAIL with notes.
-->
