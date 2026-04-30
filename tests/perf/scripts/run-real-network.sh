#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC
#
# Run the perf baseline across two real hosts over the public
# internet — one runs the WireGuard "server" half, the other the
# "client" half, and we measure end-to-end TCP throughput + latency.
#
# Topology (default):
#
#     ssh ${LEFT}  ── public internet ──  ssh ${RIGHT}
#       │                                   │
#       └── uwgsocks server peer            └── uwgsocks client peer
#                                              + iperf3 client
#                                              against tunnel addr
#
# Both hosts must:
#   - be reachable via SSH from the operator machine running this script
#   - have Go 1.25+ on PATH (or a fallback at /usr/local/go/bin/go)
#   - have iperf3 installed (apt-get install -y iperf3 / brew install iperf3)
#
# Usage:
#   LEFT=root@<amd64-host> RIGHT=root@<arm64-host> \
#     bash tests/perf/scripts/run-real-network.sh

set -euo pipefail

LEFT="${LEFT:?set LEFT to ssh-target for the WG server side}"
RIGHT="${RIGHT:?set RIGHT to ssh-target for the WG client side}"
DURATION="${DURATION:-30}"   # iperf3 test duration in seconds

echo "left:  $LEFT"
echo "right: $RIGHT"

remote_go() {
    local host=$1; shift
    ssh -o StrictHostKeyChecking=no "$host" "export PATH=/usr/local/go/bin:\$PATH; $*"
}

probe() {
    local host=$1
    echo "=== probing $host ==="
    remote_go "$host" 'uname -m && go version 2>&1 | head -1 && which iperf3 || echo "NO_IPERF3"'
}

probe "$LEFT"
probe "$RIGHT"

cat <<EOF

The full real-network harness has the following moving parts:

  1. clone/sync the repo on $LEFT and $RIGHT.
  2. build uwgsocks on each.
  3. configure peer A on $LEFT, peer B on $RIGHT, with $LEFT's public IP
     as the WG endpoint.
  4. start uwgsocks on each, wait for handshake.
  5. start iperf3 -s on $RIGHT (bound to its tunnel address).
  6. run iperf3 -c <right-tun-ip> -t \$DURATION on \$LEFT.
  7. tear down.

This script will fully implement the above as soon as the v1.0
deployment story (cosign-signed binaries pulled from a release URL)
is finalised — until then, the loopback baseline (run-loopback.sh)
is what release.yml exercises, and real-network runs are operator-
manual using this script as a starting point.

For now, here's what an operator would copy-paste:

  # Build on each side:
  ssh \$LEFT  "cd /tmp && rm -rf uwgsocks && git clone https://github.com/reindertpelsma/userspace-wireguard-socks.git uwgsocks && cd uwgsocks && /usr/local/go/bin/go build -o uwgsocks ./cmd/uwgsocks"
  ssh \$RIGHT "cd /tmp && rm -rf uwgsocks && git clone https://github.com/reindertpelsma/userspace-wireguard-socks.git uwgsocks && cd uwgsocks && /usr/local/go/bin/go build -o uwgsocks ./cmd/uwgsocks"

  # Generate keys, write configs (left side as listener):
  PRIVA=\$(wg genkey)
  PUBA=\$(echo "\$PRIVA" | wg pubkey)
  PRIVB=\$(wg genkey)
  PUBB=\$(echo "\$PRIVB" | wg pubkey)

  cat > /tmp/uwgs-left.yaml <<YAML
  wireguard:
    private_key: "\$PRIVA"
    listen_port: 51820
    addresses: ["100.64.200.1/32"]
    peers:
      - public_key: "\$PUBB"
        allowed_ips: ["100.64.200.2/32"]
  YAML

  cat > /tmp/uwgs-right.yaml <<YAML
  wireguard:
    private_key: "\$PRIVB"
    addresses: ["100.64.200.2/32"]
    peers:
      - public_key: "\$PUBA"
        endpoint: "<LEFT-public-ip>:51820"
        allowed_ips: ["100.64.200.1/32"]
        persistent_keepalive: 25
  YAML

  # Bring both up, then run iperf3 across the tunnel.
EOF

echo
echo "TODO: full automation tracked as M5 follow-up."
echo "      For now, use loopback baseline + the manual recipe above."
