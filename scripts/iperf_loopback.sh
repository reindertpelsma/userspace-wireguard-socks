#!/usr/bin/env bash
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC

set -euo pipefail

if ! command -v iperf3 >/dev/null 2>&1; then
  echo "iperf3 is required. On Debian/Ubuntu: sudo apt-get install iperf3" >&2
  exit 1
fi

if [[ ! -x ./uwgsocks ]]; then
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o uwgsocks ./cmd/uwgsocks
fi

tmp=$(mktemp -d)
server_pid=
client_pid=
iperf_pid=

cleanup() {
  set +e
  [[ -n "${server_pid:-}" ]] && kill "$server_pid" 2>/dev/null
  [[ -n "${client_pid:-}" ]] && kill "$client_pid" 2>/dev/null
  [[ -n "${iperf_pid:-}" ]] && kill "$iperf_pid" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$tmp"
}
trap cleanup EXIT

pick_port() {
  local p
  while :; do
    p=$(shuf -i 20000-60000 -n 1)
    if ! timeout 0.2 bash -c "</dev/tcp/127.0.0.1/$p" >/dev/null 2>&1; then
      echo "$p"
      return
    fi
  done
}

wg_port=$(pick_port)
local_port=$(pick_port)
tunnel_port=$(pick_port)
iperf_port=$(pick_port)

cat >"$tmp/server.conf" <<EOF
[Interface]
PrivateKey = 6C5zTlphKSL78OljtvARK9l+eHwHDihJzg88+6FxP1c=
Address = 100.64.90.1/32
ListenPort = $wg_port
MTU = 1420

[Peer]
PublicKey = ttwv7S4mBYUYVSXxToftw/119thxaoVmtEnjdaAWtzs=
AllowedIPs = 100.64.90.2/32
EOF

cat >"$tmp/client.conf" <<EOF
[Interface]
PrivateKey = SIcaKz9M+RGqA6MVnzbQsU9uvoyr1iBULxsdxyFQU3s=
Address = 100.64.90.2/32
MTU = 1420

[Peer]
PublicKey = QyKFXQYSiIBEP//EMBNonpi2PwHtp2c4dPwRWZt5RFI=
Endpoint = 127.0.0.1:$wg_port
AllowedIPs = 100.64.90.99/32
PersistentKeepalive = 1
EOF

cat >"$tmp/server.yaml" <<EOF
wireguard:
  config_file: $tmp/server.conf
reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:$tunnel_port
    target: 127.0.0.1:$iperf_port
  - proto: udp
    listen: 100.64.90.99:$tunnel_port
    target: 127.0.0.1:$iperf_port
acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
EOF

cat >"$tmp/client.yaml" <<EOF
wireguard:
  config_file: $tmp/client.conf
forwards:
  - proto: tcp
    listen: 127.0.0.1:$local_port
    target: 100.64.90.99:$tunnel_port
  - proto: udp
    listen: 127.0.0.1:$local_port
    target: 100.64.90.99:$tunnel_port
acl:
  inbound_default: allow
  outbound_default: allow
  relay_default: deny
EOF

./uwgsocks --config "$tmp/server.yaml" >"$tmp/server.log" 2>&1 &
server_pid=$!
./uwgsocks --config "$tmp/client.yaml" >"$tmp/client.log" 2>&1 &
client_pid=$!
sleep 1
kill -0 "$server_pid"
kill -0 "$client_pid"

iperf3 -s -B 127.0.0.1 -p "$iperf_port" -1 >"$tmp/iperf-server-tcp.log" 2>&1 &
iperf_pid=$!
sleep 0.4
iperf3 -c 127.0.0.1 -p "$local_port" -t "${TCP_SECONDS:-3}" --json >"$tmp/tcp.json"
wait "$iperf_pid"
iperf_pid=

iperf3 -s -B 127.0.0.1 -p "$iperf_port" -1 >"$tmp/iperf-server-udp.log" 2>&1 &
iperf_pid=$!
sleep 0.4
iperf3 -u -b "${UDP_RATE:-20M}" -c 127.0.0.1 -p "$local_port" -t "${UDP_SECONDS:-3}" --json >"$tmp/udp.json"
wait "$iperf_pid"
iperf_pid=

python3 - <<PY
import json
tcp = json.load(open("$tmp/tcp.json"))
udp = json.load(open("$tmp/udp.json"))
sent = tcp["end"]["sum_sent"]
recv = tcp["end"]["sum_received"]
usum = udp["end"]["sum"]
print("ports: wg=$wg_port local=$local_port tunnel=$tunnel_port iperf=$iperf_port")
print(f"tcp: sent={sent['bytes']} bytes {sent['bits_per_second']:.2f} bps retransmits={sent.get('retransmits')}")
print(f"tcp: recv={recv['bytes']} bytes {recv['bits_per_second']:.2f} bps")
print(f"udp: bytes={usum['bytes']} {usum['bits_per_second']:.2f} bps lost={usum.get('lost_packets')} total={usum.get('packets')} lost_percent={usum.get('lost_percent')}")
PY
