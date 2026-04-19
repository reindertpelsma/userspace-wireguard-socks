# macOS arm64 Live Validation 2026-04-19

This note records a live `uwgsocks` validation run against an Apple Silicon
Mac mini reachable at:

- IPv4: `51.159.120.52`
- IPv6: `2001:bc8:a01:1:1698:77ff:fe30:890e`

The coordinating host was the Linux droplet at:

- IPv4: `161.35.159.61`
- IPv6: `2a03:b0c0:2:f0:0:1:8888:1001`

## Scope

- Build `uwgsocks` on macOS arm64
- Run the non-wrapper `uwgsocks` package set on macOS
- Bring up a live `uwgsocks` tunnel from the droplet to the Mac over:
  - outer IPv4
  - outer IPv6
- Verify:
  - direct tunnel reachability to a Mac-hosted service
  - tunneled IPv4 Internet egress through the Mac
  - tunneled IPv6 Internet egress through the Mac
  - HTTPS proxying through the Mac
  - `iperf3` throughput over both outer paths

`uwgwrapper` was intentionally not part of the macOS target itself.

## Build And Test

The Mac was provisioned with Go `1.25.0` and built successfully as
`darwin/arm64`.

Validated package set on the Mac:

- `.`
- `./cmd/uwgsocks`
- `./internal`
- `./internal/acl`
- `./internal/config`
- `./internal/engine`
- `./internal/netstackex`
- `./internal/socketproto`
- `./internal/transport`
- `./internal/wgbind`
- `./tests`
- `./tests/malicious`
- `./tests/soak`

The only macOS-specific fix needed during this pass was shortening one Unix
socket path in `internal/engine/integration_test.go`, because Darwin rejects
longer temporary socket paths earlier than Linux does.

## Live Topology

The Mac ran:

- `uwgsocks` server on UDP port `51821`, bound on both IPv4 and IPv6
- transparent inbound enabled
- reverse-forwarded HTTP test service:
  - tunnel `100.79.10.99:18080 -> 127.0.0.1:18080`
- reverse-forwarded `iperf3` test service:
  - tunnel `100.79.10.99:5201 -> 127.0.0.1:5201`

The droplet ran:

- `uwgsocks` client with:
  - outer endpoint set to either the Mac IPv4 or Mac IPv6 address
  - dual-stack inside the tunnel:
    - `100.79.10.2/32`
    - `fd42:79:10::2/128`
  - local host forwards:
    - `127.0.0.1:18080 -> 100.79.10.99:18080`
    - `127.0.0.1:15201 -> 100.79.10.99:5201`
    - `127.0.0.1:14443 -> 104.26.13.205:443`
    - `127.0.0.1:16443 -> [2607:f2d8:1:3c::3]:443`
  - local HTTP proxy:
    - IPv4 outer run: `127.0.0.1:28082`
    - IPv6 outer run: `127.0.0.1:28083`

The extra ULA pair was necessary for the inner IPv6 tests. Outer IPv6
connectivity alone is not enough if the tunnel itself has no IPv6 source
address.

## Results

### Outer IPv4

- Handshake completed from droplet to `51.159.120.52:51821`
- Direct tunnel HTTP fetch to the Mac test service passed
- Tunneled IPv4 egress passed:
  - `curl --resolve api.ipify.org:14443:127.0.0.1 https://api.ipify.org:14443`
  - result: `51.159.120.52`
- Tunneled IPv6 egress passed:
  - `curl --resolve api64.ipify.org:16443:127.0.0.1 https://api64.ipify.org:16443`
  - result: `2001:bc8:a01:1:1698:77ff:fe30:890e`
- HTTPS proxying through the Mac passed:
  - `curl -I -x http://127.0.0.1:28082 https://www.google.com`
  - result: HTTP `200`
- `iperf3` over the tunnel-side forward passed:
  - sender: `235.48 Mbit/s`
  - receiver: `228.93 Mbit/s`

### Outer IPv6

- Handshake completed from droplet to `[2001:bc8:a01:1:1698:77ff:fe30:890e]:51821`
- Direct tunnel HTTP fetch to the Mac test service passed
- Tunneled IPv4 egress passed:
  - result: `51.159.120.52`
- Tunneled IPv6 egress passed:
  - result: `2001:bc8:a01:1:1698:77ff:fe30:890e`
- HTTPS proxying through the Mac passed:
  - `curl -I -x http://127.0.0.1:28083 https://www.google.com`
  - result: HTTP `200`
- `iperf3` over the tunnel-side forward passed:
  - sender: `282.57 Mbit/s`
  - receiver: `272.73 Mbit/s`

## Notes

- The Mac-side `iperf3` binary was built from the upstream `3.18` source tree
  and installed under `$HOME/.local/bin/iperf3`.
- An initial attempt to force tunneled IPv6 without assigning tunnel IPv6
  addresses failed exactly as expected; after adding the ULA pair, the inner
  IPv6 tests passed cleanly.
- `speedtest-cli` over the droplet-side HTTP proxy still did not complete its
  auto-discovery and latency phase during this pass. The rest of the data plane
  checks were successful, including dual-stack egress and HTTPS proxying, so
  the remaining issue appears specific to `speedtest-cli` in that proxy mode
  rather than a general tunnel failure.
