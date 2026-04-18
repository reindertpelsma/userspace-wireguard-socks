<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Live Matrix Validation 2026-04-18

This note captures a real multi-host validation pass that exercised the same
tree across four very different environments:

- `droplet`: amd64 Linux VPS in Amsterdam, public IP `161.35.159.61`
- `phone`: arm64 Android Termux in Erichem
- `rpi`: arm64 Ubuntu container on a Raspberry Pi in Delft
- `gvisor`: sandboxed container on a laptop in Erichem

The goals were:

- run the automated test suite on every environment
- verify the shared hub topology to the droplet
- verify one direct peer path (`gvisor -> phone`)
- measure real `iperf3` throughput over the live mesh
- verify WireGuard-over-TURN reachability through the droplet

## Test Suite

Results for `go test ./... -count=1`:

- local amd64: pass
- phone arm64 Termux: pass with `GOFLAGS="-ldflags=-checklinkname=0"`
- rpi arm64 container: pass
- gVisor sandbox: pass

The Termux flag is currently required because one dependency still uses a
linkname pattern that newer Go toolchains reject by default on that target.

## Live Topology

Validated topology:

- `phone -> droplet`
- `rpi -> droplet`
- `gvisor -> droplet`
- `gvisor -> phone` direct peer path

The direct peer path was validated with an HTTP fetch over WireGuard:

```bash
curl -x http://127.0.0.1:28080 http://100.78.0.1:5201/
```

That returned the expected response from the phone-hosted service.

## iperf3 Benchmarks

All numbers below are from live runs through `uwgsocks`/`uwgwrapper`, reported
as application-level throughput from `iperf3 -J`.

| Path | Mode | Direction | Sent Mbps | Received Mbps | Notes |
| --- | --- | --- | ---: | ---: | --- |
| phone -> droplet | preload | forward | 218.02 | 180.12 | reverse-forward to droplet-hosted server |
| phone -> droplet | preload | reverse | 118.76 | 77.04 | `iperf3 -R` |
| phone -> droplet | ptrace-seccomp | forward | 1.39 | 1.39 | functional but much slower |
| phone -> droplet | ptrace-seccomp | reverse | 53.88 | 0.52 | asymmetric, still not healthy enough |
| gvisor -> droplet | preload | forward | 264.38 | 227.89 | best result of this pass |
| gvisor -> droplet | preload | reverse | 153.75 | 115.86 | `iperf3 -R` |
| rpi -> droplet | preload | forward | 138.37 | 89.11 | stable |
| rpi -> droplet | preload | reverse | 121.90 | 79.68 | `iperf3 -R` |

Unsuccessful or environment-limited runs:

- `gvisor -> droplet` with `ptrace-seccomp` failed immediately with
  `function not implemented`
- `rpi -> droplet` with `ptrace-seccomp` did not finish cleanly in this pass
- direct `gvisor -> phone` `iperf3` is still less stable than simple HTTP and
  needs more live debugging even though the peer path itself is up

## Observations

- Preload mode is currently the practical high-throughput path in restricted
  environments.
- The `pselect6` emulation fix in the ptrace tracer was necessary for `iperf3`
  to make progress at all in ptrace mode.
- gVisor remains the harshest environment. Plain traffic works, but some
  ptrace-related kernel features are unavailable there by design.
- Termux/Android is surprisingly viable once the preload library and arm64
  tracer are built natively on-device.

## TURN Relay Validation

A separate isolated three-node WireGuard mesh was then brought up with the
droplet acting only as a TURN server. Each remote node used a fixed TURN relay
port and a local reverse forward:

- phone: `100.79.0.1:5301`
- rpi: `100.79.0.2:5301`
- gvisor: `100.79.0.3:5301`

TURN server setup:

- listener: UDP `0.0.0.0:34780`
- mapped relay ports: `41001`, `41002`, `41003`
- all three users marked `internal_only: true`

Important validation points:

- the droplet bound only the TURN service port `34780`
- the `internal_only` relay ports `41001-41003` were not bound on the host
- `gvisor -> phone` over TURN returned `phone-turn-ok`
- `rpi -> phone` over TURN returned `phone-turn-ok`
- `phone -> gvisor` over TURN returned `gvisor-turn-ok`
- `gvisor -> rpi` and `phone -> rpi` over TURN returned `rpi-turn-ok`
- all three nodes reported successful WireGuard handshakes through the TURN
  relay endpoints on `161.35.159.61:41001-41003`

This live TURN pass exposed one transport bug: outbound WireGuard handshakes
were incorrectly trying to `Dial()` the TURN transport even though TURN is a
listen/allocation-based transport. The fix was to add a lightweight outbound
write session on top of the existing TURN allocation so the bind layer can send
initial handshake packets through the already-open relay.

## Artifacts

JSON outputs from the live `iperf3` runs were saved during the validation pass
under `/tmp/*-droplet*.json` on the coordinating host.
