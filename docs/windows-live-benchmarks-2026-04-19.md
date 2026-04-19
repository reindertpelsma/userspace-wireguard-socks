# Windows Live Validation 2026-04-19

This note records the live Windows validation run performed against the
Droplet at `161.35.159.61`.

## Test Matrix

- Droplet: Linux amd64, `uwgsocks` server
- Windows AMD64 VM: SSH `-p 50223`
- Windows ARM64 VM: SSH `-p 50222`

## What Was Verified

- Local Linux full suite: `go test ./... -count=1`
- Windows non-wrapper package set passed on both Windows VMs:
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

`cmd/uwgwrapper`, `internal/uwgtrace`, `internal/uwgshared`, and
`tests/preload` were intentionally excluded from the Windows pass because they
are part of the Linux/Android wrapper stack.

## Live Tunnel Result

Raw UDP WireGuard reached the droplet and the server received handshake
initiations, but the Windows VMs did not complete the return path in this live
environment. To keep the live validation focused on supported fallback modes,
the benchmark used the pluggable TCP base transport instead.

The successful topology was:

- Droplet server: TCP base transport listener on `161.35.159.61:51832`
- Windows client: local forward `127.0.0.1:5201 -> 100.77.0.1:5201`
- Droplet host: `iperf3 -s -1`
- Windows host: `iperf3 -c 127.0.0.1 -p 5201 -t 5`

## Benchmarks

- Windows AMD64 over TCP transport:
  - sender: `23.2 Mbit/s`
  - receiver: `21.1 Mbit/s`
- Windows ARM64 over TCP transport:
  - sender: `27.2 Mbit/s`
  - receiver: `24.7 Mbit/s`

## Notes

- `uwgsocks.exe` built successfully on both Windows VMs with Go `1.25.0`.
- `iperf3` was installed on both Windows VMs via `winget` package
  `ar51an.iPerf3`.
- The Windows live run confirms that `uwgsocks` works there for the
  non-wrapper surface and that the TCP transport fallback is viable in a
  restrictive environment.
