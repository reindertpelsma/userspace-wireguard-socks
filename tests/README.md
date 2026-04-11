<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# Security And Malicious Tests

This directory contains adversarial tests and soak-test harnesses. The goal is
not to prove the program is perfectly safe; it is to keep the sharpest failure
modes visible and repeatable.

## Threat Model

The invariants below should stay true even when proxy clients, WireGuard peers,
DNS clients, and API callers are malicious:

- Proxy clients must not get remote code execution.
- WireGuard peers must not reach host loopback unless a host-forward option
  explicitly enables that path.
- ACLs, `AllowedIPs`, and `Address=` subnet routing must not be bypassed.
- Malformed WireGuard, IP, TCP, UDP, ICMP, SOCKS, HTTP, config, ACL, or DNS input
  must not panic the process or allocate unbounded memory.
- The management API must not expose private or preshared key material, and
  mutation endpoints must require authentication when configured.
- DNS must not silently fall back to the system resolver when WireGuard `DNS=`
  is configured for tunnel resolution.

## Test Classes

- `tests/malicious`: black-box malicious-client and fuzz seed tests that run
  with the normal `go test ./...` suite. This includes a raw TCP mean tester
  for malformed SACK options, out-of-window RST/data pressure, and many-flow
  receive-window stress.
- `tests/soak`: long-running stress harnesses. These are skipped unless an
  explicit environment variable enables them. One soak path inserts a rootless
  UDP impairment proxy between two WireGuard instances to simulate jitter,
  latency spikes, variable packet loss, and tail-drop queue pressure.

Run the default malicious suite:

```bash
go test ./tests/malicious
```

Run fuzzing for one target:

```bash
go test ./tests/malicious -run '^$' -fuzz FuzzSOCKSBlackBox -fuzztime 30s
```

Run all default tests plus the race detector:

```bash
go test ./...
go test -race ./internal/engine ./internal/netstackex ./internal/wgbind ./tests/malicious
```

Run the short local soak smoke test:

```bash
UWGS_SOAK=1 UWGS_SOAK_SECONDS=10 go test ./tests/soak -run TestLoopbackImpairedChattySOCKSSoak -count=1
```
