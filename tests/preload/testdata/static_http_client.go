// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC
//
// Phase 2 validation target — a CGO_ENABLED=0 static binary that
// connects to a tunnel TCP address and echoes a sentinel string.
// Drives the static-blob ptrace injection end-to-end:
//
//   1. uwgwrapper spawns this binary with PTRACE_TRACEME.
//   2. Supervisor injects uwgpreload-static at the post-execve stop.
//   3. uwg_static_init installs the SIGSYS handler + seccomp filter.
//   4. Supervisor PTRACE_DETACH; this binary runs at full speed.
//   5. The connect() below traps via SIGSYS, the in-process handler
//      dispatches to uwg_connect, fdproxy round-trip, dup3.
//   6. Read/write flow through the tunnel.
//
// Build: CGO_ENABLED=0 go build -o static_http_client static_http_client.go

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: static_http_client <ip> <port> <message>")
		os.Exit(2)
	}
	addr := net.JoinHostPort(os.Args[1], os.Args[2])
	msg := os.Args[3]

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte(msg)); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(buf))
}
