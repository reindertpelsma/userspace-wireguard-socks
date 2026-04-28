// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC
//
// Phase 2 stress target — a CGO_ENABLED=0 static binary HTTP server
// that handles many concurrent goroutine-driven connections.
//
// Drives the supervisor's blob injection AND Go-runtime SIGSYS-handler
// protection AND fdproxy listener flow under realistic load:
//   - thousands of goroutines accept and respond
//   - each request involves accept/read/write/close on tunnel fds
//   - the SIGSYS interception path runs at full throttle
//
// Build: CGO_ENABLED=0 go build -tags=netgo,osusergo -ldflags=-extldflags=-static
//
// Usage:  static_http_server <bind-ip> <port> <max-requests>
// The server prints "READY <ip>:<port>\n" once listening, then
// serves up to <max-requests> requests and exits 0. Each response
// echoes the request URL path so the client can verify per-request
// integrity.

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: static_http_server <ip> <port> <max-requests>")
		os.Exit(2)
	}
	ip, port := os.Args[1], os.Args[2]
	maxReq, _ := strconv.Atoi(os.Args[3])
	addr := net.JoinHostPort(ip, port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("READY %s\n", ln.Addr())
	os.Stdout.Sync()

	var served atomic.Int64
	done := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
		if int(served.Add(1)) >= maxReq {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	})
	srv := &http.Server{Handler: mux, ReadTimeout: 30 * time.Second}

	go func() { _ = srv.Serve(ln) }()
	<-done
	// Allow last response to flush.
	time.Sleep(100 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "served=%d\n", served.Load())
	// Explicit os.Exit instead of falling out of main: the deferred
	// ln.Close() only stops the listener, but the Server.Serve
	// goroutine is parked inside our SIGSYS handler's accept4 path
	// (in fdproxy_sock.c uwg_read_line). close(listenerFd) is not
	// trapped, so the preload can't abort that in-flight accept; the
	// fdproxy control read never returns. From Go's runtime view the
	// M is still "running user code" so runtime.exit's bookkeeping
	// can't drain. exit_group(0) directly side-steps both.
	os.Exit(0)
}
