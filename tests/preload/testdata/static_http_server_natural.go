// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC
//
// Diagnostic variant of static_http_server WITHOUT explicit os.Exit(0):
// returns from main naturally so we can investigate why Go's natural-
// exit path stalls under preload-static. Used by
// TestPhase2NaturalExitDiag only.

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
		fmt.Fprintln(os.Stderr, "usage: static_http_server_natural <ip> <port> <max-requests>")
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
	time.Sleep(100 * time.Millisecond)
	fmt.Fprintf(os.Stderr, "served=%d (about to fall out of main)\n", served.Load())
	// Falls out of main naturally — defer ln.Close() runs, then
	// runtime.exit. THIS IS THE STALLING PATH.
}
