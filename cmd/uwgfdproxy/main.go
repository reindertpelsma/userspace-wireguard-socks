// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

import (
	"flag"
	"log"
	"os"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
)

func main() {
	var listen, api, token string
	var socketPath string
	flag.StringVar(&listen, "listen", "/tmp/uwgfdproxy.sock", "Unix socket path exposed to the preload wrapper")
	flag.StringVar(&api, "api", getenv("UWGS_API", "http://127.0.0.1:9090"), "uwgsocks API endpoint")
	flag.StringVar(&socketPath, "socket-path", getenv("UWGS_SOCKET_PATH", "/v1/socket"), "upstream socket upgrade path, for example /v1/socket or /uwg/socket")
	flag.StringVar(&token, "token", os.Getenv("UWGS_API_TOKEN"), "uwgsocks API bearer token")
	flag.Parse()

	server, err := fdproxy.ListenWithSocketPath(listen, api, token, socketPath, log.Default())
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	log.Printf("uwgfdproxy listening on %s, upstream %s path %s", listen, api, socketPath)
	if err := server.Serve(); err != nil {
		log.Fatal(err)
	}
}

func getenv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
