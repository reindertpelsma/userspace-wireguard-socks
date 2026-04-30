//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
)

// TestChromiumRealInternetSmoke runs headless Chromium against real
// public URLs through a uwgsocks-hosted HTTP proxy. Validates the
// full real-internet outbound path:
//   - uwgsocks's `proxy.http` listener
//   - DNS resolution for real-internet hostnames (example.com,
//     api.github.com)
//   - HTTPS CONNECT through the proxy
//   - TLS handshake to the origin
//   - Chromium fully renders the DOM (which requires a working JS
//     engine; Chromium can't produce a useful --dump-dom without it)
//
// Skipped by default; set UWGS_RUN_CHROMIUM_REAL_INTERNET=1 to run.
// Picks up `UWGS_CHROME_BIN` if set, otherwise auto-detects chromium /
// chromium-browser / google-chrome / headless_shell on PATH.
//
// This test deliberately uses real-internet endpoints with stable
// content. example.com is IANA-managed and reliably returns the
// "Example Domain" title; api.github.com/zen returns a non-empty
// plain-text quote so we can validate a second, non-HTML hostname.
func TestChromiumRealInternetSmoke(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.ChromiumRealInet {
		t.Skip("set UWGS_RUN_CHROMIUM_REAL_INTERNET=1 or -uwgs-chromium-real-inet to run real-internet chromium smoke")
	}
	chromeBin := tcfg.ChromeBin
	if chromeBin == "" {
		for _, candidate := range []string{
			"chromium", "chromium-browser", "google-chrome", "headless_shell",
		} {
			if path, err := exec.LookPath(candidate); err == nil {
				chromeBin = path
				break
			}
		}
	}
	if chromeBin == "" {
		t.Skip("no chromium binary found")
	}

	// Pick a free TCP port for the proxy listener.
	proxyPort := freeTCPPort(t)

	// Spawn a proxy-only uwgsocks: HTTP listener + fallback_direct so
	// outbound requests go straight to the host's network. No WG peer
	// is configured — we don't need the tunnel for real-internet
	// access, just the proxy + dialer.
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	cfg.Proxy.HTTP = fmt.Sprintf("127.0.0.1:%d", proxyPort)
	_ = mustStart(t, cfg)
	waitTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 5*time.Second)

	for _, tc := range []struct {
		name, url, mustContain string
	}{
		{"example.com", "https://example.com/", "Example Domain"},
		// api.github.com/zen returns a single quote line; chromium
		// wraps it in a <pre>. Just verify the response shape.
		{"api.github.com", "https://api.github.com/zen", "</pre>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			args := []string{
				"--headless",
				"--no-sandbox",
				"--disable-gpu",
				"--disable-features=DBus,VizDisplayCompositor",
				"--disable-software-rasterizer",
				"--disable-dev-shm-usage",
				"--no-zygote",
				"--virtual-time-budget=10000",
				fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", proxyPort),
				"--dump-dom",
				tc.url,
			}
			cmd := exec.CommandContext(ctx, chromeBin, args...)
			out, err := cmd.CombinedOutput()
			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("chromium timed out fetching %s\noutput=%s", tc.url, out)
			}
			if err != nil {
				t.Fatalf("chromium failed fetching %s: %v\noutput=%s", tc.url, err, out)
			}
			if !strings.Contains(string(out), tc.mustContain) {
				t.Fatalf("chromium output for %s did not contain %q\noutput=%s",
					tc.url, tc.mustContain, out)
			}
			t.Logf("%s: OK (%d bytes of DOM)", tc.url, len(out))
		})
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitTCPPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("port %s not listening within %s", addr, timeout)
}
