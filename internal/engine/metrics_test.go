// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestMetricsEndpointStartsAndExposesCoreSeries verifies the four things an
// operator actually cares about for a brand-new metrics surface:
//   1. The listener comes up when configured, stays absent when not.
//   2. /metrics returns 200 with the expected Prometheus content type.
//   3. Standard collectors (Go runtime, process, build_info) are present.
//   4. At least one uwgsocks-specific series is present.
//
// We intentionally don't load-test or fuzz this — the user's call. Real
// operational validation comes from running it.
func TestMetricsEndpointStartsAndExposesCoreSeries(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.80.1/32"}
	cfg.Metrics.Listen = "127.0.0.1:0"
	eng := mustStart(t, cfg)
	defer eng.Close()

	addr := eng.Addr("metrics")
	if addr == "" {
		t.Fatal("metrics listener did not register an address")
	}

	body := scrapeMetrics(t, "http://"+addr+"/metrics", "")
	for _, want := range []string{
		"go_goroutines",                              // Go runtime collector
		"process_resident_memory_bytes",              // process collector
		"uwgsocks_build_info",                        // build info gauge
		"uwgsocks_peers ",                            // engine-derived gauge (trailing space pins exact name)
		"uwgsocks_bytes_received_total",              // device-derived counter
		"uwgsocks_mesh_requests_total",               // hot-path counter
		"uwgsocks_socks_connections_capped_total",    // hot-path counter
		"uwgsocks_conntrack_refusals_total",          // hot-path counter
		"uwgsocks_roaming_endpoint_changes_total",    // poller-driven counter
		"uwgsocks_turn_carrier_drops_total",          // package-level counter
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape body missing %q", want)
		}
	}
}

func TestMetricsEndpointDisabledWhenListenEmpty(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.80.2/32"}
	// metrics.listen left empty
	eng := mustStart(t, cfg)
	defer eng.Close()

	if addr := eng.Addr("metrics"); addr != "" {
		t.Fatalf("metrics listener should not be registered when metrics.listen is empty, got %q", addr)
	}
}

func TestMetricsEndpointEnforcesBearerTokenWhenSet(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.80.3/32"}
	cfg.Metrics.Listen = "127.0.0.1:0"
	cfg.Metrics.Token = "metrics-secret"
	eng := mustStart(t, cfg)
	defer eng.Close()

	url := "http://" + eng.Addr("metrics") + "/metrics"

	// Without a bearer header, the endpoint must reject.
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("unauth GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth GET status = %d, want 401", resp.StatusCode)
	}

	// Wrong token: still rejected.
	body := scrapeMetricsExpectStatus(t, url, "wrong-token", http.StatusUnauthorized)
	if body == "" { /* no-op */
	}

	// Correct token: 200 + body.
	body = scrapeMetrics(t, url, "metrics-secret")
	if !strings.Contains(body, "uwgsocks_build_info") {
		t.Fatalf("authenticated scrape missing uwgsocks_build_info: %s", body[:min(200, len(body))])
	}
}

func TestMetricsCounterReflectsHotPathIncrement(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.80.4/32"}
	// Mesh control listener inside the netstack — we don't need to hit
	// it, we only need its rate-limiter middleware live so we can
	// drive the counter from a unit-level path.
	cfg.MeshControl.Listen = "100.64.80.4:9999"
	cfg.Metrics.Listen = "127.0.0.1:0"
	eng := mustStart(t, cfg)
	defer eng.Close()

	// Drive the rate limiter directly via an in-process call to its
	// constructor — this is allowed because the test is in the engine
	// package's _test partner. We pick an arbitrary remote IP and hit
	// the limiter past its burst budget so the rate_limited counter
	// increments.
	for i := 0; i < 30; i++ {
		engine.RecordMeshRateLimitTestEvent(eng, "10.0.0.1:1234")
	}

	url := "http://" + eng.Addr("metrics") + "/metrics"
	body := scrapeMetrics(t, url, "")
	if !strings.Contains(body, `uwgsocks_mesh_requests_total{result="rate_limited"}`) {
		t.Fatalf("rate_limited series not present in scrape:\n%s", excerpt(body, "uwgsocks_mesh_requests_total"))
	}
}

func scrapeMetrics(t *testing.T, url, token string) string {
	t.Helper()
	return scrapeMetricsExpectStatus(t, url, token, http.StatusOK)
}

func scrapeMetricsExpectStatus(t *testing.T, url, token string, want int) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("scrape %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read scrape body: %v", err)
	}
	if resp.StatusCode != want {
		t.Fatalf("scrape status = %d, want %d, body=%s", resp.StatusCode, want, body)
	}
	return string(body)
}

// excerpt returns a few lines around the first occurrence of needle. Keeps
// failure output readable instead of dumping a 30 KiB Prometheus payload.
func excerpt(body, needle string) string {
	idx := strings.Index(body, needle)
	if idx < 0 {
		return body[:min(500, len(body))]
	}
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + 500
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
