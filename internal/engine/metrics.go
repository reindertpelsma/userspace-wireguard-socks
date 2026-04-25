// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

// metricsState owns the hot-path counters that don't have a natural Prometheus
// home (Counter requires a mutex internally; we want lock-free atomics on the
// data path, then read them at scrape time via CounterFunc collectors).
//
// Every counter here MUST be safe to read with atomic.LoadUint64 from the
// scraper goroutine while a hot-path goroutine concurrently atomic.AddUint64s.
type metricsState struct {
	// Mesh control rate-limited / authenticated request outcomes.
	meshRequestsOK          atomic.Uint64
	meshRequestsRateLimited atomic.Uint64
	meshRequestsAuthFailed  atomic.Uint64

	// (TURN carrier drops live as a package-level atomic in
	// internal/transport — surfaced by metrics CounterFunc — to avoid
	// taking a circular import dependency.)

	// SOCKS5 connection accepted but the global cap was full; the
	// listener silently rejected the connection. Useful to confirm
	// concurrency caps are sized right.
	socksConnectionsCapped atomic.Uint64

	// New relay flows refused because the conntrack table (or per-peer
	// cap) was full. Non-zero = sizing is too small or attacker is
	// floods.
	conntrackRefusals atomic.Uint64

	// Roaming events: peer's chosen outer endpoint changed. Inferred by a
	// periodic poller, not by an event hook, so the count may slightly
	// undercount very fast back-and-forth roaming. Documented.
	roamingEndpointChanges atomic.Uint64

	// Roaming poller state — the last known endpoint per peer pubkey.
	// Guarded by its own mutex, only touched by the poller goroutine and
	// the metricsState constructor; not on any hot path.
	roamMu       sync.Mutex
	lastEndpoint map[string]string
}

func newMetricsState() *metricsState {
	return &metricsState{lastEndpoint: make(map[string]string)}
}

// startMetricsServer brings up the optional Prometheus listener. No-op when
// metrics.listen is empty. Listener is intentionally separate from the admin
// API so the scrape secret can be rotated/distributed independently and so a
// compromised scrape token cannot reach the mutating admin endpoints.
func (e *Engine) startMetricsServer() error {
	addr := e.cfg.Metrics.Listen
	if addr == "" {
		return nil
	}
	if e.metrics == nil {
		e.metrics = newMetricsState()
	}
	reg := e.buildMetricsRegistry()

	ln, err := listenEndpoint(addr)
	if err != nil {
		return fmt.Errorf("metrics listen: %w", err)
	}
	e.addListener("metrics", ln)

	mux := http.NewServeMux()
	mux.Handle("/metrics", e.metricsAuthHandler(promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
		Registry:      reg,
	})))

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		if err := server.Serve(ln); err != nil && !isClosedErr(err) {
			e.log.Printf("metrics listener stopped: %v", err)
		}
	}()
	go e.metrics.runRoamingPoller(e)
	return nil
}

// metricsAuthHandler is a lightweight auth wrapper. If metrics.token is
// empty, requests pass through (the operator declared the listener trusted
// by binding it to loopback or a firewalled address). If set, a constant-
// time bearer-token check is enforced.
func (e *Engine) metricsAuthHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := e.cfg.Metrics.Token
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.Header.Get("Authorization")
		}
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// buildMetricsRegistry constructs a fresh registry per Engine. Using the
// global default registry would leak metrics across test cases and prevent
// running multiple engine instances in the same process.
func (e *Engine) buildMetricsRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	// Standard Go runtime + process collectors. These are what every
	// Prometheus operator expects to see and they're free.
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	// Build info, always 1, with version/sha/etc as labels.
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "uwgsocks_build_info",
		Help: "Build metadata as labels. Always 1.",
	}, []string{"version", "go_version", "lite"})
	buildInfo.WithLabelValues(buildInfoVersion(), buildInfoGoVersion(), buildInfoLite()).Set(1)
	reg.MustRegister(buildInfo)

	ms := e.metrics

	// Hot-path counters via CounterFunc — read the atomic at scrape time.
	reg.MustRegister(newEnumCounterCollector(
		"uwgsocks_mesh_requests_total",
		"Mesh control HTTP requests by outcome.",
		"result",
		map[string]func() float64{
			"ok":           func() float64 { return float64(ms.meshRequestsOK.Load()) },
			"rate_limited": func() float64 { return float64(ms.meshRequestsRateLimited.Load()) },
			"auth_failed":  func() float64 { return float64(ms.meshRequestsAuthFailed.Load()) },
		},
	))

	mustRegisterCounterFunc(reg, "uwgsocks_turn_carrier_drops_total",
		"TURN HTTP/WebSocket carrier datagrams dropped because the read channel was full.",
		nil, nil, func() float64 { return float64(transport.TurnCarrierDropsTotal.Load()) })

	mustRegisterCounterFunc(reg, "uwgsocks_socks_connections_capped_total",
		"SOCKS5 connections rejected because the global concurrent-connection cap was full.",
		nil, nil, func() float64 { return float64(ms.socksConnectionsCapped.Load()) })

	mustRegisterCounterFunc(reg, "uwgsocks_conntrack_refusals_total",
		"New relay flows refused because the conntrack table or per-peer cap was at capacity.",
		nil, nil, func() float64 { return float64(ms.conntrackRefusals.Load()) })

	// ACL drop counters per plane (inbound/outbound/relay) are deferred to
	// a follow-up: the deny paths are scattered across many call sites and
	// instrumenting them all is best done as a focused PR with its own
	// tests, not folded into the metrics-endpoint introduction.

	mustRegisterCounterFunc(reg, "uwgsocks_roaming_endpoint_changes_total",
		"Number of times a peer's chosen outer endpoint changed (inferred by a periodic poller; very fast roaming may undercount).",
		nil, nil, func() float64 { return float64(ms.roamingEndpointChanges.Load()) })

	// Aggregate gauges + counters derived from device state at scrape
	// time. These call into Engine accessors that already exist for
	// /v1/status, so there is no new hot-path read pattern to vet.
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "uwgsocks_peers",
		Help: "Configured WireGuard peers (whether or not they have ever handshaked).",
	}, func() float64 {
		st, err := e.Status()
		if err != nil {
			return 0
		}
		return float64(len(st.Peers))
	}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "uwgsocks_peers_handshaked",
		Help: "Peers that have completed at least one WireGuard handshake in the current process.",
	}, func() float64 {
		st, err := e.Status()
		if err != nil {
			return 0
		}
		var n float64
		for _, p := range st.Peers {
			if p.HasHandshake {
				n++
			}
		}
		return n
	}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "uwgsocks_dynamic_peers",
		Help: "Mesh-discovered dynamic peers currently tracked.",
	}, func() float64 {
		e.dynamicMu.RLock()
		defer e.dynamicMu.RUnlock()
		return float64(len(e.dynamicPeers))
	}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "uwgsocks_active_connections",
		Help: "Transparent-inbound connections in the connection-table guard. Does NOT count SOCKS/HTTP proxy sessions or socket-API sessions.",
	}, func() float64 {
		return float64(e.activeConnectionCount())
	}))
	reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "uwgsocks_relay_conntrack_flows",
		Help: "Active flows in the relay conntrack table.",
	}, func() float64 {
		e.relayMu.Lock()
		defer e.relayMu.Unlock()
		return float64(len(e.relayFlows))
	}))

	// Aggregate bytes / packets / handshake counters derived from the
	// WireGuard device dump. These are CounterFuncs because the device
	// itself owns the underlying counters.
	reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "uwgsocks_bytes_received_total",
		Help: "Bytes received over WireGuard summed across all peers.",
	}, func() float64 {
		st, err := e.Status()
		if err != nil {
			return 0
		}
		var n float64
		for _, p := range st.Peers {
			n += float64(p.ReceiveBytes)
		}
		return n
	}))
	reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "uwgsocks_bytes_transmitted_total",
		Help: "Bytes transmitted over WireGuard summed across all peers.",
	}, func() float64 {
		st, err := e.Status()
		if err != nil {
			return 0
		}
		var n float64
		for _, p := range st.Peers {
			n += float64(p.TransmitBytes)
		}
		return n
	}))

	// TCP retransmits from gVisor netstack — operationally a strong
	// signal of upstream packet loss. Surfaced as a counter; let PromQL
	// rate() it. Falls back silently if netstack stats are unavailable.
	if e.net != nil {
		reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{
			Name: "uwgsocks_tcp_retransmits_total",
			Help: "TCP segments retransmitted by the userspace gVisor netstack (sum across all flows).",
		}, func() float64 {
			return float64(netstackTCPRetransmits(e))
		}))
	}

	// Per-peer detail (bytes + last_handshake) is opt-in because it
	// scales with peer count. Capped at MaxPerPeer; over the cap the
	// rest aggregate into peer="_overflow".
	if e.cfg.Metrics.PerPeerDetail {
		registerPerPeerCollector(reg, e)
	}

	return reg
}

// runRoamingPoller observes outer endpoint changes per peer. We do this
// out-of-band rather than instrumenting every transport's endpoint
// resolution path, because the latter would require touching every
// transport and is the kind of cross-cutting change the audit warned
// against. Tradeoff: a peer that roams twice between polls counts as one
// change. Documented in docs/reference/metrics.md.
const metricsRoamingPollInterval = 30 * time.Second

func (m *metricsState) runRoamingPoller(e *Engine) {
	ticker := time.NewTicker(metricsRoamingPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.closed:
			return
		case <-ticker.C:
		}
		st, err := e.Status()
		if err != nil {
			continue
		}
		m.roamMu.Lock()
		for _, p := range st.Peers {
			ep := p.Endpoint
			if ep == "" {
				continue
			}
			prev, ok := m.lastEndpoint[p.PublicKey]
			if ok && prev != ep {
				m.roamingEndpointChanges.Add(1)
			}
			m.lastEndpoint[p.PublicKey] = ep
		}
		m.roamMu.Unlock()
	}
}

// netstackTCPRetransmits surfaces gVisor's TCP retransmit count if the
// netstack is configured. Returns 0 when stats are unavailable or the
// build/wiring cannot reach them; we deliberately avoid a hard import
// dependency on a specific gVisor version.
func netstackTCPRetransmits(e *Engine) uint64 {
	defer func() {
		// gvisor stats interfaces have shifted between versions; if
		// the assertion path panics in a future bump, we still want
		// the scrape to succeed.
		_ = recover()
	}()
	stats := e.netstackStats()
	if stats == nil {
		return 0
	}
	return stats.TCPRetransmits
}

// netstackStatsSnapshot is the subset of gVisor stats this metrics layer
// consumes. Adding fields here is a contract update with the wiring in
// engine.netstackStats().
type netstackStatsSnapshot struct {
	TCPRetransmits uint64
}

// mustRegisterCounterFunc is the no-label form. For label-shaped counters
// use newEnumCounterCollector — one collector per metric name, emitting
// all label-value series in a single Collect call. The previous "one
// collector per (name, labelValues) tuple" approach hit Prometheus's
// duplicate-Desc detector.
func mustRegisterCounterFunc(reg *prometheus.Registry, name, help string, labelNames, labelValues []string, fn func() float64) {
	if labelNames != nil {
		panic("metrics: use newEnumCounterCollector for label-shaped counters")
	}
	reg.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, fn))
}

// enumCounterCollector emits one Counter series per (label_value -> read
// function) pair, all sharing the same Desc. Use this whenever a counter
// has a fixed enum of label values known at registration time
// (rate_limited / ok / auth_failed for mesh, etc.).
type enumCounterCollector struct {
	desc       *prometheus.Desc
	labelName  string
	labelFuncs map[string]func() float64
}

func newEnumCounterCollector(name, help, labelName string, vals map[string]func() float64) *enumCounterCollector {
	return &enumCounterCollector{
		desc:       prometheus.NewDesc(name, help, []string{labelName}, nil),
		labelName:  labelName,
		labelFuncs: vals,
	}
}

func (c *enumCounterCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }
func (c *enumCounterCollector) Collect(ch chan<- prometheus.Metric) {
	for lv, fn := range c.labelFuncs {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, fn(), lv)
	}
}

// registerPerPeerCollector wires the opt-in per-peer time series. Capped at
// cfg.Metrics.MaxPerPeer; peers beyond the cap are aggregated into a single
// "_overflow" series so the operator still sees the volume but Prometheus
// doesn't get an unbounded cardinality explosion.
func registerPerPeerCollector(reg *prometheus.Registry, e *Engine) {
	bytesRx := prometheus.NewDesc("uwgsocks_peer_bytes_received_total",
		"Bytes received from a single peer (per_peer_detail=true). 'peer' is the WireGuard public key; values beyond metrics.max_per_peer are aggregated into peer=\"_overflow\".",
		[]string{"peer"}, nil)
	bytesTx := prometheus.NewDesc("uwgsocks_peer_bytes_transmitted_total",
		"Bytes transmitted to a single peer.",
		[]string{"peer"}, nil)
	lastHS := prometheus.NewDesc("uwgsocks_peer_last_handshake_unix_seconds",
		"Unix timestamp of the most recent successful handshake with the peer. 0 if never.",
		[]string{"peer"}, nil)
	reg.MustRegister(&perPeerCollector{e: e, descs: []*prometheus.Desc{bytesRx, bytesTx, lastHS}})
}

type perPeerCollector struct {
	e     *Engine
	descs []*prometheus.Desc
}

func (c *perPeerCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

func (c *perPeerCollector) Collect(ch chan<- prometheus.Metric) {
	st, err := c.e.Status()
	if err != nil {
		return
	}
	max := c.e.cfg.Metrics.MaxPerPeer
	if max <= 0 {
		max = 1024
	}
	var (
		overflowRx, overflowTx uint64
		overflowCount          int
	)
	for i, p := range st.Peers {
		if i >= max {
			overflowRx += p.ReceiveBytes
			overflowTx += p.TransmitBytes
			overflowCount++
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.descs[0], prometheus.CounterValue, float64(p.ReceiveBytes), p.PublicKey)
		ch <- prometheus.MustNewConstMetric(c.descs[1], prometheus.CounterValue, float64(p.TransmitBytes), p.PublicKey)
		ch <- prometheus.MustNewConstMetric(c.descs[2], prometheus.GaugeValue, float64(p.LastHandshakeTimeSec), p.PublicKey)
	}
	if overflowCount > 0 {
		ch <- prometheus.MustNewConstMetric(c.descs[0], prometheus.CounterValue, float64(overflowRx), "_overflow")
		ch <- prometheus.MustNewConstMetric(c.descs[1], prometheus.CounterValue, float64(overflowTx), "_overflow")
	}
}

// Build-info helpers. Prefer linker-supplied values when present; otherwise
// fall back to debug.ReadBuildInfo so dev builds still report something
// meaningful instead of an empty label.
func buildInfoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
func buildInfoGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		return info.GoVersion
	}
	return ""
}
func buildInfoLite() string {
	if liteBuild() {
		return "true"
	}
	return "false"
}

// listenForMetricsTesting resolves the metrics listener's actual address.
// Useful when metrics.listen is "127.0.0.1:0" and the kernel picks a port.
func (e *Engine) listenForMetricsTesting() (net.Addr, error) {
	if e == nil {
		return nil, errors.New("nil engine")
	}
	if ln := e.listenerByName("metrics"); ln != nil {
		return ln.Addr(), nil
	}
	return nil, errors.New("metrics listener not started")
}
