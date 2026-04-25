// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"net/http"
	"net/http/httptest"
	"sync"
)

// recordMeshRateLimitTestHandler is a per-engine memoised middleware chain
// — created on first use, reused across invocations so the bucket map
// inside the rate limiter persists across calls. Lives in a _test file so
// the test partner package can reach it via an exported wrapper.
var (
	recordMeshRateLimitTestHandlerMu sync.Mutex
	recordMeshRateLimitTestHandler   map[*Engine]http.Handler
)

// RecordMeshRateLimitTestEvent runs the engine's mesh rate-limiter middleware
// once, simulating a request from the given remote. After enough calls past
// the burst budget the meshRequestsRateLimited counter increments. This is
// the bridge the metrics smoke test uses to drive a hot-path counter without
// having to spin up a full mesh-control listener inside the netstack.
func RecordMeshRateLimitTestEvent(e *Engine, remote string) {
	if e.metrics == nil {
		e.metrics = newMetricsState()
	}
	recordMeshRateLimitTestHandlerMu.Lock()
	if recordMeshRateLimitTestHandler == nil {
		recordMeshRateLimitTestHandler = make(map[*Engine]http.Handler)
	}
	h := recordMeshRateLimitTestHandler[e]
	if h == nil {
		h = e.meshControlRateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		recordMeshRateLimitTestHandler[e] = h
	}
	recordMeshRateLimitTestHandlerMu.Unlock()
	req := httptest.NewRequest(http.MethodGet, "/v1/challenge", nil)
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
}
