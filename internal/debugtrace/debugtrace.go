// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

// Package debugtrace is a debug-only tracing facility for tracking
// fdproxy / tracer / engine IPC across the wrapper. Activated by
// setting UWGS_TRACE_FILE=/path/to/log.txt before launching uwgwrapper
// (and inherited into spawned fdproxy / tracee processes via env).
//
// When UWGS_TRACE_FILE is unset, every Logf call is a single atomic
// load + branch — effectively free. When set, all writes are
// serialized through a single goroutine-safe log.Logger so output
// from concurrent tracer threads / fdproxy goroutines is interleaved
// cleanly without garbled lines.
//
// Each line is prefixed with [pid=N comp=X] so a single log file
// can be tailed across the whole launch tree (parent wrapper, child
// fdproxy, child tracees) and the source of each line is obvious.
package debugtrace

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	enabled atomic
	logger  *log.Logger
	component string
	mu      sync.Mutex
)

type atomic struct{ v bool }

func (a *atomic) Get() bool { return a.v }

func init() {
	path := strings.TrimSpace(os.Getenv("UWGS_TRACE_FILE"))
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		// Best-effort: silently disable rather than crash.
		return
	}
	logger = log.New(f, "", log.LstdFlags|log.Lmicroseconds)
	enabled.v = true
}

// SetComponent labels subsequent Logf calls with this component name
// (e.g. "tracer", "fdproxy", "engine"). Call once per process at
// startup. No-op when tracing disabled.
func SetComponent(name string) {
	if !enabled.v {
		return
	}
	mu.Lock()
	component = name
	mu.Unlock()
}

// Enabled returns true when tracing is active. Useful for skipping
// expensive arg formatting at call sites.
func Enabled() bool { return enabled.v }

// Logf writes a single trace line tagged with the calling process's
// pid and the component label. No-op when tracing disabled.
func Logf(format string, args ...any) {
	if !enabled.v {
		return
	}
	mu.Lock()
	comp := component
	mu.Unlock()
	if comp == "" {
		comp = "?"
	}
	logger.Printf("[pid=%d comp=%s] %s", os.Getpid(), comp, fmt.Sprintf(format, args...))
}
