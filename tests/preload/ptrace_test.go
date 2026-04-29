//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
)

type wrapperArtifacts struct {
	wrapper      string
	preload      string
	stub         string
	epollNB      string
	threadedKill string
	mixed        string
	raw          string
	rawmixLib    string
	rawmixClient string
	nnpProbe     string
	stdioHeavy   string
}

type traceStats struct {
	Syscalls map[string]uint64 `json:"syscalls"`
}

type wrapperRunOptions struct {
	env         map[string]string
	wrapperArgs []string
	timeout     time.Duration
}

// staticCapableModes is the set of wrapper transports that can intercept
// statically-linked Go binaries (CGO_ENABLED=0). preload and systrap inject
// only dynamic binaries; intercepting static binaries requires either a ptrace
// layer (ptrace*, systrap-supervised) or a freestanding runtime (systrap-static).
var staticCapableModes = []string{"systrap-supervised", "systrap-static", "ptrace", "ptrace-seccomp", "ptrace-only"}

func TestUWGWrapperStaticCapableRawGoTCPUDP(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	for _, transport := range staticCapableModes {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTarget(t, art, httpSock, transport, art.raw, "tcp", "100.64.94.1", "18080", transport+"-tcp")
			if normalizedOutput(out) != transport+"-tcp" {
				t.Fatalf("unexpected %s tcp output %q", transport, out)
			}
			out = runWrappedTarget(t, art, httpSock, transport, art.raw, "udp", "100.64.94.1", "18081", transport+"-udp")
			if normalizedOutput(out) != transport+"-udp" {
				t.Fatalf("unexpected %s udp output %q", transport, out)
			}
		})
	}
}

func TestUWGWrapperPtraceOnlyAccidentalPreloadUsesSecretPassthrough(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out, stats := runWrappedTargetWithStats(t, art, httpSock, "ptrace-only", art.stub,
		[]string{"100.64.94.1", "18080", "accidental-preload", "tcp-no-poll"},
		wrapperRunOptions{
			timeout: 60 * time.Second,
			env: map[string]string{
				"LD_PRELOAD": art.preload,
			},
		})
	if normalizedOutput(out) != "accidental-preload" {
		t.Fatalf("unexpected accidental preload output %q", out)
	}
	for _, name := range []string{"socket", "connect"} {
		assertSyscallCount(t, stats, name, 0)
	}
}

func TestUWGWrapperBothStdIOHeavyStaysOffPtrace(t *testing.T) {
	if os.Getenv("UWGS_RUN_STDIO_HEAVY_DIAG") == "" {
		t.Skip("set UWGS_RUN_STDIO_HEAVY_DIAG=1 to run the stdio-heavy combo diagnostic")
	}
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out, baseline := runWrappedTargetWithStats(t, art, httpSock, "systrap", art.stdioHeavy,
		[]string{"baseline"}, wrapperRunOptions{timeout: 60 * time.Second})
	if normalizedOutput(out) != "stdio-baseline-ok" {
		t.Fatalf("unexpected stdio baseline output %q", out)
	}

	out, stats := runWrappedTargetWithStats(t, art, httpSock, "systrap", art.stdioHeavy,
		[]string{"heavy"}, wrapperRunOptions{timeout: 60 * time.Second})
	if normalizedOutput(out) != "stdio-heavy-ok" {
		t.Fatalf("unexpected stdio heavy output %q", out)
	}
	t.Logf("stdio-heavy baseline traced syscalls: %v", baseline.Syscalls)
	t.Logf("stdio-heavy workload traced syscalls: %v", stats.Syscalls)
	if os.Getenv("UWGS_STRICT_STDIO_HOTPATH") != "" && !mapsEqualUint64(stats.Syscalls, baseline.Syscalls) {
		t.Fatalf("expected stdio-heavy workload to add no ptrace traffic beyond startup baseline, baseline=%v heavy=%v", baseline.Syscalls, stats.Syscalls)
	}
}

func TestUWGWrapperBothStress(t *testing.T) {
	if os.Getenv("UWGS_SOAK") == "" {
		t.Skip("set UWGS_SOAK=1 to run long wrapper stress tests")
	}
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTargetWithOptions(t, art, httpSock, "systrap", art.rawmixClient,
		[]string{"stress", "100.64.94.1", "18080", "both-stress", "2", "2"},
		wrapperRunOptions{timeout: 90 * time.Second})
	if strings.TrimSpace(string(out)) != "rawmix-stress-ok" {
		t.Fatalf("unexpected mixed stress output %q", out)
	}
}

func TestUWGWrapperBothExecAndFork(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	// exec variant: dynamic→dynamic execve. systrap re-arms across the exec
	// boundary natively; systrap-supervised and ptrace modes also handle it.
	for _, transport := range []string{"systrap", "systrap-supervised", "ptrace", "ptrace-only"} {
		t.Run("exec/"+transport, func(t *testing.T) {
			out := runWrappedTarget(t, art, httpSock, transport, art.mixed, "100.64.94.1", "18080", "both-exec", "exec")
			if normalizedOutput(out) != "both-exec" {
				t.Fatalf("unexpected both exec output under %s: %q", transport, out)
			}
		})
	}

	// fork variant: systrap handles fork() without any ptrace layer.
	out := runWrappedTargetWithOptions(t, art, httpSock, "systrap", art.stub,
		[]string{"100.64.94.1", "18080", "both-fork", "tcp", "fork"},
		wrapperRunOptions{timeout: 60 * time.Second})
	if normalizedOutput(out) != "both-fork" {
		t.Fatalf("unexpected both fork output %q", out)
	}
}

func TestUWGWrapperCurlAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is required for the practical wrapper coverage test")
	}
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)
	hostIP := nonLoopbackIPv4(t)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18083"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "curl-over-wrapper")
		}))
	}()

	directLn, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer directLn.Close()
	go func() {
		_ = http.Serve(directLn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "curl-direct-fallback")
		}))
	}()
	_, directPort, err := net.SplitHostPort(directLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, "curl",
				[]string{"--max-time", "15", "-fsS", "http://100.64.94.1:18083/"},
				wrapperRunOptions{timeout: 90 * time.Second})
			if normalizedOutput(out) != "curl-over-wrapper" {
				t.Fatalf("unexpected curl output %q", out)
			}

			out = runWrappedTargetWithOptions(t, art, httpSock, transport, "curl",
				[]string{"--max-time", "15", "-fsS", "http://" + net.JoinHostPort(hostIP.String(), directPort) + "/"},
				wrapperRunOptions{timeout: 90 * time.Second})
			if normalizedOutput(out) != "curl-direct-fallback" {
				t.Fatalf("unexpected direct-fallback curl output %q", out)
			}
		})
	}
}

func TestUWGWrapperMessageSyscallsAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	cases := []struct {
		name string
		args []string
		want string
		// syscalls listed here are asserted (≥1) when the transport
		// spawns the ptrace tracer. Skipped for preload-only — that
		// path has no per-syscall counter, so the round-trip output
		// is the only signal there.
		syscalls []string
		// anyOfSyscalls is for cases where libc may use one of
		// several syscall numbers — each inner slice is "at least
		// one of these names must have count ≥ 1". E.g., musl
		// emulates sendmmsg as a loop of sendmsg, so {"sendmmsg",
		// "sendmsg"} accepts either. AND across outer slices.
		anyOfSyscalls [][]string
	}{
		{
			name:     "tcp-sendmsg-recvmsg",
			args:     []string{"100.64.94.1", "18080", "tcp-msg", "tcp", "msg"},
			want:     "tcp-msg",
			syscalls: []string{"sendmsg", "recvmsg"},
		},
		{
			name:     "udp-sendmsg-recvmsg",
			args:     []string{"100.64.94.1", "18081", "udp-msg", "udp", "msg"},
			want:     "udp-msg",
			syscalls: []string{"sendmsg", "recvmsg"},
		},
		{
			name:     "udp-unconnected-sendmsg-recvmsg",
			args:     []string{"100.64.94.1", "18081", "udp-unconnected-msg", "udp-unconnected", "msg"},
			want:     "udp-unconnected-msg",
			syscalls: []string{"sendmsg", "recvmsg"},
		},
		{
			name:     "udp-unconnected-sendto-recvfrom",
			args:     []string{"100.64.94.1", "18081", "udp-unconnected-sendto", "udp-unconnected"},
			want:     "udp-unconnected-sendto",
			syscalls: []string{"sendto", "recvfrom"},
		},
		{
			name:     "tcp-readv-writev",
			args:     []string{"100.64.94.1", "18080", "tcp-iov", "tcp", "iov"},
			want:     "tcp-iov",
			syscalls: []string{"readv", "writev"},
		},
		{
			name:     "udp-readv-writev",
			args:     []string{"100.64.94.1", "18081", "udp-iov", "udp", "iov"},
			want:     "udp-iov",
			syscalls: []string{"readv", "writev"},
		},
		{
			name: "udp-sendmmsg-recvmmsg",
			args: []string{"100.64.94.1", "18081", "udp-mmsg", "udp", "mmsg"},
			want: "udp-mmsg",
			// musl <1.x and some libc paths emulate sendmmsg as a
			// loop of sendmsg syscalls — the tracer then sees
			// sendmsg counts instead of sendmmsg. Check
			// EITHER family. recvmmsg has the same potential
			// asymmetry on some libcs. The point is "the libc
			// call reached the tracer", not which syscall number
			// the libc happened to use.
			anyOfSyscalls: [][]string{{"sendmmsg", "sendmsg"}, {"recvmmsg", "recvmsg"}},
		},
	}
	transports := []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"}
	for _, transport := range transports {
		for _, tc := range cases {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				hasCounters := len(tc.syscalls) > 0 || len(tc.anyOfSyscalls) > 0
				if transportTracerCountsHotpathSyscalls(transport) && hasCounters {
					out, stats := runWrappedTargetWithStats(t, art, httpSock, transport, art.stub, tc.args, wrapperRunOptions{
						timeout: 60 * time.Second,
					})
					if normalizedOutput(out) != tc.want {
						t.Fatalf("unexpected %s output %q", tc.name, out)
					}
					for _, name := range tc.syscalls {
						assertSyscallAtLeast(t, stats, name, 1)
					}
					for _, group := range tc.anyOfSyscalls {
						var total uint64
						for _, name := range group {
							total += stats.Syscalls[name]
						}
						if total < 1 {
							t.Fatalf("expected at least one of %v >= 1, got 0 (all=%v)", group, stats.Syscalls)
						}
					}
					return
				}
				out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub, tc.args, wrapperRunOptions{
					timeout: 60 * time.Second,
				})
				if normalizedOutput(out) != tc.want {
					t.Fatalf("unexpected %s output %q", tc.name, out)
				}
			})
		}
	}
}

func TestUWGWrapperPselectAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			args := []string{"100.64.94.1", "18080", "tcp-pselect", "tcp", "pselect"}
			if transportTracerCountsHotpathSyscalls(transport) {
				out, stats := runWrappedTargetWithStats(t, art, httpSock, transport, art.stub, args,
					wrapperRunOptions{timeout: 60 * time.Second})
				if normalizedOutput(out) != "tcp-pselect" {
					t.Fatalf("unexpected pselect output %q", out)
				}
				assertSyscallAtLeast(t, stats, "pselect6", 1)
				return
			}
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub, args,
				wrapperRunOptions{timeout: 60 * time.Second})
			if normalizedOutput(out) != "tcp-pselect" {
				t.Fatalf("unexpected pselect output %q", out)
			}
		})
	}
}

func TestUWGWrapperSelectAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			args := []string{"100.64.94.1", "18080", "tcp-select", "tcp", "select"}
			if transportTracerCountsHotpathSyscalls(transport) {
				out, stats := runWrappedTargetWithStats(t, art, httpSock, transport, art.stub, args,
					wrapperRunOptions{timeout: 60 * time.Second})
				if normalizedOutput(out) != "tcp-select" {
					t.Fatalf("unexpected select output %q", out)
				}
				// libc may reach the kernel via either the native
				// select(2) syscall or pselect6(2). amd64 has both;
				// arm64 has only pselect6; glibc 2.43 maps select()
				// onto pselect6 even on amd64. Accept either —
				// what we're pinning is "the libc call reached the
				// tracer", not which syscall number was used.
				got := stats.Syscalls["select"] + stats.Syscalls["pselect6"]
				if got < 1 {
					t.Fatalf("expected at least one of select/pselect6, got 0 (all=%v)", stats.Syscalls)
				}
				return
			}
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub, args,
				wrapperRunOptions{timeout: 60 * time.Second})
			if normalizedOutput(out) != "tcp-select" {
				t.Fatalf("unexpected select output %q", out)
			}
		})
	}
}

func TestUWGWrapperPtraceSeccompSocketSyscallSurfaceStats(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out, stats := runWrappedTargetWithStats(t, art, httpSock, "ptrace-seccomp", art.stub,
		[]string{"100.64.94.1", "18080", "syscall-surface", "tcp", "syscall-surface"},
		wrapperRunOptions{timeout: 60 * time.Second})
	if normalizedOutput(out) != "syscall-surface" {
		t.Fatalf("unexpected syscall surface output %q", out)
	}
	for _, name := range []string{
		"socket",
		"connect",
		"write",
		"read",
		"dup",
		"dup2",
		"dup3",
		"getsockname",
		"getpeername",
		"shutdown",
		"fcntl",
		"getsockopt",
		"setsockopt",
		"poll",
		"ppoll",
		"close",
	} {
		assertSyscallAtLeast(t, stats, name, 1)
	}
}

// TestUWGWrapperSocketSyscallSurfaceExtra runs the extended
// syscall-surface walk added alongside the original surface stub.
// It pins the syscalls that the original walk skipped — send + recv
// (vs write/read), F_DUPFD_CLOEXEC, multi-fd poll across a socket
// and a pipe, and shutdown(SHUT_WR) — so a regression in the
// seccomp filter or preload wrapper can't silently bypass them.
//
// The test runs across all wrapper transports so the preload-only
// path also exercises the round-trip. Counter assertions only fire
// for transports that spawn the ptrace tracer (preload-only has no
// per-syscall counter file).
func TestUWGWrapperSocketSyscallSurfaceExtra(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	args := []string{"100.64.94.1", "18080", "syscall-surface-extra", "tcp", "syscall-surface-extra"}
	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			if transportTracerCountsHotpathSyscalls(transport) {
				// Bumped from 60s — ptrace-only on GH runners occasion-
				// ally exceeds 60s; same CPU-contention root cause as
				// TestPtraceNonblockConnectFlow.
				out, stats := runWrappedTargetWithStats(t, art, httpSock, transport, art.stub, args,
					wrapperRunOptions{timeout: 120 * time.Second})
				if normalizedOutput(out) != "syscall-surface-extra" {
					t.Fatalf("unexpected syscall surface extra output %q", out)
				}
				// libc's send/recv map to sendto/recvfrom on Linux,
				// so the tracer records them under those syscall names.
				for _, name := range []string{
					"sendto",
					"recvfrom",
					"fcntl",
					"poll",
					"shutdown",
				} {
					assertSyscallAtLeast(t, stats, name, 1)
				}
				// Two shutdowns (SHUT_WR then SHUT_RDWR) — assert both
				// to catch a partial-shutdown bypass.
				assertSyscallAtLeast(t, stats, "shutdown", 2)
				return
			}
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub, args,
				wrapperRunOptions{timeout: 60 * time.Second})
			if normalizedOutput(out) != "syscall-surface-extra" {
				t.Fatalf("unexpected syscall surface extra output %q", out)
			}
		})
	}
}

// TestUWGWrapperPtraceSeccompTCPListenerStats re-runs the TCP listener
// flow under ptrace+seccomp and asserts that bind, listen, and accept
// each show up in the tracer counters. The plain TCPListener test only
// verifies the round-trip; if seccomp regressed and stopped trapping
// any of these, a libc-direct bypass would still echo successfully.
func TestUWGWrapperPtraceSeccompTCPListenerStats(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	stats, err := runWrappedListenerWithStats(t, art, httpSock, "ptrace-seccomp",
		[]string{"100.64.94.2", "19193", "ptrace-seccomp-listener-stats", "listen-tcp"},
		serverEng, "100.64.94.2:19193", "ptrace-seccomp-listener-stats")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bind", "listen", "accept", "close"} {
		assertSyscallAtLeast(t, stats, name, 1)
	}
}

// TestUWGWrapperPtraceSeccompTCPListenerAccept4Stats covers the
// accept4(2) path. The original listener stub uses 3-arg accept(); no
// existing test exercised the 4-arg accept4 entry that real apps using
// SOCK_CLOEXEC/SOCK_NONBLOCK take. The stub here passes SOCK_CLOEXEC
// and verifies the returned fd has FD_CLOEXEC set — proving the flag
// argument made it through preload/ptrace correctly.
func TestUWGWrapperPtraceSeccompTCPListenerAccept4Stats(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	stats, err := runWrappedListenerWithStats(t, art, httpSock, "ptrace-seccomp",
		[]string{"100.64.94.2", "19194", "ptrace-seccomp-listener-accept4", "listen-tcp-accept4"},
		serverEng, "100.64.94.2:19194", "ptrace-seccomp-listener-accept4")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bind", "listen", "accept4", "close"} {
		assertSyscallAtLeast(t, stats, name, 1)
	}
}

// TestUWGWrapperPreloadAccept4Listener is the preload-only sibling of
// the ptrace+seccomp accept4 listener test. Preload has no per-syscall
// counter file, so this is a round-trip-only check — but it pins the
// preload accept4() wrapper end-to-end, including the SOCK_CLOEXEC
// flag handling that the C stub asserts.
func TestUWGWrapperPreloadAccept4Listener(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, "preload", art.stub,
			[]string{"100.64.94.2", "19195", "preload-listener-accept4", "listen-tcp-accept4"}, wrapperRunOptions{})

		runErr := func() error {
			// stderr can only be safely read AFTER cmd.Wait
			// (i.e. <-done) returns — until then, os/exec's
			// stderr-copying goroutine is still writing into the
			// bytes.Buffer and the -race detector will flag any
			// concurrent .String() call. Defer the read.
			drainAndDump := func() string {
				killProcessGroup(cmd)
				<-done
				return stderr.String()
			}
			conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:19195")
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("preload-listener-accept4")); err != nil {
				return fmt.Errorf("listener write failed: %w\nstderr=%s", err, drainAndDump())
			}
			buf := make([]byte, len("preload-listener-accept4"))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return fmt.Errorf("listener read failed: %w\nstderr=%s", err, drainAndDump())
			}
			if string(buf) != "preload-listener-accept4" {
				return fmt.Errorf("listener echo mismatch %q\nstderr=%s", buf, drainAndDump())
			}
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("listener wrapper failed: %w\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("listener wrapper did not exit\nstderr=%s", drainAndDump())
			}
			return nil
		}()
		if runErr == nil {
			return
		}
		lastErr = runErr
		t.Logf("retrying preload accept4 listener test after transient failure: %v", runErr)
	}
	t.Fatal(lastErr)
}

// runWrappedListenerWithStats wires a temp UWGS_TRACE_STATS_PATH into
// the listener wrapper, drives the echo round-trip, then reads the
// resulting tracer stats file. It mirrors the retry/teardown logic of
// startWrappedListenerProcess but is dedicated to stats-asserting
// tests so the existing listener tests stay byte-identical.
func runWrappedListenerWithStats(t *testing.T, art wrapperArtifacts, httpSock, transport string, args []string, serverEng *engine.Engine, dialAddr, message string) (traceStats, error) {
	t.Helper()
	statsPath := filepath.Join(t.TempDir(), "trace-stats.json")
	opts := wrapperRunOptions{env: map[string]string{"UWGS_TRACE_STATS_PATH": statsPath}}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, transport, art.stub, args, opts)

		runErr := func() error {
			// stderr can only be safely read AFTER cmd.Wait
			// (i.e. <-done) returns. See the same pattern in
			// TestUWGWrapperPreloadAccept4Listener for details.
			drainAndDump := func() string {
				killProcessGroup(cmd)
				<-done
				return stderr.String()
			}
			conn := retryTunnelDial(t, serverEng, "tcp", dialAddr)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte(message)); err != nil {
				return fmt.Errorf("listener write failed: %w\nstderr=%s", err, drainAndDump())
			}
			buf := make([]byte, len(message))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return fmt.Errorf("listener read failed: %w\nstderr=%s", err, drainAndDump())
			}
			if string(buf) != message {
				return fmt.Errorf("listener echo mismatch %q\nstderr=%s", buf, drainAndDump())
			}
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("listener wrapper failed: %w\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("listener wrapper did not exit\nstderr=%s", drainAndDump())
			}
			return nil
		}()
		if runErr == nil {
			data, err := os.ReadFile(statsPath)
			if err != nil {
				return traceStats{}, fmt.Errorf("read trace stats: %w", err)
			}
			var stats traceStats
			if err := json.Unmarshal(data, &stats); err != nil {
				return traceStats{}, fmt.Errorf("decode trace stats: %w\n%s", err, data)
			}
			if stats.Syscalls == nil {
				stats.Syscalls = make(map[string]uint64)
			}
			return stats, nil
		}
		lastErr = runErr
		t.Logf("retrying %s listener stats run after transient failure: %v", transport, runErr)
	}
	return traceStats{}, lastErr
}

// TestUWGWrapperRecvPeekAcrossTransports asserts that recv(MSG_PEEK)
// does not consume data on a TCP stream, across every wrapper
// transport. Protocol-detection code (TLS sniffers, SOCKS hand-off,
// HTTP/2 detection) relies on this. A custom recv shim that silently
// drops the flags argument would still echo the message back on the
// first recv but would mismatch the peeked prefix vs. the second
// real recv, which the C stub asserts.
func TestUWGWrapperRecvPeekAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	args := []string{"100.64.94.1", "18080", "recv-peek-msg", "tcp", "recv-peek"}
	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub, args,
				wrapperRunOptions{timeout: 120 * time.Second})
			if normalizedOutput(out) != "recv-peek-msg" {
				t.Fatalf("unexpected recv-peek output %q", out)
			}
		})
	}
}

// TestUWGWrapperShortReadAcrossTransports forces a small read buffer
// against a longer payload, then drains the rest with subsequent
// reads. The proxy/tracer paths must not lose bytes when the
// caller-supplied buffer is smaller than what arrived from the
// tunnel (a class of bug where buffered "extra" bytes can be silently
// dropped on the next recv call).
func TestUWGWrapperShortReadAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	// Message must be ≥8 bytes; the stub progressively reads with
	// budgets of 4, 16, then full so the first read is genuinely
	// shorter than the payload.
	args := []string{"100.64.94.1", "18080", "short-read-payload-message", "tcp", "short-read"}
	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub, args,
				wrapperRunOptions{timeout: 120 * time.Second})
			if normalizedOutput(out) != "short-read-payload-message" {
				t.Fatalf("unexpected short-read output %q", out)
			}
		})
	}
}

func TestUWGWrapperUDPConnectProbeLazy(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	missingAPI := filepath.Join(t.TempDir(), "missing-http.sock")

	for _, transport := range []string{"ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, missingAPI, transport, art.stub,
				[]string{"100.64.94.1", "18080", "udp-connect-probe", "udp-connect-probe"},
				wrapperRunOptions{timeout: 15 * time.Second})
			if normalizedOutput(out) != "udp-connect-probe" {
				t.Fatalf("unexpected UDP connect probe output %q", out)
			}
		})
	}
}

func TestUWGWrapperPtraceSeccompTCPListener(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, "ptrace-seccomp", art.stub,
			[]string{"100.64.94.2", "19190", "ptrace-seccomp-listener", "listen-tcp"}, wrapperRunOptions{})

		runErr := func() error {
			drainAndDump := func() string {
				killProcessGroup(cmd)
				<-done
				return stderr.String()
			}
			conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:19190")
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("ptrace-seccomp-listener")); err != nil {
				return fmt.Errorf("listener write failed: %w\nstderr=%s", err, drainAndDump())
			}
			buf := make([]byte, len("ptrace-seccomp-listener"))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return fmt.Errorf("listener read failed: %w\nstderr=%s", err, drainAndDump())
			}
			if string(buf) != "ptrace-seccomp-listener" {
				return fmt.Errorf("listener echo mismatch %q\nstderr=%s", buf, drainAndDump())
			}
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("listener wrapper failed: %w\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("listener wrapper did not exit\nstderr=%s", drainAndDump())
			}
			return nil
		}()
		if runErr == nil {
			return
		}
		lastErr = runErr
		t.Logf("retrying ptrace+seccomp listener test after transient failure: %v", runErr)
	}
	t.Fatal(lastErr)
}

func TestUWGWrapperPreloadOnlyTCPUDPAndListener(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "preload", art.stub, "100.64.94.1", "18080", "preload-tcp", "tcp")
	if normalizedOutput(out) != "preload-tcp" {
		t.Fatalf("unexpected preload tcp output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "preload", art.stub, "100.64.94.1", "18081", "preload-udp", "udp")
	if normalizedOutput(out) != "preload-udp" {
		t.Fatalf("unexpected preload udp output %q", out)
	}

	// `preload` is now libc-only (post-rename); the libc-shim
	// listener path is more flake-prone under GH-runner CPU
	// contention than it was when this transport name still
	// included seccomp + SIGSYS as a fallback. Bumped from 3 to
	// 6 attempts to absorb the runner-environment variance; the
	// test passes reliably on self-hosted + dev hosts in the
	// first attempt (~4s).
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		// Small back-off between attempts to let the previous
		// fdproxy + tunnel listener tear down cleanly before the
		// next one races to bind the same tunnel address.
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
		}
		cmd, stderr, done := startWrappedListenerProcess(t, art, httpSock, "preload", art.stub,
			[]string{"100.64.94.2", "19191", "preload-listener", "listen-tcp"}, wrapperRunOptions{})

		runErr := func() error {
			// stderr is only safe to read AFTER cmd.Wait (i.e. <-done).
			// See TestUWGWrapperPreloadAccept4Listener for the
			// same drain helper + the data-race rationale.
			drainAndDump := func() string {
				killProcessGroup(cmd)
				<-done
				return stderr.String()
			}
			conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:19191")
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("preload-listener")); err != nil {
				return fmt.Errorf("preload listener write failed: %w\nstderr=%s", err, drainAndDump())
			}
			buf := make([]byte, len("preload-listener"))
			if _, err := io.ReadFull(conn, buf); err != nil {
				return fmt.Errorf("preload listener read failed: %w\nstderr=%s", err, drainAndDump())
			}
			if string(buf) != "preload-listener" {
				return fmt.Errorf("preload listener echo mismatch %q\nstderr=%s", buf, drainAndDump())
			}
			select {
			case err := <-done:
				if err != nil {
					return fmt.Errorf("preload listener wrapper failed: %w\nstderr=%s", err, stderr.String())
				}
			case <-time.After(10 * time.Second):
				return fmt.Errorf("preload listener wrapper did not exit\nstderr=%s", drainAndDump())
			}
			return nil
		}()
		if runErr == nil {
			return
		}
		lastErr = runErr
		t.Logf("retrying preload listener test after transient failure: %v", runErr)
	}
	t.Fatal(lastErr)
}

func TestUWGWrapperPtraceLifecycleLoop(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true binary not available")
	}

	for _, transport := range []string{"ptrace", "ptrace-only", "ptrace-seccomp"} {
		t.Run(transport, func(t *testing.T) {
			for i := 0; i < 15; i++ {
				out := runWrappedTargetWithOptions(t, art, httpSock, transport, truePath, nil, wrapperRunOptions{
					timeout: 15 * time.Second,
				})
				if got := strings.TrimSpace(string(out)); got != "" {
					t.Fatalf("unexpected %s output on iteration %d: %q", transport, i, out)
				}
			}
		})
	}
}

func TestUWGWrapperNoNewPrivilegesDefaultAndOverride(t *testing.T) {
	if runningRestrictedGVisor() {
		t.Skip("restricted gVisor keeps no_new_privs forced on wrapper-launched processes")
	}
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "preload", art.nnpProbe)
	if normalizedOutput(out) != "1" {
		t.Fatalf("expected preload default no_new_privs=1, got %q", out)
	}

	out = runWrappedTargetWithOptions(t, art, httpSock, "preload", art.nnpProbe, nil, wrapperRunOptions{
		wrapperArgs: []string{"--no-new-privileges=false"},
	})
	if normalizedOutput(out) != "0" {
		t.Fatalf("expected preload override no_new_privs=0, got %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "ptrace", art.nnpProbe)
	if normalizedOutput(out) != "1" {
		t.Fatalf("expected ptrace default no_new_privs=1, got %q", out)
	}

	out = runWrappedTargetWithOptions(t, art, httpSock, "ptrace", art.nnpProbe, nil, wrapperRunOptions{
		wrapperArgs: []string{"--no-new-privileges=false"},
	})
	if normalizedOutput(out) != "0" {
		t.Fatalf("expected ptrace override no_new_privs=0, got %q", out)
	}
}

func requireWrapperToolchain(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("wrapper integration tests skipped in -short mode (run without -short or in release CI)")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("wrapper tests are linux/amd64 only")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is required for wrapper integration tests")
	}
}

func buildWrapperArtifacts(t *testing.T) wrapperArtifacts {
	t.Helper()
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	embeddedPreloadDir := filepath.Join(repo, "cmd", "uwgwrapper", "assets")
	embeddedPreload := filepath.Join("cmd", "uwgwrapper", "assets", "uwgpreload.so")
	art := wrapperArtifacts{
		wrapper:      filepath.Join(tmp, "uwgwrapper"),
		preload:      filepath.Join(tmp, "uwgpreload.so"),
		stub:         filepath.Join(tmp, "stub_client"),
		epollNB:      filepath.Join(tmp, "epoll_nonblock_repro"),
		threadedKill: filepath.Join(tmp, "threaded_tracee_death"),
		mixed:        filepath.Join(tmp, "mixed_client"),
		raw:          filepath.Join(tmp, "raw_client"),
		rawmixLib:    filepath.Join(tmp, "librawmix_helpers.so"),
		rawmixClient: filepath.Join(tmp, "rawmix_client"),
		nnpProbe:     filepath.Join(tmp, "nnp_probe"),
		stdioHeavy:   filepath.Join(tmp, "stdio_heavy"),
	}
	if err := os.MkdirAll(embeddedPreloadDir, 0o755); err != nil {
		t.Fatalf("mkdir embedded preload dir: %v", err)
	}
	run(t, repo, "bash", "preload/build_phase1.sh", embeddedPreload)
	run(t, repo, "bash", "preload/build_phase1.sh", art.preload)
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.stub, "tests/preload/testdata/stub_client.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.epollNB, "tests/preload/testdata/epoll_nonblock_repro.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-o", art.threadedKill, "tests/preload/testdata/threaded_tracee_death.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.mixed, "tests/preload/testdata/mixed_client.c")
	run(t, repo, "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", art.rawmixLib, "tests/preload/testdata/rawmix_helpers.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-I", "tests/preload/testdata", "-L", tmp, "-Wl,-rpath,$ORIGIN", "-o", art.rawmixClient, "tests/preload/testdata/rawmix_client.c", "-lrawmix_helpers")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.nnpProbe, "tests/preload/testdata/nnp_probe.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.stdioHeavy, "tests/preload/testdata/stdio_heavy.c")
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"}, "go", "build", "-o", art.raw, "tests/preload/testdata/raw_client.go")
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"}, "go", "build", "-o", art.wrapper, "./cmd/uwgwrapper")
	return art
}

func setupWrapperNetwork(t *testing.T) (*engine.Engine, string) {
	t.Helper()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.94.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.94.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	apiSock := filepath.Join(t.TempDir(), "api.sock")
	httpSock := filepath.Join(t.TempDir(), "http.sock")
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.94.2/32"}
	clientCfg.API.Listen = "unix:" + apiSock
	clientCfg.API.AllowUnauthenticatedUnix = true
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoa(serverPort)),
		AllowedIPs:          []string{"100.64.94.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)
	_ = clientEng
	waitPath(t, httpSock)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go serveEchoListener(ln)

	udp, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.94.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go serveUDPEcho(udp)

	return serverEng, httpSock
}

func wrappedCommand(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) *exec.Cmd {
	t.Helper()
	listenDir, err := os.MkdirTemp("", "uwgfdproxy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(listenDir) })
	listenSock := filepath.Join(listenDir, fmt.Sprintf("fdproxy-%s.sock", strings.ReplaceAll(transport, "/", "_")))
	cmdArgs := []string{"--transport=" + transport, "--listen", listenSock, "--api", "unix:" + httpSock, "--socket-path", "/uwg/socket"}
	if os.Getenv("UWGS_TEST_DEBUG") != "" {
		cmdArgs = append([]string{"-v"}, cmdArgs...)
	}
	if os.Getenv("UWGS_TEST_DEBUG_STRESS") != "" && len(args) > 0 && args[0] == "stress" {
		cmdArgs = append([]string{"-v"}, cmdArgs...)
	}
	cmdArgs = append(cmdArgs, opts.wrapperArgs...)
	if transportUsesPreload(transport) {
		cmdArgs = append(cmdArgs, "--preload", art.preload)
	}
	cmdArgs = append(cmdArgs, "--", target)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(art.wrapper, cmdArgs...)
	cmd.Env = append([]string{}, os.Environ()...)
	for key, value := range opts.env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}

func runCommandCombinedFileBacked(t *testing.T, cmd *exec.Cmd) ([]byte, error) {
	t.Helper()
	dir := t.TempDir()
	stdoutPath := filepath.Join(dir, "stdout.log")
	stderrPath := filepath.Join(dir, "stderr.log")
	stdoutFile, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatalf("create stdout log: %v", err)
	}
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		_ = stdoutFile.Close()
		t.Fatalf("create stderr log: %v", err)
	}
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile
	runErr := cmd.Run()
	_ = stdoutFile.Close()
	_ = stderrFile.Close()
	stdout, _ := os.ReadFile(stdoutPath)
	stderr, _ := os.ReadFile(stderrPath)
	out := append(append([]byte{}, stdout...), stderr...)
	return out, runErr
}

func runningRestrictedGVisor() bool {
	if _, err := os.Stat("/proc/sentry-meminfo"); err == nil {
		return true
	}
	return false
}

func unsupportedWrappedMode(out []byte) bool {
	return bytes.Contains(out, []byte("function not implemented"))
}

func startWrappedListenerProcess(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) (*exec.Cmd, *bytes.Buffer, chan error) {
	t.Helper()
	var lastErr error
	var lastStderr string
	for attempt := 0; attempt < 3; attempt++ {
		cmd := wrappedCommand(t, art, httpSock, transport, target, args, opts)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		reader := bufio.NewReader(stdout)
		type readyResult struct {
			line string
			err  error
		}
		readyCh := make(chan readyResult, 1)
		go func() {
			line, err := reader.ReadString('\n')
			readyCh <- readyResult{line: line, err: err}
		}()

		var ready string
		select {
		case res := <-readyCh:
			ready, err = res.line, res.err
		case <-time.After(10 * time.Second):
			killProcessGroup(cmd)
			<-done
			err = fmt.Errorf("listener did not become ready before timeout")
		}
		if err == nil && strings.TrimSpace(ready) == "READY" {
			return cmd, &stderr, done
		}
		// Kill and drain BEFORE reading stderr — os/exec's stderr-copy
		// goroutine writes into the bytes.Buffer until cmd.Wait() returns
		// (which is what `<-done` blocks on). Reading stderr.String() while
		// that goroutine is still active is a textbook data race the -race
		// detector will flag.
		killProcessGroup(cmd)
		<-done
		lastErr = err
		lastStderr = stderr.String()
		if runningRestrictedGVisor() && unsupportedWrappedMode(stderr.Bytes()) {
			t.Skipf("skipping wrapper mode %q on restricted gVisor kernel: %s", transport, strings.TrimSpace(stderr.String()))
		}
		if retryableWrappedFailure(stderr.Bytes(), nil) {
			t.Logf("retrying wrapped listener after startup failure: %s %v", target, args)
			continue
		}
		if err != nil {
			t.Fatalf("listener did not become ready: %v\nstderr=%s", err, lastStderr)
		}
		t.Fatalf("listener readiness = %q\nstderr=%s", ready, lastStderr)
	}
	t.Fatalf("listener did not become ready after retries: %v\nstderr=%s", lastErr, lastStderr)
	return nil, nil, nil
}

func runWrappedTarget(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args ...string) []byte {
	t.Helper()
	return runWrappedTargetWithOptions(t, art, httpSock, transport, target, args, wrapperRunOptions{})
}

func runWrappedTargetWithOptions(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) []byte {
	t.Helper()
	timeout := opts.timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	var lastOut []byte
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		base := wrappedCommand(t, art, httpSock, transport, target, args, opts)
		cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
		cmd.Env = append([]string{}, base.Env...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		out, err := runCommandCombinedFileBacked(t, cmd)
		cancel()
		if err == nil {
			return out
		}
		lastOut = out
		lastErr = err
		if runningRestrictedGVisor() && unsupportedWrappedMode(out) {
			t.Skipf("skipping wrapper mode %q on restricted gVisor kernel: %s", transport, strings.TrimSpace(string(out)))
		}
		if ctx.Err() == context.DeadlineExceeded {
			killProcessGroup(cmd)
			if attempt < 2 && retryableWrappedTimeout(target, transport, args) {
				t.Logf("retrying wrapped target after timeout: %s %v", target, args)
				continue
			}
			t.Fatalf("wrapped target %s %v timed out\n%s", target, args, out)
		}
		killProcessGroup(cmd)
		if attempt < 2 && retryableWrappedFailure(out, err) {
			t.Logf("retrying wrapped target after transient failure: %s %v (%v)", target, args, err)
			continue
		}
		t.Fatalf("wrapped target %s %v failed: %v\n%s", target, args, err, out)
	}
	t.Fatalf("wrapped target %s %v failed after retries: %v\n%s", target, args, lastErr, lastOut)
	return nil
}

func runWrappedTargetWithStats(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) ([]byte, traceStats) {
	t.Helper()
	statsPath := filepath.Join(t.TempDir(), "trace-stats.json")
	if opts.env == nil {
		opts.env = make(map[string]string)
	}
	opts.env["UWGS_TRACE_STATS_PATH"] = statsPath
	out := runWrappedTargetWithOptions(t, art, httpSock, transport, target, args, opts)
	data, err := os.ReadFile(statsPath)
	if err != nil {
		t.Fatalf("read trace stats: %v", err)
	}
	var stats traceStats
	if err := json.Unmarshal(data, &stats); err != nil {
		t.Fatalf("decode trace stats: %v\n%s", err, data)
	}
	if stats.Syscalls == nil {
		stats.Syscalls = make(map[string]uint64)
	}
	return out, stats
}

func transportUsesPreload(transport string) bool {
	switch transport {
	case "systrap", "combo-only", "preload+seccomp", "preload-plus-seccomp", "preload", "preload-only":
		return true
	default:
		return false
	}
}

// transportUsesPtrace reports whether a wrapper transport spawns the
// ptrace tracer. Only those transports populate UWGS_TRACE_STATS_PATH,
// so syscall-counter assertions are meaningful for them and useless
// for preload-only mode.
func transportUsesPtrace(transport string) bool {
	switch transport {
	case "ptrace", "ptrace-only", "ptrace-seccomp", "systrap":
		return true
	default:
		return false
	}
}

// transportTracerCountsHotpathSyscalls reports whether the tracer's
// per-syscall counter is expected to see hot-path syscalls (send,
// recv, read, write, poll, etc.). Only the pure ptrace modes get the
// hot-path through the tracer; systrap traps in-process via SIGSYS,
// and preload uses libc-symbol interposition with no tracer at all.
func transportTracerCountsHotpathSyscalls(transport string) bool {
	switch transport {
	case "ptrace", "ptrace-only", "ptrace-seccomp":
		return true
	default:
		return false
	}
}

func assertSyscallCount(t *testing.T, stats traceStats, name string, want uint64) {
	t.Helper()
	got := stats.Syscalls[name]
	if got != want {
		t.Fatalf("expected traced syscall %s=%d, got %d (all=%v)", name, want, got, stats.Syscalls)
	}
}

func assertSyscallAtLeast(t *testing.T, stats traceStats, name string, want uint64) {
	t.Helper()
	got := stats.Syscalls[name]
	if got < want {
		t.Fatalf("expected traced syscall %s>=%d, got %d (all=%v)", name, want, got, stats.Syscalls)
	}
}

func assertSyscallDelta(t *testing.T, baseline, stats traceStats, name string, want int64) {
	t.Helper()
	got := int64(stats.Syscalls[name]) - int64(baseline.Syscalls[name])
	if got != want {
		t.Fatalf("expected traced syscall delta %s=%d, got %d (baseline=%v current=%v)", name, want, got, baseline.Syscalls, stats.Syscalls)
	}
}

// assertSyscallDeltaAtMost lets a test express "preload should bypass
// almost everything for this syscall, but a small fixed amount of
// leakage from libc-internal callsites is acceptable." Cold→hot path
// promotion in preload causes the first I/O after connect/accept to
// reach the tracer (HotReady starts 0), and newer glibc (>= 2.40) also
// emits an extra fcntl(F_GETFL) inside fdopen/setvbuf flows that
// bypasses preload's interposition entirely. Strict delta=0 was
// fine on older glibc but breaks on 2.43+ — relax with a cap.
func assertSyscallDeltaAtMost(t *testing.T, baseline, stats traceStats, name string, want int64) {
	t.Helper()
	got := int64(stats.Syscalls[name]) - int64(baseline.Syscalls[name])
	if got < 0 || got > want {
		t.Fatalf("expected traced syscall delta %s in [0,%d], got %d (baseline=%v current=%v)", name, want, got, baseline.Syscalls, stats.Syscalls)
	}
}

func mapsEqualUint64(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for key, av := range a {
		if bv, ok := b[key]; !ok || av != bv {
			return false
		}
	}
	return true
}

func normalizedOutput(out []byte) string {
	lines := strings.Split(string(out), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "uwgwrapper:"):
			continue
		case strings.HasPrefix(trimmed, "connect fd="):
			continue
		case strings.HasPrefix(trimmed, "send fd="):
			continue
		case strings.HasPrefix(trimmed, "write fd="):
			continue
		case strings.HasPrefix(trimmed, "recv fd="):
			continue
		case strings.HasPrefix(trimmed, "read fd="):
			continue
		case strings.HasPrefix(trimmed, "manager_connect "):
			continue
		case strings.HasPrefix(trimmed, "manager_request "):
			continue
		case strings.HasPrefix(trimmed, "proxy_connect "):
			continue
		default:
			kept = append(kept, trimmed)
		}
	}
	return strings.Join(kept, "\n")
}

func retryableWrappedFailure(out []byte, err error) bool {
	if bytes.Contains(out, []byte("cannot read file data: Error 38")) {
		return true
	}
	if bytes.Contains(out, []byte("ptrace mode failed: no such process")) {
		return true
	}
	if bytes.Contains(out, []byte("worker ")) && bytes.Contains(out, []byte(" failed: ")) {
		return true
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 141 {
		return true
	}
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 127 && len(bytes.TrimSpace(out)) == 0 {
		return true
	}
	return false
}

func retryableWrappedTimeout(target, transport string, args []string) bool {
	base := filepath.Base(target)
	if base == "rawmix_client" || base == "mixed_client" || base == "raw_client" || base == "curl" {
		return true
	}
	// ptrace-only UDP iov handling is occasionally flaky on busy GNU runners; a
	// retry is cheaper than letting a single transient hang fail the full release.
	if base == "stub_client" && transport == "ptrace-only" {
		for _, arg := range args {
			if arg == "iov" {
				return true
			}
		}
	}
	return false
}

func buildWithEnv(t *testing.T, dir string, env map[string]string, name string, args ...string) {
	t.Helper()
	// Always inject -buildvcs=false directly into `go build` /
	// `go install` so the test works in containers where .git is
	// missing OR where git refuses with "dubious ownership"
	// (exit status 128). GOFLAGS is unreliable across container
	// matrices — some images pre-set it and we'd be appending; some
	// don't honor a child-set value because the parent `go test`
	// already locked in build flags. The CLI flag wins
	// unconditionally.
	if name == "go" && len(args) > 0 && (args[0] == "build" || args[0] == "install") {
		injected := append([]string{args[0], "-buildvcs=false"}, args[1:]...)
		args = injected
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{}, os.Environ()...)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}

func nonLoopbackIPv4(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil && prefix.Addr().Is4() {
				return prefix.Addr()
			}
		}
	}
	t.Skip("no non-loopback IPv4 address available for wrapper direct-fallback test")
	return netip.Addr{}
}
