//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestPtraceNonblockConnectFlow pins the bare-ptrace TCP-connect
// flow that curl + every modern HTTP client takes:
//
//	socket(SOCK_STREAM[+SOCK_NONBLOCK])  // or fcntl(F_SETFL, O_NONBLOCK)
//	connect()                            // → EINPROGRESS for non-blocking
//	poll(POLLOUT)
//	getsockopt(SO_ERROR)                 // → 0
//	send(GET request)
//	recv(response)
//	recv() again                         // → EAGAIN on non-blocking
//	close()
//
// The 20-line C reproducer in testdata/connect_repro.c walks the
// flow and exits 0 on success. We exercise it across all 5 wrapper
// transports × 3 socket modes (sock-nonblock, fcntl, blocking) so
// regressions in any of:
//   - non-blocking connect not returning EINPROGRESS,
//   - poll/getsockopt not flagging the connect ready,
//   - the localFD blocking on recv when the tracee fd is O_NONBLOCK
//     (the curl hang we hit on real-Linux glibc 2.43, where the
//     tracer's handleRecvfrom blocked forever waiting for "more
//     data" on a connection that had already delivered everything),
// fail one named subtest instead of an opaque suite-level hang.
func TestPtraceNonblockConnectFlow(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)
	repro := filepath.Join(t.TempDir(), "connect_repro")
	repo := filepath.Clean(filepath.Join("..", ".."))
	build := exec.Command("gcc", "-O2", "-Wall", "-o", repro, "tests/preload/testdata/connect_repro.c")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build connect_repro: %v\n%s", err, out)
	}
	for _, transport := range []string{"preload", "systrap", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		for _, mode := range []string{"sock-nonblock", "fcntl", "blocking"} {
			t.Run(transport+"/"+mode, func(t *testing.T) {
				// Bumped from 30s — ptrace-only mode on GH runners
				// occasionally exceeds 30s under CPU contention; the
				// per-syscall ptrace round-trip multiplies anything
				// that's already slow. Self-hosted + dev hosts complete
				// in <0.1s, so 90s is generous.
				out := runWrappedTargetWithOptions(t, art, httpSock, transport, repro,
					[]string{"100.64.94.1", "18080", mode},
					wrapperRunOptions{timeout: 90 * time.Second})
				// "OK got N bytes" is the success sentinel from the
				// reproducer. Anything else (FAIL ..., a hang, an
				// empty stdout) means a real regression.
				if !bytes.Contains(out, []byte("OK got")) {
					t.Fatalf("connect+round-trip on %s/%s did not complete; got:\n%s", transport, mode, out)
				}
			})
		}
	}
}
