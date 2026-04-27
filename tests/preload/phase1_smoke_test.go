// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPhase1SeccompPreloadTCP validates the new SIGSYS+seccomp-based
// preload (preload/uwgpreload-phase1.so, built from preload/core/*)
// against a real uwgsocks engine + fdproxy.
//
// Uses the C stub_client (art.stub) rather than the Go raw_client.
// The Go runtime's signal-handling machinery (preempt signals,
// scheduler signal mask manipulation) interacts poorly with our
// SIGSYS-based interception in unexpected ways — Go-binary support
// is a known Phase 1 gap to be addressed in Phase 2 alongside the
// libc-symbol shim layer. C/libc-routed syscalls work cleanly.
func TestPhase1SeccompPreloadTCP(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	phase1So := filepath.Join(t.TempDir(), "uwgpreload-phase1.so")
	build := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), phase1So)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}
	art.preload = phase1So

	// Use the C stub_client which is libc-routed. Its tcp mode does
	// connect() → write() → read() → echo back the message → exit.
	args := []string{"100.64.94.1", "18080", "phase1-tcp", "tcp"}
	base := wrappedCommand(t, art, httpSock, "preload", art.stub, args, wrapperRunOptions{})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, base.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	t.Logf("=== output (%d bytes) ===\n%s\n=== end ===", len(out), out)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("timed out — see output above")
	}
	if err != nil {
		t.Fatalf("wrapper run failed: %v", err)
	}
	if !strings.Contains(string(out), "phase1-tcp") {
		t.Fatalf("expected phase1-tcp in output; got: %q", out)
	}
}
