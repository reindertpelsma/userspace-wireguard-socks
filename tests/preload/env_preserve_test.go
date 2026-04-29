// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSystrapSupervisedPreservesUWGSEnvAcrossExecveWithEmptyEnv pins the
// supervisor's force-preserve-env behavior at the execve seccomp-event
// stop. The fixture (env_drop_and_check.c) re-execs itself with envp =
// {NULL}, simulating a chromium-sandbox / sudo style env scrub. The
// child counts UWGS_* env vars + LD_PRELOAD; absent the supervisor's
// preserveUWGSEnvAtExecve fix the count is 0 and the fixture exits 2.
//
// With the fix, the supervisor:
//   1. Catches PTRACE_EVENT_SECCOMP for execve before the kernel
//      processes it.
//   2. Reads the tracee's envp via PtracePeekData.
//   3. mmaps a buffer in the tracee via remoteSyscall(SYS_mmap).
//   4. Writes a merged envp (existing pointers + injected UWGS_*/
//      LD_PRELOAD strings) into the buffer.
//   5. Rewrites the syscall's envp arg to point at the buffer.
//   6. Continues execve.
//
// Pins the contract that wrapper-tracked sessions survive programs
// that rebuild envp from scratch.
func TestSystrapSupervisedPreservesUWGSEnvAcrossExecveWithEmptyEnv(t *testing.T) {
	t.Skip("env-preserve full integration deferred: needs syscall-hijack at SECCOMP-event (orig_rax=-1 cancel + mmap + re-issue execve) + supervisor access to spawn env. Scaffolding in exec_env_inject.go, design tracked in #91.")
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	// Short tmp path so the unix-socket fdproxy.sock fits within the
	// 108-byte sun_path limit. t.TempDir() bakes the full test name
	// into the path which blows the limit on Go's auto-generated
	// per-test directories.
	tmp, err := os.MkdirTemp(os.TempDir(), "uwgs-env")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })

	bin := filepath.Join(tmp, "env_drop_and_check")
	build := exec.Command("gcc", "-O2", "-Wall", "-Wextra", "-o", bin,
		filepath.Join(repo, "tests/preload/testdata/env_drop_and_check.c"))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("gcc env_drop_and_check: %v\n%s", err, out)
	}

	wrapperArgs := []string{
		"--transport=systrap-supervised",
		"--listen", filepath.Join(tmp, "fdproxy.sock"),
		"--api", "unix:" + httpSock,
		"--socket-path", "/uwg/socket",
		"--", bin, bin,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, art.wrapper, wrapperArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, runErr := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("supervisor run timed out\noutput=%s", out)
	}
	if runErr != nil {
		t.Fatalf("supervisor run failed: %v\noutput=%s", runErr, out)
	}
	o := string(out)
	if !strings.Contains(o, "UWGS_COUNT=") {
		t.Fatalf("child fixture didn't print UWGS_COUNT — execve may have failed\noutput=%s", o)
	}
	// We pin LD_PRELOAD=1 because the wrapper sets that env and
	// dropping it silently disables interception. The fixture exits
	// 2 when UWGS_COUNT=0, so reaching success means at least one
	// UWGS_* var survived.
	if !strings.Contains(o, "LD_PRELOAD=1") {
		t.Fatalf("LD_PRELOAD env was not preserved across execve\noutput=%s", o)
	}
}
