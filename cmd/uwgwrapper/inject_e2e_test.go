// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPhase2InjectAndRunStaticInit is the Phase 2 step 5c+5d
// integration test:
//   1. Build the freestanding blob via build_static.sh.
//   2. Spawn /bin/sleep, attach via PTRACE_SEIZE+INTERRUPT.
//   3. parseStaticBlob → loadBlobIntoTracee → runStaticInit.
//   4. Assert uwg_static_init returned a non-fatal value
//      (-EINVAL is fine — it just means uwg_core_init failed because
//      no UWGS_TRACE_SECRET, NOT that injection broke).
//
// The point of this test is NOT to exercise tunnel functionality
// end-to-end (that's step 6). It's to confirm the injection
// machinery — mmap, segment copy, relocations, RIP handoff,
// return-trap — all work cleanly.
func TestPhase2InjectAndRunStaticInit(t *testing.T) {
	if testing.Short() {
		t.Skip("blob injection test requires ptrace+mmap into a live process; skipped in -short mode")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	tmp := t.TempDir()
	build := exec.Command("bash", filepath.Join(repo, "preload", "build_static.sh"), tmp)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_static.sh failed: %v\n%s", err, out)
	}
	blob := filepath.Join(tmp, "uwgpreload-static-"+runtime.GOARCH+".so")
	spec, err := parseStaticBlob(blob)
	if err != nil {
		t.Fatalf("parseStaticBlob: %v", err)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid, cleanup := attachAndStop(t)
	defer cleanup()

	base, err := loadBlobIntoTracee(pid, spec)
	if err != nil {
		t.Fatalf("loadBlobIntoTracee: %v", err)
	}
	t.Logf("blob loaded into tracee at base=%#x size=%d KB",
		base, spec.totalSize()/1024)

	rc, err := runStaticInit(pid, spec, base)
	if err != nil {
		t.Fatalf("runStaticInit: %v", err)
	}
	t.Logf("uwg_static_init returned %d", rc)
	// rc == 0  → init succeeded (would happen if UWGS_TRACE_SECRET set)
	// rc == -22 (-EINVAL) → init failed at the secret check, but the
	//   blob ran cleanly and returned. That's the success bar for
	//   this injection-machinery test.
	if rc != 0 && rc != -22 {
		t.Fatalf("uwg_static_init returned unexpected value %d (expected 0 or -EINVAL=-22)", rc)
	}
}
