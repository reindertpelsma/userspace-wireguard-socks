// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPhase1FxlockStress compiles and runs the C-level futex rwlock
// stress test (preload/core/tests/fxlock_stress.c). 32 threads × 100k
// ops each, mixed reader/writer, with each writer leaving a per-thread
// marker that subsequent same-window reads must see consistently.
//
// Any "wrong=N" output with N > 0 indicates a torn read or a write
// landing inside another thread's critical section — i.e., the lock
// is broken. 3.2M ops with wrong=0 is the bar.
func TestPhase1FxlockStress(t *testing.T) {
	requirePhase1Toolchain(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	bin := filepath.Join(t.TempDir(), "fxlock_stress")
	src := filepath.Join("preload", "core", "tests", "fxlock_stress.c")
	cmd := exec.Command("gcc", "-O2", "-D_GNU_SOURCE", "-pthread",
		"-I", "preload/core", "-I", "preload", "-o", bin, src)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fxlock_stress.c: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		t.Fatalf("fxlock_stress run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "wrong=0") {
		t.Fatalf("fxlock stress detected races: %s", out)
	}
	t.Logf("fxlock stress: %s", strings.TrimSpace(string(out)))
}

// TestPhase1CacheRaceStress drives the actual shared_state.c
// per-fd-locked cache via uwg_state_store / lookup / clear from many
// threads on overlapping fds. Each store stamps a marker into
// saved_fl; each subsequent lookup must see a self-consistent
// snapshot (no mixed-writer fields) — torn=0 is the bar.
//
// This is the integration test the user's spec calls out: hammers
// concurrent socket/connect/close on the same fd from multiple
// threads. With per-fd rwlock + race_close, the legacy
// torn-read class of races is eliminated.
func TestPhase1CacheRaceStress(t *testing.T) {
	requirePhase1Toolchain(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	bin := filepath.Join(t.TempDir(), "cache_race_stress")
	cmd := exec.Command("gcc", "-O2", "-D_GNU_SOURCE", "-pthread",
		"-I", "preload/core", "-I", "preload",
		"-o", bin,
		"preload/core/tests/cache_race_stress.c",
		"preload/core/shared_state.c",
		"preload/core/freestanding_runtime.c")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile cache_race_stress.c: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		t.Fatalf("cache_race_stress run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "torn=0") {
		t.Fatalf("cache stress detected torn reads: %s", out)
	}
	t.Logf("cache race stress: %s", strings.TrimSpace(string(out)))
}
