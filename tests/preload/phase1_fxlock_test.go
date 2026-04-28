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

// TestPhase1FxlockContentionStress drives a small pool of fxlocks
// (smaller than the thread count, so contention is forced) with
// randomized op selection (rd / wr / try_wr at realistic ratios).
// Invariants checked per-op and aggregated:
//   - Under wrlock: holder_count must be exactly 1.
//   - Under rdlock: holder_count >= 1, writer_marker == 0.
//   - Within an rdlock window: shared_value is byte-stable.
//   - try_wr OK only when nobody else holds.
//   - All locks fully drain at end of run (no leftover holders).
//
// This catches contention-pool race classes that the single-lock
// fxlock_stress doesn't exercise: cross-lock interactions, retry-
// loop wake-up correctness, and the rdlock-decrement-to-zero
// FUTEX_WAKE path the user spotted.
func TestPhase1FxlockContentionStress(t *testing.T) {
	requirePhase1Toolchain(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	bin := filepath.Join(t.TempDir(), "fxlock_contention_stress")
	src := filepath.Join("preload", "core", "tests", "fxlock_contention_stress.c")
	cmd := exec.Command("gcc", "-O2", "-D_GNU_SOURCE", "-pthread",
		"-I", "preload/core", "-I", "preload", "-o", bin, src)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile fxlock_contention_stress.c: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		t.Fatalf("fxlock_contention_stress run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "RESULT OK") {
		t.Fatalf("fxlock contention stress detected violations: %s", out)
	}
	t.Logf("fxlock contention stress:\n%s", strings.TrimSpace(string(out)))
}

// TestPhase1FxlockContentionStressMean is the same harness compiled
// at a meaner contention ratio (32 threads × 4 locks × 300k ops =
// 9.6M ops with 8:1 contention) — slow path validation. Skipped in
// short mode.
func TestPhase1FxlockContentionStressMean(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping mean-config fxlock stress in -short mode")
	}
	requirePhase1Toolchain(t)
	repo := filepath.Clean(filepath.Join("..", ".."))
	bin := filepath.Join(t.TempDir(), "fxlock_contention_mean")
	src := filepath.Join("preload", "core", "tests", "fxlock_contention_stress.c")
	cmd := exec.Command("gcc", "-O2", "-D_GNU_SOURCE",
		"-DN_THREADS=32", "-DN_LOCKS=4", "-DN_OPS_PER_THREAD=300000",
		"-pthread", "-I", "preload/core", "-I", "preload", "-o", bin, src)
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile mean-config: %v\n%s", err, out)
	}
	out, err := exec.Command(bin).CombinedOutput()
	if err != nil {
		t.Fatalf("mean-config run failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "RESULT OK") {
		t.Fatalf("mean-config detected violations: %s", out)
	}
	t.Logf("fxlock contention mean:\n%s", strings.TrimSpace(string(out)))
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
