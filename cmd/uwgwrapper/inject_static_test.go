// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestParseStaticBlob exercises the ELF parser end-to-end against
// the actual freestanding artifact produced by preload/build_static.sh.
// Validates that the supervisor will be able to find uwg_static_init,
// enumerate PT_LOAD segments, and compute the contiguous span
// before we wire up the ptrace injection itself.
func TestParseStaticBlob(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("static blob only built on linux")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	tmp := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(repo, "preload", "build_static.sh"), tmp)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build_static.sh failed: %v\n%s", err, out)
	}

	arch := runtime.GOARCH
	blob := filepath.Join(tmp, "uwgpreload-static-"+arch+".so")
	spec, err := parseStaticBlob(blob)
	if err != nil {
		t.Fatalf("parseStaticBlob(%s): %v", blob, err)
	}
	if spec.EntryOffset == 0 {
		t.Fatalf("uwg_static_init entry offset is zero — build artifact broken")
	}
	if len(spec.Loads) == 0 {
		t.Fatalf("blob has no PT_LOAD segments")
	}
	if spec.HighVaddr <= spec.LowVaddr {
		t.Fatalf("invalid address span: low=%#x high=%#x", spec.LowVaddr, spec.HighVaddr)
	}
	t.Logf("blob spec: entry=%#x loads=%d low=%#x high=%#x size=%d KB",
		spec.EntryOffset, len(spec.Loads), spec.LowVaddr, spec.HighVaddr,
		spec.totalSize()/1024)

	// EntryAtBase: if the blob is mmap'd at base 0x10000, entry should
	// be 0x10000 + (entry_offset - low_vaddr).
	base := uint64(0x10000)
	want := base + spec.EntryOffset - spec.LowVaddr
	if got := spec.EntryAtBase(base); got != want {
		t.Fatalf("EntryAtBase(%#x) = %#x, want %#x", base, got, want)
	}
}
