// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"runtime"
)

// Phase 2 static-binary supervisor scaffolding.
//
// Goal: when uwgwrapper is asked to wrap a static binary (no
// LD_PRELOAD path), inject our freestanding uwgpreload-static blob
// into the tracee at exec time, jump to its uwg_static_init entry,
// then let the tracee run at full speed with the in-process SIGSYS
// handler installed.
//
// Implementation ladder:
//   ✅ Step 1: freestanding.h shim
//   ✅ Step 2: custom uwg_parse_ipv6
//   ✅ Step 3: build_static.sh produces freestanding .so
//   ✅ Step 4: replace __thread + environ with portable shims
//             — zero externs in freestanding build
//   ✅ Step 5a: ELF parser scaffold (this file) — finds entry point
//             offset, enumerates PT_LOAD segments, returns relocation
//             tables for the supervisor to apply.
//   ⏳ Step 5b: remote mmap via ptrace SETREGS (allocate space in tracee)
//   ⏳ Step 5c: PTRACE_POKEDATA copy of segments + relocation fixup
//   ⏳ Step 5d: jump to uwg_static_init via PTRACE_SETREGS RIP
//   ⏳ Step 6:  validation suite: tests/preload/phase2_static_test.go

// staticBlobSpec describes everything the supervisor needs to inject
// the blob into a tracee. Computed once per uwgwrapper run and
// reused for every static-binary tracee.
type staticBlobSpec struct {
	// Path on disk (or eventually embedded bytes). Source order:
	//   1. UWGS_STATIC_BLOB env var
	//   2. preload/uwgpreload-static-${arch}.so next to uwgwrapper
	//   3. (future) //go:embed
	Path string

	// EntryOffset is uwg_static_init's offset relative to the blob's
	// load base. Set by parseStaticBlob.
	EntryOffset uint64

	// TrapOffset is uwg_static_trap's offset relative to the blob's
	// load base. The supervisor uses this as the return address when
	// handoffing into uwg_static_init, so the function's return
	// raises SIGTRAP and the supervisor regains control.
	TrapOffset uint64

	// Loads is the ordered list of PT_LOAD segments. The supervisor
	// allocates a single contiguous mapping of (HighVaddr-LowVaddr)
	// in the tracee and copies each segment to (base + p.Vaddr -
	// LowVaddr).
	Loads []elf.ProgHeader

	// Relocations: list of RELA entries to apply after segment copy.
	// For PIE blobs, these are mostly R_X86_64_RELATIVE / R_AARCH64_
	// RELATIVE — add base to a pointer field.
	Relocations []elf.Rela64

	// LowVaddr and HighVaddr define the address range the blob spans.
	// Total mmap size = HighVaddr - LowVaddr (rounded up to page).
	LowVaddr, HighVaddr uint64
}

// staticBlobPath picks the blob path per platform. Source order:
//  1. UWGS_STATIC_BLOB env var (explicit override).
//  2. cmd/uwgwrapper/assets/uwgpreload-static-${arch}.so produced
//     by preload/build_static.sh during the wrapper build (sibling
//     to the wrapper binary or in CWD/cmd/uwgwrapper/assets).
//
// Embedding via //go:embed is a planned follow-up — currently the
// build flow runs build_static.sh before `go build` and the
// resulting .so is placed next to the wrapper binary or in the
// repo's cmd/uwgwrapper/assets/.
func staticBlobPath() string {
	if p := os.Getenv("UWGS_STATIC_BLOB"); p != "" {
		return p
	}
	exe, _ := os.Executable()
	exeDir := ""
	if exe != "" {
		for i := len(exe) - 1; i >= 0; i-- {
			if exe[i] == '/' {
				exeDir = exe[:i+1]
				break
			}
		}
	}
	var name string
	switch runtime.GOARCH {
	case "amd64":
		name = "uwgpreload-static-amd64.so"
	case "arm64":
		name = "uwgpreload-static-arm64.so"
	default:
		return ""
	}
	for _, candidate := range []string{
		exeDir + name,
		exeDir + "assets/" + name,
		"cmd/uwgwrapper/assets/" + name,
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return ""
}

// parseStaticBlob loads the blob from disk and extracts everything
// the supervisor needs. Idempotent — safe to call once at uwgwrapper
// startup.
func parseStaticBlob(path string) (*staticBlobSpec, error) {
	if path == "" {
		return nil, errors.New("no static blob path configured")
	}
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	spec := &staticBlobSpec{Path: path}

	// Find the uwg_static_init entry point in the dynamic symbol table.
	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("read dynamic symbols: %w", err)
	}
	for _, s := range syms {
		switch s.Name {
		case "uwg_static_init":
			spec.EntryOffset = s.Value
		case "uwg_static_trap":
			spec.TrapOffset = s.Value
		}
	}
	if spec.EntryOffset == 0 {
		return nil, errors.New("uwg_static_init not exported by blob — build_static.sh produced a broken artifact")
	}
	if spec.TrapOffset == 0 {
		return nil, errors.New("uwg_static_trap not exported by blob — build_static.sh produced a broken artifact")
	}

	// Collect PT_LOAD segments and the address span they cover.
	first := true
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		spec.Loads = append(spec.Loads, p.ProgHeader)
		if first || p.Vaddr < spec.LowVaddr {
			spec.LowVaddr = p.Vaddr
			first = false
		}
		end := p.Vaddr + p.Memsz
		if end > spec.HighVaddr {
			spec.HighVaddr = end
		}
	}
	if len(spec.Loads) == 0 {
		return nil, errors.New("blob has no PT_LOAD segments")
	}

	// TODO Step 5b: parse .rela.dyn for RELA entries the supervisor
	// applies post-copy. For an -fPIC freestanding .so produced by
	// build_static.sh, these are typically R_X86_64_RELATIVE for the
	// few static-pointer fields (e.g., __dso_handle if any).

	return spec, nil
}

// totalSize returns the bytes the supervisor must mmap in the tracee.
func (s *staticBlobSpec) totalSize() uint64 {
	span := s.HighVaddr - s.LowVaddr
	// Round up to page (4K is universal; arm64 is sometimes 16K but
	// 4K alignment always works for mmap).
	const pageMask = uint64(4095)
	return (span + pageMask) &^ pageMask
}

// EntryAtBase returns the absolute address of uwg_static_init given
// the base mmap address chosen for the blob in the tracee.
func (s *staticBlobSpec) EntryAtBase(base uint64) uint64 {
	return base + (s.EntryOffset - s.LowVaddr)
}
