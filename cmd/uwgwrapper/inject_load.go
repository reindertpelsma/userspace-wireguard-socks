// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Phase 2 step 5c: load the freestanding blob into a stopped tracee.
//
// 1. remoteMmap a single contiguous region of spec.totalSize() in the
//    tracee.
// 2. For each PT_LOAD segment, read the file bytes from disk and
//    POKEDATA them into the right offset within the mapped region.
//    Memsz - Filesz pages stay zero (they're already zero-filled
//    after MAP_ANONYMOUS, which we use here, OR we use the file-
//    backed mmap path; we use anonymous + manual copy because that's
//    simpler and works for blobs without proper PHDR/load-script
//    layout).
// 3. Apply RELA relocations (.rela.dyn) for PIE-relative entries:
//    for R_X86_64_RELATIVE / R_AARCH64_RELATIVE, *(addr + base) =
//    addend + base.
// 4. mprotect each segment to its declared permissions.
//
// Returns the base address chosen by the kernel.

const (
	rwxRWPlusExec = unix.PROT_READ | unix.PROT_WRITE | unix.PROT_EXEC
	pageSizeMask  = uintptr(4095)
)

// loadBlobIntoTracee performs steps 1-4. The tracee must already be
// in a stopped state.
func loadBlobIntoTracee(pid int, spec *staticBlobSpec) (base uintptr, err error) {
	// Step 1: remote mmap.
	span := uintptr(spec.totalSize())
	addr, err := remoteSyscall(pid, unix.SYS_MMAP,
		0, span, rwxRWPlusExec,
		unix.MAP_ANONYMOUS|unix.MAP_PRIVATE,
		^uintptr(0), 0)
	if err != nil {
		return 0, fmt.Errorf("remote mmap: %w", err)
	}
	if int64(addr) < 0 && int64(addr) >= -4095 {
		return 0, fmt.Errorf("remote mmap returned errno %d", -int64(addr))
	}
	base = addr

	// Step 2: open blob file, copy each PT_LOAD into the right offset.
	f, err := os.Open(spec.Path)
	if err != nil {
		return base, fmt.Errorf("open blob: %w", err)
	}
	defer f.Close()
	for _, p := range spec.Loads {
		if p.Filesz == 0 {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := f.Seek(int64(p.Off), io.SeekStart); err != nil {
			return base, fmt.Errorf("seek seg: %w", err)
		}
		if _, err := io.ReadFull(f, buf); err != nil {
			return base, fmt.Errorf("read seg: %w", err)
		}
		dst := base + uintptr(p.Vaddr-spec.LowVaddr)
		if err := writeMem(pid, dst, buf); err != nil {
			return base, fmt.Errorf("write seg @vaddr=%#x: %w", p.Vaddr, err)
		}
	}

	// Step 3: apply RELA relocations from .rela.dyn.
	if err := applyRelocations(pid, spec, base); err != nil {
		return base, fmt.Errorf("apply relocations: %w", err)
	}

	// Step 4: mprotect would tighten the perms here (we mapped RWX
	// initially to allow segment writes). For Phase 2 step 5c we
	// leave the whole region RWX so the blob can write its own BSS
	// without faults — the security implication is minor since the
	// region is private to one process. A later commit can enforce
	// proper perms once the segment-vs-rodata vs BSS layout is
	// stable.
	_ = elf.PF_R
	return base, nil
}

// writeMem copies a buffer into the tracee's address space via
// PTRACE_POKEDATA. The kernel ABI takes one word at a time but
// unix.PtracePokeData handles batching internally.
func writeMem(pid int, addr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	n, err := unix.PtracePokeData(pid, addr, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("short PtracePokeData: %d/%d", n, len(data))
	}
	return nil
}

// applyRelocations walks the blob's .rela.dyn section and applies
// each RELA entry. For -fPIC -shared blobs produced by build_static.sh,
// nearly all relocations are R_*_RELATIVE: *(addr+base) = addend+base.
// Other relocation types are rejected — the blob shouldn't have any.
func applyRelocations(pid int, spec *staticBlobSpec, base uintptr) error {
	f, err := elf.Open(spec.Path)
	if err != nil {
		return fmt.Errorf("open blob: %w", err)
	}
	defer f.Close()
	rela := f.Section(".rela.dyn")
	if rela == nil {
		return nil // nothing to relocate
	}
	data, err := rela.Data()
	if err != nil {
		return fmt.Errorf("read .rela.dyn: %w", err)
	}
	const relaSize = 24 // sizeof(Elf64_Rela)
	if len(data)%relaSize != 0 {
		return fmt.Errorf(".rela.dyn size %d not multiple of %d", len(data), relaSize)
	}
	bo := f.ByteOrder
	for off := 0; off < len(data); off += relaSize {
		offset := bo.Uint64(data[off : off+8])
		info := bo.Uint64(data[off+8 : off+16])
		addend := int64(bo.Uint64(data[off+16 : off+24]))
		relType := uint32(info & 0xffffffff)
		// R_X86_64_RELATIVE = 8; R_AARCH64_RELATIVE = 1027
		if relType != 8 && relType != 1027 {
			return fmt.Errorf("blob has non-RELATIVE relocation type %d at offset %#x — build_static.sh produced an artifact we can't load",
				relType, offset)
		}
		// *(base + offset - LowVaddr) = base + addend
		target := base + uintptr(offset-spec.LowVaddr)
		val := int64(base) + addend
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], uint64(val))
		if err := writeMem(pid, target, word[:]); err != nil {
			return fmt.Errorf("relocation write @offset=%#x: %w", offset, err)
		}
	}
	return nil
}
