// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// Phase 2 step 5b: remote-syscall primitive.
//
// Executes one syscall in the tracee's address space from the
// supervisor. The tracee must be in a ptrace-stop (e.g., post-execve
// or syscall-entry stop) when this is called.
//
// Algorithm:
//   1. Save the tracee's register state.
//   2. Locate or write a syscall instruction in the tracee.
//   3. Set PC/RIP to that instruction; load syscall number + args
//      into the ABI-mandated registers.
//   4. PTRACE_SINGLESTEP — kernel executes the instruction.
//   5. Wait for the post-syscall stop, read the return value from
//      RAX/X0.
//   6. Restore the original registers (and original bytes if we
//      overwrote any).
//
// We pick the instruction location by overwriting 4 bytes at the
// tracee's current PC with the architecture's syscall opcode, then
// restoring after. Both x86_64's `0F 05` and arm64's `D4 00 00 01`
// fit. PC is guaranteed to be on an executable page since we're
// in a ptrace-stop on a running process.

const (
	x86SyscallOpcode  = uint32(0x000005_0F)       // 0F 05 (low 16 bits)
	arm64SVC0Encoding = uint32(0xD4000001)        // svc #0
)

// remoteSyscall executes one syscall inside the ptraced tracee and
// returns its return value (or -errno as a negative number, mirroring
// the kernel's raw return).
//
// `pid` must be a stopped tracee. The syscall is identified by `nr`
// with up to 6 args.
func remoteSyscall(pid int, nr uintptr, args ...uintptr) (uintptr, error) {
	if len(args) > 6 {
		return 0, fmt.Errorf("remoteSyscall: max 6 args, got %d", len(args))
	}
	var padded [6]uintptr
	for i, a := range args {
		padded[i] = a
	}

	// Save current regs so we can restore at the end.
	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceGetRegs: %w", err)
	}

	// Save the bytes we're about to overwrite.
	pc := getPC(&saved)
	var origInsn [8]byte
	if _, err := unix.PtracePeekData(pid, uintptr(pc), origInsn[:]); err != nil {
		return 0, fmt.Errorf("PtracePeekData orig: %w", err)
	}

	// Overlay the syscall instruction.
	var insn [8]byte
	copy(insn[:], origInsn[:])
	switch runtime.GOARCH {
	case "amd64":
		insn[0] = 0x0F
		insn[1] = 0x05
	case "arm64":
		// little-endian arm64 word: D4 00 00 01 → 01 00 00 D4
		insn[0] = 0x01
		insn[1] = 0x00
		insn[2] = 0x00
		insn[3] = 0xD4
	}
	if _, err := unix.PtracePokeData(pid, uintptr(pc), insn[:]); err != nil {
		return 0, fmt.Errorf("PtracePokeData syscall: %w", err)
	}

	// Build the register state for the syscall, preserving everything
	// except the syscall ABI registers + PC.
	regs := saved
	loadSyscallRegs(&regs, nr, padded)

	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("PtraceSetRegs: %w", err)
	}

	// Single-step the syscall.
	if err := unix.PtraceSingleStep(pid); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("PtraceSingleStep: %w", err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("Wait4 after syscall: %w", err)
	}
	if !ws.Stopped() {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("tracee not stopped after syscall (status=%v)", ws)
	}

	// Read result.
	var post unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &post); err != nil {
		_, _ = unix.PtracePokeData(pid, uintptr(pc), origInsn[:])
		return 0, fmt.Errorf("PtraceGetRegs post: %w", err)
	}

	// Restore the overwritten bytes.
	if _, err := unix.PtracePokeData(pid, uintptr(pc), origInsn[:]); err != nil {
		return 0, fmt.Errorf("PtracePokeData restore: %w", err)
	}

	// Restore the saved registers.
	if err := unix.PtraceSetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceSetRegs restore: %w", err)
	}

	return readSyscallResult(&post), nil
}
