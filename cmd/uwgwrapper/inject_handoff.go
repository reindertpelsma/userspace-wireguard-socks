// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// Phase 2 step 5d: RIP handoff to uwg_static_init.
//
// After loadBlobIntoTracee returns, the supervisor knows the base
// address. To run uwg_static_init in the tracee:
//
//   1. Set RIP/PC to (base + spec.EntryOffset - spec.LowVaddr).
//   2. Set RDI/X0 = argc, RSI/X1 = argv pointer, RDX/X2 = envp pointer.
//      For Phase 2's first cut we pass 0/NULL for all three; uwg_static_init
//      tolerates NULL envp (will fall back to other env-discovery paths).
//   3. Reserve a 16-byte stack slot for the return address pointing at
//      a known sentinel (a single SIGTRAP-equivalent instruction at a
//      known address). When uwg_static_init returns it'll trap there
//      and the supervisor regains control.
//
// For a true static-binary handoff (running the program after init),
// the supervisor would set the return target to the original AT_ENTRY
// from auxv. For the validation test, we set it to a sentinel address
// so we can confirm uwg_static_init returned cleanly.

// runStaticInit invokes uwg_static_init(0, NULL, NULL) in the tracee
// and returns the function's return value (uwg_core_init's status:
// 0 on success or -errno on failure).
//
// Strategy: write a 1-byte int3 (or arm64 brk #0) instruction into
// the tracee's stack as the return target. Set up the call stack so
// the function ABI's "return" pops that address and traps. The
// supervisor catches the trap, reads RAX/X0 for the result, restores
// the original register state, and returns.
func runStaticInit(pid int, spec *staticBlobSpec, base uintptr) (int64, error) {
	// Save current regs.
	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceGetRegs: %w", err)
	}

	// Reserve a 16-byte aligned scratch slot on the stack (used for
	// the saved return address on amd64).
	regs := saved
	sp := getSP(&regs)
	sp -= 64
	sp &^= 15
	setSP(&regs, sp)

	// The return target is uwg_static_trap inside the blob's
	// executable text segment — int3/brk #0 instructions that raise
	// SIGTRAP for the supervisor to catch. Putting it on the stack
	// would hit NX (kernel returns SIGSEGV not SIGTRAP).
	trapAddr := uintptr(base + uintptr(spec.TrapOffset-spec.LowVaddr))

	// Set return target + entry-point + arg regs.
	entry := uint64(base + uintptr(spec.EntryOffset-spec.LowVaddr))
	setupHandoff(&regs, entry, uint64(trapAddr))

	// On amd64 the function call ABI requires the return address on
	// the stack at [rsp]. arm64 sets x30 (LR) directly, no push needed.
	if getArchName() == "amd64" {
		var retBytes [8]byte
		for i := 0; i < 8; i++ {
			retBytes[i] = byte(uint64(trapAddr) >> (i * 8))
		}
		// setupHandoff already decremented rsp by 8 on amd64.
		if err := writeMem(pid, uintptr(getSP(&regs)), retBytes[:]); err != nil {
			return 0, fmt.Errorf("write return addr to stack: %w", err)
		}
	}

	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return 0, fmt.Errorf("PtraceSetRegs handoff: %w", err)
	}

	// Continue and wait for the int3/brk trap.
	if err := unix.PtraceCont(pid, 0); err != nil {
		return 0, fmt.Errorf("PtraceCont: %w", err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("Wait4 after handoff: %w", err)
	}
	if !ws.Stopped() {
		return 0, fmt.Errorf("tracee not stopped after handoff (status=%v)", ws)
	}
	if ws.StopSignal() != syscall.SIGTRAP {
		var crashRegs unix.PtraceRegs
		_ = unix.PtraceGetRegs(pid, &crashRegs)
		return 0, fmt.Errorf("unexpected stop signal after handoff: %v (expected SIGTRAP); pc=%#x sp=%#x",
			ws.StopSignal(), getPC(&crashRegs), getSP(&crashRegs))
	}

	// Read return value (RAX/X0). uwg_static_init returns C `int`
	// (32-bit) so the high 32 bits of RAX/X0 are caller-set garbage
	// per the ABI. Sign-extend the low 32.
	var post unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &post); err != nil {
		return 0, fmt.Errorf("PtraceGetRegs post-handoff: %w", err)
	}
	rc := int64(int32(readSyscallResult(&post)))

	// Restore registers.
	if err := unix.PtraceSetRegs(pid, &saved); err != nil {
		return rc, fmt.Errorf("PtraceSetRegs restore: %w", err)
	}
	return rc, nil
}
