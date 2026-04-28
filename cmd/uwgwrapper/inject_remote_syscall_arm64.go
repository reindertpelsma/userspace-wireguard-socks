// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && arm64

package main

import "golang.org/x/sys/unix"

// arm64 syscall ABI: nr=x8, args = x0 x1 x2 x3 x4 x5. Result in x0.
func loadSyscallRegs(regs *unix.PtraceRegs, nr uintptr, args [6]uintptr) {
	regs.Regs[8] = uint64(nr)
	for i := 0; i < 6; i++ {
		regs.Regs[i] = uint64(args[i])
	}
}

func readSyscallResult(regs *unix.PtraceRegs) uintptr {
	return uintptr(regs.Regs[0])
}

func getPC(regs *unix.PtraceRegs) uint64 { return regs.Pc }
func getSP(regs *unix.PtraceRegs) uint64 { return regs.Sp }
func setSP(regs *unix.PtraceRegs, sp uint64) { regs.Sp = sp }
func getArchName() string                { return "arm64" }

// arm64 ABI: function call sets x30 (LR) to return addr, no stack push.
// Args go in x0..x7.
func setupHandoff(regs *unix.PtraceRegs, entry, retAddr uint64) {
	regs.Pc = entry
	regs.Regs[30] = retAddr // LR
	regs.Regs[0] = 0
	regs.Regs[1] = 0
	regs.Regs[2] = 0
}

func setupHandoffWithEnvp(regs *unix.PtraceRegs, entry, retAddr, envp uint64) {
	regs.Pc = entry
	regs.Regs[30] = retAddr
	regs.Regs[0] = 0
	regs.Regs[1] = 0
	regs.Regs[2] = envp
}
