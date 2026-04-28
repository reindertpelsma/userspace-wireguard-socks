// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && amd64

package main

import "golang.org/x/sys/unix"

// x86_64 syscall ABI: nr=rax, args = rdi rsi rdx r10 r8 r9.
// Result in rax.
func loadSyscallRegs(regs *unix.PtraceRegs, nr uintptr, args [6]uintptr) {
	regs.Rax = uint64(nr)
	regs.Rdi = uint64(args[0])
	regs.Rsi = uint64(args[1])
	regs.Rdx = uint64(args[2])
	regs.R10 = uint64(args[3])
	regs.R8 = uint64(args[4])
	regs.R9 = uint64(args[5])
	// Original_rax is what the kernel uses to restart syscalls;
	// setting it to nr keeps our intended syscall coherent.
	regs.Orig_rax = uint64(nr)
}

func readSyscallResult(regs *unix.PtraceRegs) uintptr {
	return uintptr(regs.Rax)
}

func getPC(regs *unix.PtraceRegs) uint64 { return regs.Rip }
func getSP(regs *unix.PtraceRegs) uint64 { return regs.Rsp }
func setSP(regs *unix.PtraceRegs, sp uint64) { regs.Rsp = sp }
func getArchName() string                { return "amd64" }

// setupHandoff: set RIP=entry, push return_addr on stack, set arg regs
// rdi/rsi/rdx = (0, 0, 0). amd64 calling convention: caller pushes
// return address before call; we simulate that by writing return_addr
// at *(rsp) and decrementing rsp by 8.
func setupHandoff(regs *unix.PtraceRegs, entry, retAddr uint64) {
	regs.Rsp -= 8
	regs.Rip = entry
	regs.Rdi = 0 // argc
	regs.Rsi = 0 // argv
	regs.Rdx = 0 // envp
}

func setupHandoffWithEnvp(regs *unix.PtraceRegs, entry, retAddr, envp uint64) {
	regs.Rsp -= 8
	regs.Rip = entry
	regs.Rdi = 0    // argc
	regs.Rsi = 0    // argv
	regs.Rdx = envp // envp
}
