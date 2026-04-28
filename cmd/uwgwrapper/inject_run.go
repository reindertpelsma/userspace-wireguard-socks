// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// runStaticPreload is the transport=preload-static entry point.
//
//   1. fork + exec the target with PTRACE_TRACEME so the parent
//      becomes its tracer.
//   2. Wait for the post-execve stop (signal-stop with SIGTRAP).
//   3. Read the tracee's auxv to find AT_ENTRY (saved_start).
//   4. Read the tracee's stack to find argc/argv/envp pointers.
//   5. Load the blob into the tracee (loadBlobIntoTracee).
//   6. Run uwg_static_init(0, NULL, envp) (runStaticInit overload).
//   7. PTRACE_DETACH — the tracee resumes its original _start with
//      our SIGSYS handler + seccomp filter installed.
func runStaticPreload(target string, args []string, env []string,
	blobPath string) error {

	// Step 1: spawn the child with PTRACE_TRACEME.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command(target, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace:    true,             // PTRACE_TRACEME in child before exec
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start target: %w", err)
	}
	pid := cmd.Process.Pid

	// Step 2: wait for the post-execve stop.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("Wait4 post-exec: %w", err)
	}
	if !ws.Stopped() {
		return fmt.Errorf("tracee exited before stop: %v", ws)
	}

	// Step 3+4: read auxv and the tracee stack.
	envpPtr, err := readEnvpPointer(pid)
	if err != nil {
		return fmt.Errorf("locate envp on tracee stack: %w", err)
	}

	// Step 5: parse + load the blob.
	spec, err := parseStaticBlob(blobPath)
	if err != nil {
		return fmt.Errorf("parse blob: %w", err)
	}
	base, err := loadBlobIntoTracee(pid, spec)
	if err != nil {
		return fmt.Errorf("load blob: %w", err)
	}

	// Step 6: run uwg_static_init with the real envp.
	rc, err := runStaticInitWithEnvp(pid, spec, base, envpPtr)
	if err != nil {
		return fmt.Errorf("runStaticInit: %w", err)
	}
	// rc == 0 → init succeeded; rc < 0 means tunnel interception
	// won't fire but the program still runs.
	_ = rc

	// Step 7: detach. The tracee resumes execution at its original
	// PC (saved by ptrace's POST-EXEC stop semantics) and its
	// signal handlers + seccomp filter installed by uwg_static_init
	// remain active.
	if err := unix.PtraceDetach(pid); err != nil {
		return fmt.Errorf("PtraceDetach: %w", err)
	}

	// Wait for the target to exit and propagate its status.
	if err := cmd.Wait(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Exited() {
					os.Exit(status.ExitStatus())
				}
				if status.Signaled() {
					os.Exit(128 + int(status.Signal()))
				}
			}
		}
		return fmt.Errorf("target exited abnormally: %w", err)
	}
	return nil
}

// readEnvpPointer locates the envp[0] pointer on the tracee's stack
// post-execve. Layout (kernel guarantee):
//
//	*(rsp +  0) = argc
//	*(rsp +  8) = argv[0]
//	*(rsp + 16) = argv[1]
//	... up to argv[argc-1]
//	*(rsp + 8 + 8*argc) = NULL  (argv terminator)
//	*(rsp + 8 + 8*argc + 8) = envp[0]   ← we return this address
func readEnvpPointer(pid int) (uintptr, error) {
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return 0, err
	}
	sp := getSP(&regs)
	// Read argc.
	var word [8]byte
	if _, err := unix.PtracePeekData(pid, uintptr(sp), word[:]); err != nil {
		return 0, fmt.Errorf("read argc: %w", err)
	}
	argc := binary.LittleEndian.Uint64(word[:])
	// envp starts at sp + 8 + 8*argc + 8 (skip argc, argv[0..argc-1],
	// argv-NULL-terminator).
	envpAddr := uintptr(sp) + 8 + uintptr(argc)*8 + 8
	return envpAddr, nil
}

// runStaticInitWithEnvp is the variant of runStaticInit that passes
// a real envp pointer as the third arg.
func runStaticInitWithEnvp(pid int, spec *staticBlobSpec, base, envp uintptr) (int64, error) {
	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &saved); err != nil {
		return 0, fmt.Errorf("PtraceGetRegs: %w", err)
	}

	regs := saved
	sp := getSP(&regs)
	sp -= 64
	sp &^= 15
	setSP(&regs, sp)

	trapAddr := uintptr(base + uintptr(spec.TrapOffset-spec.LowVaddr))
	entry := uint64(base + uintptr(spec.EntryOffset-spec.LowVaddr))
	setupHandoffWithEnvp(&regs, entry, uint64(trapAddr), uint64(envp))

	if getArchName() == "amd64" {
		var retBytes [8]byte
		binary.LittleEndian.PutUint64(retBytes[:], uint64(trapAddr))
		if err := writeMem(pid, uintptr(getSP(&regs)), retBytes[:]); err != nil {
			return 0, fmt.Errorf("write return addr: %w", err)
		}
	}

	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return 0, fmt.Errorf("PtraceSetRegs handoff: %w", err)
	}
	if err := unix.PtraceCont(pid, 0); err != nil {
		return 0, fmt.Errorf("PtraceCont: %w", err)
	}
	var ws unix.WaitStatus
	if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("Wait4: %w", err)
	}
	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP {
		return 0, fmt.Errorf("post-handoff: %v", ws)
	}
	var post unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &post); err != nil {
		return 0, err
	}
	rc := int64(int32(readSyscallResult(&post)))
	if err := unix.PtraceSetRegs(pid, &saved); err != nil {
		return rc, fmt.Errorf("PtraceSetRegs restore: %w", err)
	}
	return rc, nil
}
