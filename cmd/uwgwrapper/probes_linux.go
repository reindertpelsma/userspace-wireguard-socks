// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeSeccompAvailable returns true if this process can install a
// trivial seccomp filter. Used by transport=auto to decide whether
// systrap / ptrace-seccomp modes are reachable on this host.
//
// The probe is a one-shot best-effort: we install a no-op filter
// that allows everything via SECCOMP_RET_ALLOW. The kernel applies
// it to the calling thread only; subsequent forks inherit it. We
// don't undo it (seccomp filters can't be removed), so we run the
// probe in a short-lived child process (`uwgwrapper --mode=
// probe-seccomp`) and report based on its exit status.
//
// Returning false when the test is inconclusive is safe — the auto
// cascade just falls through to ptrace-only and then libc-only.
func probeSeccompAvailable() bool {
	cmd := exec.Command(os.Args[0], "--mode=probe-seccomp")
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// probePtraceAvailable returns true if this process can ptrace a
// child. Container runtimes that block ptrace (Docker default
// seccomp, K8s pods without SYS_PTRACE) cause this to return false.
func probePtraceAvailable() bool {
	cmd := exec.Command(os.Args[0], "--mode=probe-ptrace")
	cmd.Env = []string{}
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// runProbeSeccomp installs a noop allow-everything seccomp filter
// in this process. Exits 0 if seccomp works, non-zero if not.
//
// Filter program (3 instructions):
//
//	BPF_RET | BPF_K, SECCOMP_RET_ALLOW
//
// Single instruction is enough for seccomp(2) to accept; the
// filter never traps anything.
func runProbeSeccomp() {
	// PR_SET_NO_NEW_PRIVS is required before installing a filter
	// unless the caller has CAP_SYS_ADMIN. Always set it.
	if _, _, errno := syscall.Syscall6(unix.SYS_PRCTL,
		uintptr(unix.PR_SET_NO_NEW_PRIVS),
		1, 0, 0, 0, 0); errno != 0 {
		os.Exit(1)
	}
	// Single-instruction allow-everything BPF program.
	type sockFilter struct {
		Code uint16
		Jt   uint8
		Jf   uint8
		K    uint32
	}
	type sockFprog struct {
		Len    uint16
		Filter *sockFilter
	}
	const (
		BPF_RET            = 0x06
		BPF_K              = 0x00
		SECCOMP_RET_ALLOW  = 0x7fff0000
		SECCOMP_SET_MODE   = 1 // SECCOMP_SET_MODE_FILTER
	)
	insn := []sockFilter{
		{Code: BPF_RET | BPF_K, K: SECCOMP_RET_ALLOW},
	}
	prog := sockFprog{Len: uint16(len(insn)), Filter: &insn[0]}
	_, _, errno := syscall.Syscall(unix.SYS_SECCOMP,
		SECCOMP_SET_MODE, 0, uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

// runProbePtrace forks a child with PTRACE_TRACEME and runs
// /bin/true under it. Exits 0 if attach + wait completes cleanly,
// non-zero if ptrace is blocked.
func runProbePtrace() {
	// Look up /bin/true; some images only have busybox under
	// /bin/sh, but ptrace itself doesn't care about the target —
	// any tiny program works.
	target := "/bin/true"
	if _, err := os.Stat(target); err != nil {
		// Fall back to ourselves with --mode=probe-noop. Most
		// hosts have /bin/true though.
		target = os.Args[0]
	}
	cmd := exec.Command(target)
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		os.Exit(1)
	}
	pid := cmd.Process.Pid
	// Wait for the post-exec stop.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		os.Exit(1)
	}
	// Detach and let the child run to completion.
	_ = unix.PtraceDetach(pid)
	_, _ = syscall.Wait4(pid, &ws, 0, nil)
	os.Exit(0)
}

// suppressArgsForProbe trims our own argv down to just the binary
// path so that re-execing ourselves for a probe doesn't pick up
// the user's flags or `--` forwarded args.
func suppressArgsForProbe() {
	// noop placeholder; reserved if we want to scrub later.
	_ = strings.Join(os.Args, " ")
}
