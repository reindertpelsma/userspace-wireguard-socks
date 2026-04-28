// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"os/exec"
	"runtime"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// attachAndStop spawns /bin/sleep, attaches via PTRACE_SEIZE, then
// PTRACE_INTERRUPTs it to ensure a clean group-stop (not mid-syscall).
// This is the same shape as the real Phase 2 supervisor: attach to a
// running tracee and put it in a clean stop state before injecting.
func attachAndStop(t *testing.T) (pid int, cleanup func()) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn sleep: %v", err)
	}
	pid = cmd.Process.Pid
	killChild := func() { _ = cmd.Process.Kill() }

	if err := unix.PtraceSeize(pid); err != nil {
		killChild()
		t.Fatalf("PtraceSeize %d: %v", pid, err)
	}
	if err := unix.PtraceInterrupt(pid); err != nil {
		killChild()
		t.Fatalf("PtraceInterrupt: %v", err)
	}

	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, 0, nil)
		if err != nil {
			killChild()
			t.Fatalf("Wait4 after attach: %v", err)
		}
		if !ws.Stopped() {
			killChild()
			t.Fatalf("tracee unexpectedly exited: %v", ws)
		}
		break
	}
	cleanup = func() {
		_ = unix.PtraceDetach(pid)
		killChild()
	}
	return pid, cleanup
}

// TestRemoteSyscallGetpid drives remoteSyscall against a clean-stopped
// tracee. SYS_getpid is the simplest test: no args, no side effects.
func TestRemoteSyscallGetpid(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid, cleanup := attachAndStop(t)
	defer cleanup()

	rc, err := remoteSyscall(pid, unix.SYS_GETPID)
	if err != nil {
		t.Fatalf("remoteSyscall(getpid): %v", err)
	}
	if int(rc) != pid {
		t.Fatalf("remote getpid() = %d, want %d", int(rc), pid)
	}
	t.Logf("remote getpid OK: returned %d (pid=%d)", int(rc), pid)
}

// TestRemoteSyscallMmapMunmap exercises the 6-arg path. mmap hits
// every syscall arg register; if any arg is mis-loaded the kernel
// returns -EINVAL or worse.
func TestRemoteSyscallMmapMunmap(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid, cleanup := attachAndStop(t)
	defer cleanup()

	// mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)
	const (
		PROT_RW = unix.PROT_READ | unix.PROT_WRITE
		FLAGS   = unix.MAP_ANONYMOUS | unix.MAP_PRIVATE
	)
	addr, err := remoteSyscall(pid, unix.SYS_MMAP,
		0, 4096, PROT_RW, FLAGS, ^uintptr(0), 0)
	if err != nil {
		t.Fatalf("remoteSyscall(mmap): %v", err)
	}
	// Errors come back as -errno (in [-4095, -1]); valid addresses are
	// large positive values (top of low-half on x86_64).
	if int64(addr) < 0 && int64(addr) >= -4095 {
		t.Fatalf("mmap returned errno: %d (%v)", -int64(addr),
			syscall.Errno(-int64(addr)))
	}
	if addr < 0x1000 {
		t.Fatalf("mmap returned implausibly low address: %#x", addr)
	}
	t.Logf("remote mmap OK: addr=%#x size=4096", addr)

	rc, err := remoteSyscall(pid, unix.SYS_MUNMAP, addr, 4096)
	if err != nil {
		t.Fatalf("remoteSyscall(munmap): %v", err)
	}
	if int64(rc) != 0 {
		t.Fatalf("munmap returned %d, want 0", int64(rc))
	}
	t.Logf("remote munmap OK")
}
