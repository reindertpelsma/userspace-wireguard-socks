// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && (amd64 || arm64)

package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// runSystrapSupervised is the transport=systrap-supervised entry
// point.
//
// The semantics:
//
//   - Target is fork+execed with PTRACE_TRACEME and the env var
//     UWGS_SUPERVISED=1. The .so constructor sees the env and asks
//     the seccomp filter to RET_TRACE on SYS_execve / SYS_execveat
//     (in addition to its normal RET_TRAP for network syscalls).
//
//   - We attach to the target as its tracer, set
//     PTRACE_O_TRACESECCOMP + PTRACE_O_TRACEEXEC, and wait for
//     events. On every PTRACE_EVENT_SECCOMP for execve/execveat we
//     let the syscall complete (PTRACE_CONT), wait for the
//     follow-up PTRACE_EVENT_EXEC stop, then decide:
//
//       - dynamic image (PT_INTERP present): nothing to do —
//         LD_PRELOAD propagates through execve and the new image's
//         dynamic linker re-loads our .so before user main runs.
//         The kernel-inherited seccomp filter is in place during
//         the post-exec libc-init window; for the trim trap list
//         (network syscalls only) libc-init doesn't trip it, so
//         there's no race.
//
//       - static image (no PT_INTERP): inject the freestanding
//         blob into the new image's address space and jump to
//         uwg_static_init. Reuses the same machinery as
//         transport=systrap-static (parseStaticBlob /
//         loadBlobIntoTracee / runStaticInitWithEnvp).
//
//   - We stay attached for the lifetime of the process tree; on
//     fork/clone we automatically follow new children via
//     PTRACE_O_TRACEFORK / TRACEVFORK / TRACECLONE.
//
//   - When the wrapped target exits, we exit with the same status.
//
// Multi-threaded execve: the kernel guarantees only the calling
// thread survives execve (sibling threads are killed atomically),
// so we always see a single PID re-emerge from the post-exec stop
// — no special handling needed for multi-threaded targets.
func runSystrapSupervised(target string, args, env []string,
	preloadPath, blobPath string) error {

	if preloadPath == "" {
		return errors.New("systrap-supervised needs --preload (or UWGS_PRELOAD) for dynamic-target re-arm")
	}
	// Blob is optional at startup: dynamic-only workloads don't
	// need it. Only static-execve children require the blob, and
	// we lazy-parse on first such event. If the blob is missing
	// when a static child appears, the supervisor logs a clear
	// error and lets the static child run un-armed (same effective
	// behaviour as systrap without the supervisor).
	if blobPath == "" {
		blobPath = staticBlobPath()
	}
	var blobSpec *staticBlobSpec
	if blobPath != "" {
		var err error
		blobSpec, err = parseStaticBlob(blobPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "uwgwrapper: systrap-supervised: blob at %s failed to parse (%v); static-execve children will run un-armed\n", blobPath, err)
			blobSpec = nil
		}
	}

	// Lock the OS thread for the whole supervisor run — ptrace
	// requires the same OS thread that called PTRACE_ATTACH /
	// caused the post-exec stop to issue subsequent ptrace ops.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	envSupervised := append([]string{}, env...)
	envSupervised = appendEnv(envSupervised, "UWGS_SUPERVISED=1")
	envSupervised = prependEnvPath(envSupervised, "LD_PRELOAD", preloadPath)

	cmd := exec.Command(target, args...)
	cmd.Env = envSupervised
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace:    true, // child PTRACE_TRACEME before exec
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start target: %w", err)
	}
	rootPID := cmd.Process.Pid

	// Initial post-exec stop.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(rootPID, &ws, 0, nil); err != nil {
		return fmt.Errorf("wait4 post-exec: %w", err)
	}
	if !ws.Stopped() {
		return fmt.Errorf("target exited before stop: %v", ws)
	}

	// Set tracer options. PTRACE_O_TRACESECCOMP lets us see
	// PTRACE_EVENT_SECCOMP whenever a syscall hits a RET_TRACE.
	// PTRACE_O_TRACEEXEC reports the post-exec stop as
	// PTRACE_EVENT_EXEC (rather than a SIGTRAP we'd have to guess
	// the source of). PTRACE_O_TRACEFORK / TRACEVFORK / TRACECLONE
	// auto-attach to children so we follow the whole process tree.
	const (
		ptraceOTraceSeccomp = 0x00000080 // PTRACE_O_TRACESECCOMP
		ptraceOTraceExec    = 0x00000010 // PTRACE_O_TRACEEXEC
		ptraceOTraceFork    = 0x00000004 // PTRACE_O_TRACEFORK
		ptraceOTraceVfork   = 0x00000008 // PTRACE_O_TRACEVFORK
		ptraceOTraceClone   = 0x00000020 // PTRACE_O_TRACECLONE
		ptraceOTraceExit    = 0x00000040 // PTRACE_O_TRACEEXIT
	)
	options := uintptr(ptraceOTraceSeccomp | ptraceOTraceExec |
		ptraceOTraceFork | ptraceOTraceVfork | ptraceOTraceClone |
		ptraceOTraceExit)
	if err := unix.PtraceSetOptions(rootPID, int(options)); err != nil {
		return fmt.Errorf("PTRACE_SETOPTIONS: %w", err)
	}

	// Resume the root process; from here on we react to events.
	if err := unix.PtraceCont(rootPID, 0); err != nil {
		return fmt.Errorf("initial PTRACE_CONT: %w", err)
	}

	exitCode, err := supervisorEventLoop(rootPID, blobSpec)
	if err != nil {
		return err
	}
	os.Exit(exitCode)
	return nil
}

// supervisorEventLoop is the long-running ptrace event loop.
// Returns the wrapped target's exit code on clean termination
// (when the root traced PID exits — we don't wait for non-traced
// siblings like a co-running fdproxy daemon).
func supervisorEventLoop(rootPID int, blobSpec *staticBlobSpec) (int, error) {
	const (
		ptraceEventExec    = 4 // PTRACE_EVENT_EXEC
		ptraceEventSeccomp = 7 // PTRACE_EVENT_SECCOMP
	)
	exitCode := 0

	// seenTracees tracks which tracee PIDs we've already configured
	// PTRACE_O_* options on. The kernel docs say options inherit
	// across fork/clone, but ubuntu:18.04's 4.15 kernel + dash combo
	// doesn't reliably inherit PTRACE_O_TRACESECCOMP — auto-attached
	// fork children's execve hits RET_TRACE and the kernel returns
	// -ENOSYS to the tracee because no PTRACE_EVENT_SECCOMP gets
	// delivered to us. Set options explicitly on the first stop we
	// see for each new pid as a defensive belt-and-braces. Idempotent
	// on kernels that DO inherit (newer glibc/musl matrix entries).
	const (
		ptraceOTraceSeccomp = 0x00000080
		ptraceOTraceExec    = 0x00000010
		ptraceOTraceFork    = 0x00000004
		ptraceOTraceVfork   = 0x00000008
		ptraceOTraceClone   = 0x00000020
		ptraceOTraceExit    = 0x00000040
	)
	traceeOptions := uintptr(ptraceOTraceSeccomp | ptraceOTraceExec |
		ptraceOTraceFork | ptraceOTraceVfork | ptraceOTraceClone |
		ptraceOTraceExit)
	seenTracees := map[int]bool{rootPID: true}

	for {
		var ws syscall.WaitStatus
		// Wait for any traced child. WALL = wait for any child,
		// __WCLONE-or-not. Returns the pid that stopped/exited.
		pid, err := syscall.Wait4(-1, &ws, syscall.WALL, nil)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.ECHILD) {
				// All traced children gone.
				return exitCode, nil
			}
			return exitCode, fmt.Errorf("wait4: %w", err)
		}

		// First-stop hook: ensure PTRACE_O_* are set on this tracee
		// before we hand control back. The kernel might have auto-
		// inherited them but we don't trust that on older kernels.
		if !seenTracees[pid] && ws.Stopped() {
			if err := unix.PtraceSetOptions(pid, int(traceeOptions)); err == nil {
				seenTracees[pid] = true
			}
			// If PtraceSetOptions failed (e.g. tracee already past
			// the attach-stop) we leave seen=false and try again
			// on the next stop. Soft-fail — the kernel may have
			// inherited the options already, in which case
			// everything works.
		}

		switch {
		case ws.Exited():
			// Only the root process's exit triggers us to
			// return; children/grandchildren exiting is normal.
			// Non-traced co-running processes (the fdproxy
			// daemon spawned by the wrapper) also wait4-match
			// here on -1; ignore them by checking pid.
			if pid == rootPID {
				exitCode = ws.ExitStatus()
				return exitCode, nil
			}
			continue
		case ws.Signaled():
			if pid == rootPID {
				exitCode = 128 + int(ws.Signal())
				return exitCode, nil
			}
			continue
		case ws.Stopped():
			sig := ws.StopSignal()
			cause := int(ws) >> 16

			switch cause {
			case ptraceEventSeccomp:
				// RET_TRACE event — the only ones in the filter
				// today are execve / execveat. Just let the
				// syscall continue; the follow-up
				// PTRACE_EVENT_EXEC stop is where we do the
				// per-target re-arm work.
				//
				// Force-preserve-UWGS_*-env across this boundary
				// is scaffolded in cmd/uwgwrapper/exec_env_inject.go
				// but not wired in here yet — at SECCOMP-event the
				// tracee is in a stop where remoteSyscall can't
				// allocate a fresh buffer (the kernel has the
				// original syscall queued and PtraceSingleStep
				// dispatches it instead of our substituted mmap).
				// The full integration needs to either intercept
				// at PTRACE_EVENT_EXEC and rewrite the new image's
				// stack envp in place, or hijack the syscall by
				// setting orig_rax to a no-op + replaying after
				// allocation. Tracked as task #91 follow-up.
				if err := unix.PtraceCont(pid, 0); err != nil {
					return exitCode, fmt.Errorf("PtraceCont after SECCOMP event: %w", err)
				}
				continue
			case ptraceEventExec:
				// Post-exec stop. Decide static-vs-dynamic and
				// inject if needed.
				if err := handleExecveBoundary(pid, blobSpec); err != nil {
					// Don't kill the whole supervised tree on
					// one failed re-arm — log and let the
					// child run un-armed. That's the same
					// behavior as systrap (no supervisor) for
					// that child.
					fmt.Fprintf(os.Stderr, "uwgwrapper: systrap-supervised: re-arm at execve for pid %d failed: %v\n", pid, err)
				}
				if err := unix.PtraceCont(pid, 0); err != nil {
					return exitCode, fmt.Errorf("PtraceCont after EXEC event: %w", err)
				}
				continue
			default:
				// Other ptrace events (FORK/VFORK/CLONE/EXIT)
				// or a signal-stop. For new-child events the
				// kernel auto-attaches; we just need to
				// continue the parent. For signal-stops we
				// pass the signal through to the tracee.
				deliver := 0
				if cause == 0 && sig != syscall.SIGTRAP {
					// Genuine signal-stop — re-deliver.
					deliver = int(sig)
				}
				if err := unix.PtraceCont(pid, deliver); err != nil {
					if errors.Is(err, syscall.ESRCH) {
						// Race: target exited between event
						// and PtraceCont. Harmless.
						continue
					}
					return exitCode, fmt.Errorf("PtraceCont default: %w", err)
				}
				continue
			}
		default:
			// Some other status (CONTINUED?) — ignore.
			continue
		}
	}
}

// handleExecveBoundary inspects the freshly-exec'd image for `pid`
// and re-arms the appropriate injection.
//
// The decision is based on whether the new image has a PT_INTERP
// program header (i.e. names a dynamic linker). A static binary
// has no PT_INTERP and must get the freestanding blob injected.
// A dynamic binary needs nothing from us — LD_PRELOAD propagates
// via envp and the dynamic linker re-runs our .so constructor.
func handleExecveBoundary(pid int, blobSpec *staticBlobSpec) error {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	f, err := elf.Open(exePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", exePath, err)
	}
	defer f.Close()

	staticImage := true
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			staticImage = false
			break
		}
	}
	if !staticImage {
		// Dynamic — LD_PRELOAD will re-run our constructor in
		// the new image. Nothing to do.
		return nil
	}

	// Static — but no blob configured: log + leave un-armed.
	if blobSpec == nil {
		fmt.Fprintf(os.Stderr, "uwgwrapper: systrap-supervised: pid %d execed a static binary but no blob is configured; child will run without interception. Set UWGS_STATIC_BLOB to enable static-execve re-arm.\n", pid)
		return nil
	}

	// At PTRACE_EVENT_EXEC the tracee is in the syscall-exit-stop
	// of execve — still inside the kernel's syscall return path,
	// not yet at user-space. Remote syscalls don't work here
	// because the kernel's syscall bookkeeping is mid-flight.
	// Single-step once to advance to the new image's first user-
	// space instruction (the dynamic linker's _start for dynamic
	// images, the program's _start for static); the resulting
	// SIGTRAP puts the tracee in a clean user-mode stop where
	// PTRACE_GETREGS returns user regs and remote syscalls work.
	if err := unix.PtraceSingleStep(pid); err != nil {
		return fmt.Errorf("PtraceSingleStep into user-space: %w", err)
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("Wait4 after single-step: %w", err)
	}
	if !ws.Stopped() || ws.StopSignal() != syscall.SIGTRAP {
		return fmt.Errorf("expected SIGTRAP at user-space entry; got %v", ws)
	}

	// Static — inject the blob. The tracee is currently in the
	// post-exec stop, which is the same state as the initial
	// post-exec stop for transport=systrap-static. Reuse the same
	// machinery: read envp from the stack, load the blob, run
	// uwg_static_init.
	envpPtr, err := readEnvpPointer(pid)
	if err != nil {
		return fmt.Errorf("read envp: %w", err)
	}
	base, err := loadBlobIntoTracee(pid, blobSpec)
	if err != nil {
		return fmt.Errorf("load blob: %w", err)
	}
	if _, err := runStaticInitWithEnvp(pid, blobSpec, base, envpPtr); err != nil {
		return fmt.Errorf("runStaticInit: %w", err)
	}
	return nil
}
