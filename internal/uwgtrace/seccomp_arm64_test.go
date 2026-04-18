// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build (linux || android) && arm64

package uwgtrace

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildSeccompSimpleProgram(t *testing.T) {
	prog, err := buildSeccompProgram(SeccompSimple, 0)
	if err != nil {
		t.Fatalf("build simple seccomp program: %v", err)
	}

	for _, nr := range append(append([]uint32{}, secretBypassSyscalls...), alwaysTraceSyscalls...) {
		if got := evalSeccompProgram(t, prog, nr, 0, unix.AUDIT_ARCH_AARCH64); got != unix.SECCOMP_RET_TRACE {
			t.Fatalf("syscall %d: got seccomp action %#x, want trace", nr, got)
		}
	}
	if got := evalSeccompProgram(t, prog, unix.SYS_GETPID, 0, unix.AUDIT_ARCH_AARCH64); got != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("getpid got seccomp action %#x, want allow", got)
	}
	if got := evalSeccompProgram(t, prog, unix.SYS_GETPID, 0, 0); got != unix.SECCOMP_RET_TRACE {
		t.Fatalf("unexpected arch got seccomp action %#x, want trace", got)
	}
}

func TestBuildSeccompSecretProgram(t *testing.T) {
	const secret = uint64(0x1122334455667788)
	prog, err := buildSeccompProgram(SeccompSecret, secret)
	if err != nil {
		t.Fatalf("build secret seccomp program: %v", err)
	}
	if len(prog) > 64 {
		t.Fatalf("secret seccomp program grew unexpectedly large: %d filters", len(prog))
	}

	for _, nr := range secretBypassSyscalls {
		if got := evalSeccompProgram(t, prog, nr, secret, unix.AUDIT_ARCH_AARCH64); got != unix.SECCOMP_RET_ALLOW {
			t.Fatalf("syscall %d with secret: got seccomp action %#x, want allow", nr, got)
		}
		if got := evalSeccompProgram(t, prog, nr, secret+1, unix.AUDIT_ARCH_AARCH64); got != unix.SECCOMP_RET_TRACE {
			t.Fatalf("syscall %d with wrong secret: got seccomp action %#x, want trace", nr, got)
		}
	}

	for _, nr := range alwaysTraceSyscalls {
		if got := evalSeccompProgram(t, prog, nr, secret, unix.AUDIT_ARCH_AARCH64); got != unix.SECCOMP_RET_TRACE {
			t.Fatalf("syscall %d must not use arg5 as secret: got seccomp action %#x, want trace", nr, got)
		}
	}
	if got := evalSeccompProgram(t, prog, unix.SYS_GETPID, 0, unix.AUDIT_ARCH_AARCH64); got != unix.SECCOMP_RET_ALLOW {
		t.Fatalf("getpid got seccomp action %#x, want allow", got)
	}
}

func TestBuildSeccompSecretProgramRejectsZeroSecret(t *testing.T) {
	if _, err := buildSeccompProgram(SeccompSecret, 0); err != syscall.EINVAL {
		t.Fatalf("build secret seccomp with zero secret err=%v, want EINVAL", err)
	}
}

func TestSeccompSyscallSetsAreDisjoint(t *testing.T) {
	for _, nr := range secretBypassSyscalls {
		if syscallInSet(int64(nr), alwaysTraceSyscalls) {
			t.Fatalf("syscall %d is present in both the passthrough and always-trace sets", nr)
		}
	}
}

func evalSeccompProgram(t *testing.T, prog []unix.SockFilter, nr uint32, arg5 uint64, arch uint32) uint32 {
	t.Helper()
	var a uint32
	for pc, steps := 0, 0; ; steps++ {
		if steps > len(prog)+8 {
			t.Fatalf("seccomp program did not terminate")
		}
		if pc < 0 || pc >= len(prog) {
			t.Fatalf("program counter out of range: %d", pc)
		}
		ins := prog[pc]
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch ins.K {
			case seccompOffsetNR:
				a = nr
			case seccompOffsetArch:
				a = arch
			case seccompOffsetArg5Lo:
				a = uint32(arg5)
			case seccompOffsetArg5Hi:
				a = uint32(arg5 >> 32)
			default:
				t.Fatalf("unsupported absolute load offset %d", ins.K)
			}
			pc++
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == ins.K {
				pc += 1 + int(ins.Jt)
			} else {
				pc += 1 + int(ins.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		default:
			t.Fatalf("unsupported instruction code %#x", ins.Code)
		}
	}
}
