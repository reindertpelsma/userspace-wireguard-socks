// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && amd64

package uwgtrace

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	seccompOffsetNR     = 0
	seccompOffsetArch   = 4
	seccompOffsetArg5Lo = 16 + 5*8
	seccompOffsetArg5Hi = seccompOffsetArg5Lo + 4
)

func installSeccompFilter(mode SeccompMode, secret uint64, setNoNewPrivs bool) error {
	if setNoNewPrivs {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return err
		}
	}
	prog, err := buildSeccompProgram(mode, secret)
	if err != nil {
		return err
	}
	fprog := unix.SockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}
	_, _, errno := syscall.RawSyscall(unix.SYS_SECCOMP, uintptr(unix.SECCOMP_SET_MODE_FILTER), 0, uintptr(unsafe.Pointer(&fprog)))
	if errno != 0 {
		return errno
	}
	return nil
}

func buildSeccompProgram(mode SeccompMode, secret uint64) ([]unix.SockFilter, error) {
	var out []unix.SockFilter
	ldAbs := func(offset uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offset}
	}
	jeq := func(k uint32, jt, jf uint8) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: jt, Jf: jf, K: k}
	}
	ret := func(v uint32) unix.SockFilter {
		return unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: v}
	}
	trace := ret(unix.SECCOMP_RET_TRACE)
	allow := ret(unix.SECCOMP_RET_ALLOW)

	out = append(out,
		ldAbs(seccompOffsetArch),
		jeq(unix.AUDIT_ARCH_X86_64, 1, 0),
		ret(unix.SECCOMP_RET_TRACE),
	)

	secretBypassSyscalls := []uint32{
		unix.SYS_SOCKET,
		unix.SYS_CONNECT,
		unix.SYS_BIND,
		unix.SYS_LISTEN,
		unix.SYS_ACCEPT,
		unix.SYS_ACCEPT4,
		unix.SYS_CLOSE,
		unix.SYS_READ,
		unix.SYS_WRITE,
		unix.SYS_DUP,
		unix.SYS_DUP2,
		unix.SYS_DUP3,
		unix.SYS_GETSOCKNAME,
		unix.SYS_GETPEERNAME,
		unix.SYS_SHUTDOWN,
		unix.SYS_FCNTL,
		unix.SYS_GETSOCKOPT,
		unix.SYS_SETSOCKOPT,
		unix.SYS_POLL,
		unix.SYS_PPOLL,
	}

	alwaysTraceSyscalls := []uint32{
		unix.SYS_SENDTO,
		unix.SYS_RECVFROM,
	}

	out = append(out, ldAbs(seccompOffsetNR))

	switch mode {
	case SeccompSimple:
		for _, nr := range append(append([]uint32{}, secretBypassSyscalls...), alwaysTraceSyscalls...) {
			out = append(out,
				jeq(nr, 0, 1),
				trace,
			)
		}
	case SeccompSecret:
		if secret == 0 {
			return nil, syscall.EINVAL
		}
		low := uint32(secret)
		high := uint32(secret >> 32)
		for _, nr := range secretBypassSyscalls {
			out = append(out,
				jeq(nr, 0, 6),
				ldAbs(seccompOffsetArg5Lo),
				jeq(low, 0, 2),
				ldAbs(seccompOffsetArg5Hi),
				jeq(high, 1, 0),
				trace,
				allow,
			)
		}
		for _, nr := range alwaysTraceSyscalls {
			out = append(out,
				jeq(nr, 0, 1),
				trace,
			)
		}
	case SeccompNone:
		// No filter should be installed in this mode.
	default:
		return nil, syscall.EINVAL
	}
	out = append(out, allow)

	return out, nil
}
