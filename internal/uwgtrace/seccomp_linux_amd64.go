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
	jeqTarget := func(k uint32, target int) error {
		skip := target - len(out) - 1
		if skip < 0 || skip > 255 {
			return syscall.EINVAL
		}
		out = append(out, jeq(k, uint8(skip), 0))
		return nil
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
		unix.SYS_READV,
		unix.SYS_WRITEV,
		unix.SYS_SENDMSG,
		unix.SYS_RECVMSG,
		unix.SYS_SENDMMSG,
		unix.SYS_RECVMMSG,
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
		unix.SYS_SELECT,
		unix.SYS_PSELECT6,
	}

	out = append(out, ldAbs(seccompOffsetNR))

	switch mode {
	case SeccompSimple:
		traceSyscalls := append(append([]uint32{}, secretBypassSyscalls...), alwaysTraceSyscalls...)
		traceIndex := len(out) + len(traceSyscalls) + 1
		for _, nr := range traceSyscalls {
			if err := jeqTarget(nr, traceIndex); err != nil {
				return nil, err
			}
		}
		out = append(out, allow, trace)
	case SeccompSecret:
		if secret == 0 {
			return nil, syscall.EINVAL
		}
		low := uint32(secret)
		high := uint32(secret >> 32)
		secretIndex := len(out) + len(secretBypassSyscalls) + len(alwaysTraceSyscalls) + 1
		traceIndex := secretIndex + 6
		for _, nr := range secretBypassSyscalls {
			if err := jeqTarget(nr, secretIndex); err != nil {
				return nil, err
			}
		}
		for _, nr := range alwaysTraceSyscalls {
			if err := jeqTarget(nr, traceIndex); err != nil {
				return nil, err
			}
		}
		out = append(out,
			allow,
			ldAbs(seccompOffsetArg5Lo),
			jeq(low, 0, 2),
			ldAbs(seccompOffsetArg5Hi),
			jeq(high, 1, 0),
			trace,
			allow,
			trace,
		)
	case SeccompNone:
		// No filter should be installed in this mode.
		out = append(out, allow)
	default:
		return nil, syscall.EINVAL
	}

	return out, nil
}
