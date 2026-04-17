// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux && amd64

package uwgtrace

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/uwgshared"
	"golang.org/x/sys/unix"
)

const (
	envTraceSeccompMode = "UWGS_TRACE_SECCOMP_MODE"
	envTraceSecret      = "UWGS_TRACE_SECRET"
	envTraceNoNewPrivs  = "UWGS_TRACE_NO_NEW_PRIVS"
	envTraceStatsPath   = "UWGS_TRACE_STATS_PATH"

	helperExitPtraceUnsupported  = 111
	helperExitSeccompUnsupported = 112
)

var (
	ErrPtraceUnavailable  = errors.New("ptrace tracing unavailable")
	ErrSeccompUnavailable = errors.New("seccomp trace filter unavailable")
)

type Options struct {
	Args            []string
	Env             []string
	FDProxy         string
	SeccompMode     SeccompMode
	NoNewPrivileges bool
	Verbose         bool
	Shared          *uwgshared.Table
	StatsPath       string
}

type tracer struct {
	seccompMode SeccompMode
	secret      uint64
	verbose     bool
	fdproxy     string
	shared      *uwgshared.Table
	pid         int
	pidfd       int
	pending     map[int]pendingSyscall
	blocked     map[int]blockedSyscall
	localMu     sync.Mutex
	taskGroup   map[int]int
	pidfds      map[int]int
	fdEpoch     map[procFD]uint64
	nextEpoch   uint64
	localFDs    map[procFD]int
	statsPath   string
	stats       traceStats
}

type SeccompMode int

const (
	SeccompNone SeccompMode = iota
	SeccompSimple
	SeccompSecret
)

type traceStats struct {
	Syscalls map[string]uint64 `json:"syscalls"`
}

type pendingKind int

const (
	pendingSocket pendingKind = iota + 1
	pendingClose
	pendingDup
	pendingDupN
	pendingAccept
)

type pendingSyscall struct {
	kind    pendingKind
	fd      int
	oldfd   int
	newfd   int
	domain  int
	typ     int
	proto   int
	group   int
	addrPtr uint64
	addrLen uint64
	peer    tracedSockaddr
	localFD int
	epoch   uint64
	state   uwgshared.TrackedFD
}

type blockedSyscall struct {
	seccompStop bool
	regs        unix.PtraceRegs
}

type procFD struct {
	pid int
	fd  int
}

type tracedSockaddr struct {
	family int
	ip     string
	port   uint16
}

type tracedMSghdr struct {
	name       uintptr
	nameLen    uint32
	iov        uintptr
	iovLen     uint64
	control    uintptr
	controlLen uint64
	flags      int32
}

type tracedIovec struct {
	base uintptr
	len  int
}

const (
	tracedIovecSize        = 16
	tracedMSghdrSize       = 56
	tracedMSghdrNameLenOff = 8
	tracedMSghdrFlagsOff   = 48
	tracedMMSghdrSize      = 64
	tracedMMSghdrLenOff    = 56
	tracedMaxIov           = 1024
	tracedMaxIOBytes       = 16 << 20
)

func (t *tracer) trackedSnapshotGroup(group, fd int) uwgshared.TrackedFD {
	return t.shared.Snapshot(group, fd)
}

func (t *tracer) trackedSnapshot(tid, fd int) uwgshared.TrackedFD {
	return t.shared.Snapshot(t.groupFor(tid), fd)
}

func (t *tracer) trackedUpdateGroup(group, fd int, fn func(entry *uwgshared.TrackedFD)) {
	t.shared.Update(group, fd, fn)
}

func (t *tracer) trackedUpdate(tid, fd int, fn func(entry *uwgshared.TrackedFD)) {
	t.shared.Update(t.groupFor(tid), fd, fn)
}

func (t *tracer) trackedClearGroup(group, fd int) {
	t.shared.Clear(group, fd)
}

func (t *tracer) trackedClear(tid, fd int) {
	t.shared.Clear(t.groupFor(tid), fd)
}

func Run(opts Options) (int, error) {
	if len(opts.Args) == 0 {
		return 0, fmt.Errorf("missing target program")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	args := append([]string{"--mode=tracee-helper", "--"}, opts.Args...)
	cmd := exec.Command(self, args...)
	cmd.Env = append([]string{}, opts.Env...)
	cmd.Env = setEnv(cmd.Env, envTraceSeccompMode, opts.SeccompMode.String())
	cmd.Env = setEnv(cmd.Env, envTraceNoNewPrivs, boolString(opts.NoNewPrivileges))
	if opts.StatsPath != "" {
		cmd.Env = setEnv(cmd.Env, envTraceStatsPath, opts.StatsPath)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	t := &tracer{
		seccompMode: opts.SeccompMode,
		secret:      traceSecret(opts.Shared, opts.Env),
		verbose:     opts.Verbose,
		fdproxy:     opts.FDProxy,
		shared:      opts.Shared,
		pid:         cmd.Process.Pid,
		pending:     make(map[int]pendingSyscall),
		blocked:     make(map[int]blockedSyscall),
		taskGroup:   make(map[int]int),
		pidfds:      make(map[int]int),
		fdEpoch:     make(map[procFD]uint64),
		localFDs:    make(map[procFD]int),
		statsPath:   opts.StatsPath,
		stats:       traceStats{Syscalls: make(map[string]uint64)},
	}
	defer t.writeStats()
	t.taskGroup[t.pid] = t.pid

	var status syscall.WaitStatus
	if _, err := syscall.Wait4(t.pid, &status, 0, nil); err != nil {
		return 0, err
	}
	switch {
	case status.Exited():
		switch status.ExitStatus() {
		case helperExitPtraceUnsupported:
			return 0, ErrPtraceUnavailable
		case helperExitSeccompUnsupported:
			return 0, ErrSeccompUnavailable
		default:
			return status.ExitStatus(), nil
		}
	case status.Signaled():
		return 128 + int(status.Signal()), nil
	case !status.Stopped():
		return 0, fmt.Errorf("unexpected trace helper state: %v", status)
	}

	t.pidfd, err = unix.PidfdOpen(t.pid, 0)
	if err != nil {
		return 0, err
	}
	t.pidfds[t.pid] = t.pidfd
	defer func() {
		t.localMu.Lock()
		defer t.localMu.Unlock()
		seen := make(map[int]struct{}, len(t.pidfds))
		for _, fd := range t.pidfds {
			if fd < 0 {
				continue
			}
			if _, ok := seen[fd]; ok {
				continue
			}
			seen[fd] = struct{}{}
			_ = unix.Close(fd)
		}
	}()

	options := unix.PTRACE_O_TRACESYSGOOD |
		unix.PTRACE_O_TRACECLONE |
		unix.PTRACE_O_TRACEFORK |
		unix.PTRACE_O_TRACEVFORK |
		unix.PTRACE_O_TRACEEXEC |
		unix.PTRACE_O_EXITKILL
	if opts.SeccompMode != SeccompNone {
		options |= unix.PTRACE_O_TRACESECCOMP
	}
	if err := unix.PtraceSetOptions(t.pid, options); err != nil {
		return 0, err
	}
	if opts.SeccompMode != SeccompNone {
		if err := unix.PtraceCont(t.pid, 0); err != nil {
			return 0, err
		}
	} else {
		if err := unix.PtraceSyscall(t.pid, 0); err != nil {
			return 0, err
		}
	}
	return t.loop()
}

func RunTraceeHelper(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("tracee helper requires target program")
	}
	if err := ptraceTraceme(); err != nil {
		os.Exit(helperExitPtraceUnsupported)
	}
	noNewPrivs := os.Getenv(envTraceNoNewPrivs) != "0"
	if noNewPrivs {
		if err := setNoNewPrivileges(); err != nil {
			return err
		}
	}
	seccompMode := parseSeccompMode(os.Getenv(envTraceSeccompMode))
	if seccompMode != SeccompNone {
		if err := installSeccompFilter(seccompMode, parseSecret(os.Getenv(envTraceSecret)), noNewPrivs); err != nil {
			os.Exit(helperExitSeccompUnsupported)
		}
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGSTOP); err != nil {
		return err
	}
	target, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	return syscall.Exec(target, args, os.Environ())
}

func (t *tracer) loop() (int, error) {
	for {
		if progressed, err := t.retryBlocked(); err != nil {
			return 0, err
		} else if progressed {
			continue
		}
		var status syscall.WaitStatus
		waitFlags := unix.WALL
		if len(t.blocked) > 0 {
			waitFlags |= syscall.WNOHANG
		}
		tid, err := syscall.Wait4(-1, &status, waitFlags, nil)
		if err != nil {
			if errors.Is(err, syscall.ECHILD) {
				return 0, nil
			}
			return 0, err
		}
		if tid == 0 {
			time.Sleep(500 * time.Microsecond)
			continue
		}
		switch {
		case status.Exited():
			t.clearProcess(tid)
			if tid == t.pid {
				return status.ExitStatus(), nil
			}
		case status.Signaled():
			t.clearProcess(tid)
			if tid == t.pid {
				return 128 + int(status.Signal()), nil
			}
		case status.Stopped():
			if err := t.handleStop(tid, status); err != nil {
				if errors.Is(err, syscall.ESRCH) {
					continue
				}
				return 0, err
			}
		}
	}
}

func (t *tracer) retryBlocked() (bool, error) {
	t.scrubStaleGuards()
	for tid, blocked := range t.blocked {
		switch t.shared.GuardDisposition(tid) {
		case uwgshared.GuardOwnedBySelf:
			delete(t.blocked, tid)
			return true, t.resumeDefault(tid, blocked.seccompStop)
		case uwgshared.GuardOwnedByOther:
			continue
		case uwgshared.GuardUnlocked:
			delete(t.blocked, tid)
			return true, t.dispatchInterceptedSyscall(tid, blocked.regs, blocked.seccompStop)
		}
	}
	return false, nil
}

func (t *tracer) scrubStaleGuards() {
	writer, readers := t.shared.GuardOwners()
	if writer != 0 && !t.guardOwnerAlive(int(writer)) {
		_ = t.shared.ClearGuardWriterOwner(writer)
	}
	for _, reader := range readers {
		if !t.guardOwnerAlive(int(reader)) {
			_ = t.shared.ClearGuardReaderOwner(reader)
		}
	}
}

func (t *tracer) guardOwnerAlive(tid int) bool {
	if tid <= 0 {
		return false
	}
	if _, ok := t.taskGroup[tid]; ok {
		return true
	}
	err := syscall.Kill(tid, 0)
	return err == nil || err == syscall.EPERM
}

func (t *tracer) handleStop(tid int, status syscall.WaitStatus) error {
	switch cause := status.TrapCause(); cause {
	case unix.PTRACE_EVENT_CLONE, unix.PTRACE_EVENT_FORK, unix.PTRACE_EVENT_VFORK:
		child, err := unix.PtraceGetEventMsg(tid)
		if err != nil {
			return err
		}
		parentGroup := t.groupFor(tid)
		childGroup := parentGroup
		if cause == unix.PTRACE_EVENT_FORK || cause == unix.PTRACE_EVENT_VFORK {
			childGroup = int(child)
		}
		t.setTaskGroup(int(child), childGroup)
		if childGroup != parentGroup {
			childPidfd, err := unix.PidfdOpen(int(child), 0)
			if err != nil {
				return err
			}
			t.setPidfd(childGroup, childPidfd)
		}
		if childGroup != parentGroup {
			if err := t.copyProcess(parentGroup, childGroup); err != nil {
				return err
			}
		}
		if t.verbose {
			fmt.Fprintf(os.Stderr, "uwgwrapper: traced child %d from %d (group=%d)\n", child, tid, childGroup)
		}
		return t.resume(tid)
	case unix.PTRACE_EVENT_EXEC:
		group := t.groupFor(tid)
		t.setTaskGroup(tid, group)
		t.reconcileExecGroup(group)
		return t.resume(tid)
	case unix.PTRACE_EVENT_SECCOMP:
		if _, ok := t.pending[tid]; ok {
			return t.resumeForExit(tid)
		}
		return t.handleInterceptedSyscall(tid, true)
	}
	if status.StopSignal() == syscall.Signal(syscall.SIGTRAP|0x80) {
		regs, err := t.getRegs(tid)
		if err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return err
		}
		if t.seccompMode != SeccompNone {
			if pending, ok := t.pending[tid]; ok {
				delete(t.pending, tid)
				return t.handlePendingExit(tid, pending, regs)
			}
			return t.resume(tid)
		}
		if int64(regs.Rax) != -int64(syscall.ENOSYS) {
			if pending, ok := t.pending[tid]; ok {
				delete(t.pending, tid)
				return t.handlePendingExit(tid, pending, regs)
			}
			return t.resume(tid)
		}
		return t.handleInterceptedSyscall(tid, false)
	}
	if sig := status.StopSignal(); sig == syscall.SIGSTOP || sig == syscall.SIGTRAP {
		return t.resume(tid)
	}
	return t.resumeSignal(tid, int(status.StopSignal()))
}

func (t *tracer) handleInterceptedSyscall(tid int, seccompStop bool) error {
	regs, err := t.getRegs(tid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	nr := int64(regs.Orig_rax)
	if nr < 0 {
		return t.resume(tid)
	}
	t.scrubStaleGuards()
	switch t.shared.GuardDisposition(tid) {
	case uwgshared.GuardOwnedBySelf:
		return t.resumeDefault(tid, seccompStop)
	case uwgshared.GuardOwnedByOther:
		t.blocked[tid] = blockedSyscall{seccompStop: seccompStop, regs: regs}
		return nil
	}
	return t.dispatchInterceptedSyscall(tid, regs, seccompStop)
}

func (t *tracer) dispatchInterceptedSyscall(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	nr := int64(regs.Orig_rax)
	if nr < 0 {
		return t.resume(tid)
	}
	if t.hasPassthroughSecret(nr, regs) {
		return t.resumeDefault(tid, seccompStop)
	}
	t.countSyscall(nr)
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: tid=%d syscall=%d seccomp=%t rax=%d\n", tid, nr, seccompStop, int64(regs.Rax))
	}
	switch nr {
	case unix.SYS_SOCKET:
		return t.handleSocket(tid, regs, seccompStop)
	case unix.SYS_CONNECT:
		return t.handleConnect(tid, regs, seccompStop)
	case unix.SYS_BIND:
		return t.handleBind(tid, regs, seccompStop)
	case unix.SYS_LISTEN:
		return t.handleListen(tid, regs, seccompStop)
	case unix.SYS_ACCEPT, unix.SYS_ACCEPT4:
		return t.handleAccept(tid, regs, nr == unix.SYS_ACCEPT4, seccompStop)
	case unix.SYS_CLOSE:
		return t.handleClose(tid, regs, seccompStop)
	case unix.SYS_SENDTO:
		return t.handleSendto(tid, regs, seccompStop)
	case unix.SYS_RECVFROM:
		return t.handleRecvfrom(tid, regs, seccompStop)
	case unix.SYS_SENDMSG:
		return t.handleSendmsg(tid, regs, seccompStop)
	case unix.SYS_RECVMSG:
		return t.handleRecvmsg(tid, regs, seccompStop)
	case unix.SYS_SENDMMSG:
		return t.handleSendmmsg(tid, regs, seccompStop)
	case unix.SYS_RECVMMSG:
		return t.handleRecvmmsg(tid, regs, seccompStop)
	case unix.SYS_READ:
		return t.handleRead(tid, regs, seccompStop)
	case unix.SYS_WRITE:
		return t.handleWrite(tid, regs, seccompStop)
	case unix.SYS_READV:
		return t.handleReadv(tid, regs, seccompStop)
	case unix.SYS_WRITEV:
		return t.handleWritev(tid, regs, seccompStop)
	case unix.SYS_DUP:
		return t.handleDup(tid, regs, seccompStop)
	case unix.SYS_DUP2, unix.SYS_DUP3:
		return t.handleDupN(tid, regs, nr == unix.SYS_DUP3, seccompStop)
	case unix.SYS_GETSOCKNAME:
		return t.handleGetSockName(tid, regs, false, seccompStop)
	case unix.SYS_GETPEERNAME:
		return t.handleGetSockName(tid, regs, true, seccompStop)
	case unix.SYS_SHUTDOWN:
		return t.handleShutdown(tid, regs, seccompStop)
	case unix.SYS_FCNTL:
		return t.handleFcntl(tid, regs, seccompStop)
	case unix.SYS_GETSOCKOPT:
		return t.handleGetSockOpt(tid, regs, seccompStop)
	case unix.SYS_SETSOCKOPT:
		return t.handleSetSockOpt(tid, regs, seccompStop)
	case unix.SYS_POLL:
		return t.handlePoll(tid, regs, false, seccompStop)
	case unix.SYS_PPOLL:
		return t.handlePoll(tid, regs, true, seccompStop)
	default:
		return t.resumeDefault(tid, seccompStop)
	}
}

func (t *tracer) hasPassthroughSecret(nr int64, regs unix.PtraceRegs) bool {
	if t.secret == 0 || regs.R9 != t.secret {
		return false
	}
	switch nr {
	case unix.SYS_SENDTO, unix.SYS_RECVFROM:
		return false
	case unix.SYS_SOCKET,
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
		unix.SYS_PPOLL:
		return true
	default:
		return false
	}
}

func (t *tracer) handleSocket(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	domain := int(int32(regs.Rdi))
	typ := int(int32(regs.Rsi))
	proto := int(int32(regs.Rdx))
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return t.resumeDefault(tid, seccompStop)
	}
	base := typ & 0xf
	if base != unix.SOCK_STREAM && base != unix.SOCK_DGRAM {
		return t.resumeDefault(tid, seccompStop)
	}
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: pending socket tid=%d domain=%d type=%d proto=%d\n", tid, domain, typ, proto)
	}
	t.pending[tid] = pendingSyscall{kind: pendingSocket, domain: domain, typ: typ, proto: proto}
	if base == unix.SOCK_DGRAM && isICMPProtocol(proto) {
		regs.Rdx = 0
		if err := unix.PtraceSetRegs(tid, &regs); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return err
		}
	}
	return t.resumeForExit(tid)
}

func (t *tracer) handleConnect(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	addr, err := t.readSockaddr(tid, uintptr(regs.Rsi), regs.Rdx)
	if err != nil || (addr.family != unix.AF_INET && addr.family != unix.AF_INET6) {
		return t.resumeDefault(tid, seccompStop)
	}
	if isLoopback(addr) {
		t.trackedClear(tid, fd)
		return t.resumeDefault(tid, seccompStop)
	}
	if int(state.Type)&0xf == unix.SOCK_DGRAM && !isICMPProtocol(int(state.Protocol)) {
		t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
			entry.Kind = uwgshared.KindUDPConnected
			entry.HotReady = 0
			entry.RemoteFamily = int32(addr.family)
			entry.RemotePort = addr.port
			uwgshared.StringToBytes(entry.RemoteIP[:], addr.ip)
		})
		return t.finishEmulated(tid, regs, 0, seccompStop)
	}
	proto := "tcp"
	kind := int32(uwgshared.KindTCPStream)
	if int(state.Type)&0xf == unix.SOCK_DGRAM {
		proto = "icmp"
		kind = uwgshared.KindUDPConnected
		addr.port = 0
	}
	managerLocal, err := t.openManagerSocket()
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	bindIP := uwgshared.BytesToString(state.BindIP[:])
	if bindIP == "" {
		bindIP = defaultBindIP(state.Domain)
	}
	line := fmt.Sprintf("CONNECT %s %s %d %s %d\n", proto, addr.ip, addr.port, bindIP, state.BindPort)
	reply, err := managerRequestLine(managerLocal, line)
	if err != nil {
		_ = unix.Close(managerLocal)
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	actualBind, ok := parseConnectReplyLine(reply)
	if !ok {
		_ = unix.Close(managerLocal)
		return t.finishEmulated(tid, regs, -int64(syscall.ECONNREFUSED), seccompStop)
	}
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: connect fd=%d proto=%s remote=%s:%d bind=%s\n", fd, proto, addr.ip, addr.port, actualBind)
	}
	t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
	t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
		entry.Proxied = 1
		entry.Kind = kind
		entry.HotReady = 0
		entry.Bound = 1
		if actualBind.IsValid() {
			entry.BindFamily = int32(addrFamilyForAddr(actualBind.Addr()))
			entry.BindPort = actualBind.Port()
			uwgshared.StringToBytes(entry.BindIP[:], actualBind.Addr().String())
		}
		entry.RemoteFamily = int32(addr.family)
		entry.RemotePort = addr.port
		uwgshared.StringToBytes(entry.RemoteIP[:], addr.ip)
	})
	result := int64(0)
	if kind == uwgshared.KindTCPStream && state.SavedFL&unix.O_NONBLOCK != 0 {
		result = -int64(syscall.EINPROGRESS)
	}
	return t.finishEmulated(tid, regs, result, seccompStop)
}

func (t *tracer) openUDPConnected(tid, fd int, state uwgshared.TrackedFD, dest tracedSockaddr) (uwgshared.TrackedFD, error) {
	proto := "udp"
	bindPort := state.BindPort
	if isICMPProtocol(int(state.Protocol)) {
		proto = "icmp"
		dest.port = 0
		bindPort = 0
	}
	managerLocal, err := t.openManagerSocket()
	if err != nil {
		return state, err
	}
	bindIP := uwgshared.BytesToString(state.BindIP[:])
	if bindIP == "" {
		bindIP = defaultBindIP(state.Domain)
	}
	line := fmt.Sprintf("CONNECT %s %s %d %s %d\n", proto, dest.ip, dest.port, bindIP, bindPort)
	reply, err := managerRequestLine(managerLocal, line)
	if err != nil {
		_ = unix.Close(managerLocal)
		return state, err
	}
	actualBind, ok := parseConnectReplyLine(reply)
	if !ok {
		_ = unix.Close(managerLocal)
		return state, syscall.ECONNREFUSED
	}
	t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
	t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
		entry.Proxied = 1
		entry.Kind = uwgshared.KindUDPConnected
		entry.HotReady = 0
		entry.Bound = 1
		if actualBind.IsValid() {
			entry.BindFamily = int32(addrFamilyForAddr(actualBind.Addr()))
			entry.BindPort = actualBind.Port()
			uwgshared.StringToBytes(entry.BindIP[:], actualBind.Addr().String())
		}
		entry.RemoteFamily = int32(dest.family)
		entry.RemotePort = dest.port
		uwgshared.StringToBytes(entry.RemoteIP[:], dest.ip)
	})
	return t.trackedSnapshot(tid, fd), nil
}

func remoteSockaddrFromState(state uwgshared.TrackedFD) (tracedSockaddr, bool) {
	ip := uwgshared.BytesToString(state.RemoteIP[:])
	family := int(state.RemoteFamily)
	if family == 0 {
		if state.Domain == unix.AF_INET6 {
			family = unix.AF_INET6
		} else {
			family = unix.AF_INET
		}
	}
	if ip == "" || (family != unix.AF_INET && family != unix.AF_INET6) {
		return tracedSockaddr{}, false
	}
	return tracedSockaddr{family: family, ip: ip, port: state.RemotePort}, true
}

func (t *tracer) handleBind(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	addr, err := t.readSockaddr(tid, uintptr(regs.Rsi), regs.Rdx)
	if err != nil || (addr.family != unix.AF_INET && addr.family != unix.AF_INET6) {
		return t.resumeDefault(tid, seccompStop)
	}
	if isLoopback(addr) {
		t.trackedClear(tid, fd)
		return t.resumeDefault(tid, seccompStop)
	}
	t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
		entry.Bound = 1
		entry.BindFamily = int32(addr.family)
		entry.BindPort = addr.port
		uwgshared.StringToBytes(entry.BindIP[:], addr.ip)
	})
	return t.finishEmulated(tid, regs, 0, seccompStop)
}

func (t *tracer) handleListen(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 || int(state.Type)&0xf != unix.SOCK_STREAM {
		return t.resumeDefault(tid, seccompStop)
	}
	managerLocal, err := t.openManagerSocket()
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	bindIP := uwgshared.BytesToString(state.BindIP[:])
	if bindIP == "" {
		bindIP = defaultBindIP(state.Domain)
	}
	line := fmt.Sprintf("LISTEN tcp %s %d %d %d\n", bindIP, state.BindPort, boolToInt(state.ReuseAddr != 0), boolToInt(state.ReusePort != 0))
	reply, err := managerRequestLine(managerLocal, line)
	if err != nil {
		_ = unix.Close(managerLocal)
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	token, actualBind, ok := parseTCPListenReplyLine(reply)
	if !ok || token == "" {
		_ = unix.Close(managerLocal)
		return t.finishEmulated(tid, regs, -int64(syscall.ECONNREFUSED), seccompStop)
	}
	t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
	t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
		entry.Proxied = 1
		entry.Kind = uwgshared.KindTCPListener
		entry.HotReady = 0
		entry.Bound = 1
		if actualBind.Port() != 0 {
			entry.BindPort = actualBind.Port()
		}
		if uwgshared.BytesToString(entry.BindIP[:]) == "" {
			uwgshared.StringToBytes(entry.BindIP[:], defaultBindIP(entry.Domain))
		}
	})
	return t.finishEmulated(tid, regs, 0, seccompStop)
}

func (t *tracer) handleAccept(tid int, regs unix.PtraceRegs, accept4 bool, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Proxied == 0 || state.Kind != uwgshared.KindTCPListener {
		return t.resumeDefault(tid, seccompStop)
	}
	group := t.groupFor(tid)
	localFD, err := t.ensureLocalFD(procFD{pid: group, fd: fd})
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	line, err := readLineFD(localFD)
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	var token, ip string
	var attachID uint64
	var port uint16
	if _, err := fmt.Sscanf(line, "ACCEPT %s %d %s %d", &token, &attachID, &ip, &port); err != nil {
		return t.finishEmulated(tid, regs, -int64(syscall.EPROTO), seccompStop)
	}
	managerLocal, err := t.openManagerSocket()
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	reply, err := managerRequestLine(managerLocal, fmt.Sprintf("ATTACH %s %d\n", token, attachID))
	if err != nil {
		_ = unix.Close(managerLocal)
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	if !strings.HasPrefix(reply, "OK") {
		_ = unix.Close(managerLocal)
		return t.finishEmulated(tid, regs, -int64(syscall.ECONNABORTED), seccompStop)
	}
	flags := 0
	if accept4 {
		flags = int(int32(regs.R10)) & (unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC)
	}
	addrPtr := regs.Rsi
	addrLen := regs.Rdx
	regs.Orig_rax = uint64(unix.SYS_SOCKET)
	regs.Rdi = uint64(state.Domain)
	regs.Rsi = uint64(unix.SOCK_STREAM | flags)
	regs.Rdx = 0
	regs.R10 = 0
	regs.R8 = 0
	regs.R9 = 0
	if err := unix.PtraceSetRegs(tid, &regs); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			_ = unix.Close(managerLocal)
			return nil
		}
		_ = unix.Close(managerLocal)
		return fmt.Errorf("set regs for emulated accept on tid %d: %w", tid, err)
	}
	t.pending[tid] = pendingSyscall{
		kind:    pendingAccept,
		fd:      fd,
		domain:  int(state.Domain),
		typ:     unix.SOCK_STREAM | flags,
		group:   group,
		addrPtr: addrPtr,
		addrLen: addrLen,
		peer:    tracedSockaddr{family: int(state.Domain), ip: ip, port: port},
		localFD: managerLocal,
	}
	return t.resumeForExit(tid)
}

func (t *tracer) handleClose(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	group := t.groupFor(tid)
	t.pending[tid] = pendingSyscall{
		kind:  pendingClose,
		fd:    fd,
		group: group,
		epoch: t.epochFor(procFD{pid: group, fd: fd}),
	}
	return t.resumeForExit(tid)
}

func (t *tracer) handleRead(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Proxied == 0 {
		if state.Active != 0 && int(state.Type)&0xf == unix.SOCK_DGRAM && state.Kind == uwgshared.KindUDPConnected {
			regs.R8 = 0
			regs.R9 = 0
			return t.handleRecvfrom(tid, regs, seccompStop)
		}
		return t.resumeDefault(tid, seccompStop)
	}
	if state.Kind == uwgshared.KindTCPStream || state.Kind == uwgshared.KindUDPConnected || state.Kind == uwgshared.KindUDPListener {
		regs.R8 = 0
		regs.R9 = 0
		return t.handleRecvfrom(tid, regs, seccompStop)
	}
	return t.resumeDefault(tid, seccompStop)
}

func (t *tracer) handleWrite(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Proxied == 0 {
		if state.Active != 0 && int(state.Type)&0xf == unix.SOCK_DGRAM && state.Kind == uwgshared.KindUDPConnected {
			regs.R8 = 0
			regs.R9 = 0
			return t.handleSendto(tid, regs, seccompStop)
		}
		return t.resumeDefault(tid, seccompStop)
	}
	if state.Kind == uwgshared.KindTCPStream || state.Kind == uwgshared.KindUDPConnected || state.Kind == uwgshared.KindUDPListener {
		regs.R8 = 0
		regs.R9 = 0
		return t.handleSendto(tid, regs, seccompStop)
	}
	return t.resumeDefault(tid, seccompStop)
}

func (t *tracer) handleReadv(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	iovPtr := uintptr(regs.Rsi)
	iovLen := uint64(regs.Rdx)
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 && state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	iov, total, err := t.readTraceIovecs(tid, iovPtr, iovLen)
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	result, _, _, _, handled, err := t.emulateRecvBuffer(tid, fd, total)
	if !handled {
		return t.resumeDefault(tid, seccompStop)
	}
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	if len(result) > 0 {
		if err := t.writeTraceIovecPayload(tid, iov, result); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
	}
	return t.finishEmulated(tid, regs, int64(len(result)), seccompStop)
}

func (t *tracer) handleWritev(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	iovPtr := uintptr(regs.Rsi)
	iovLen := uint64(regs.Rdx)
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 && state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	iov, total, err := t.readTraceIovecs(tid, iovPtr, iovLen)
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	result, handled, err := t.emulateSendBuffer(tid, fd, func() ([]byte, error) {
		return t.readTraceIovecPayload(tid, iov, total)
	}, 0, 0)
	if !handled {
		return t.resumeDefault(tid, seccompStop)
	}
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	return t.finishEmulated(tid, regs, result, seccompStop)
}

func (t *tracer) handleSendto(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Active != 0 && state.Proxied == 0 && int(state.Type)&0xf == unix.SOCK_DGRAM {
		if state.Kind == uwgshared.KindUDPConnected {
			if regs.R8 != 0 {
				return t.finishEmulated(tid, regs, -int64(syscall.EISCONN), seccompStop)
			}
			dest, ok := remoteSockaddrFromState(state)
			if !ok {
				return t.finishEmulated(tid, regs, -int64(syscall.EDESTADDRREQ), seccompStop)
			}
			var openErr error
			state, openErr = t.openUDPConnected(tid, fd, state, dest)
			if openErr != nil {
				return t.finishEmulated(tid, regs, -errnoResult(openErr), seccompStop)
			}
		} else if dest, err := t.readSockaddr(tid, uintptr(regs.R8), regs.R9); err == nil && (dest.family == unix.AF_INET || dest.family == unix.AF_INET6) && !isLoopback(dest) {
			if isICMPProtocol(int(state.Protocol)) {
				managerLocal, openErr := t.openManagerSocket()
				if openErr != nil {
					return t.finishEmulated(tid, regs, -errnoResult(openErr), seccompStop)
				}
				bindIP := uwgshared.BytesToString(state.BindIP[:])
				if bindIP == "" {
					bindIP = defaultBindIP(state.Domain)
				}
				reply, reqErr := managerRequestLine(managerLocal, fmt.Sprintf("CONNECT icmp %s 0 %s 0\n", dest.ip, bindIP))
				if reqErr != nil {
					_ = unix.Close(managerLocal)
					return t.finishEmulated(tid, regs, -errnoResult(reqErr), seccompStop)
				}
				actualBind, ok := parseConnectReplyLine(reply)
				if !ok {
					_ = unix.Close(managerLocal)
					return t.finishEmulated(tid, regs, -int64(syscall.ECONNREFUSED), seccompStop)
				}
				t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
				t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
					entry.Proxied = 1
					entry.Kind = uwgshared.KindUDPConnected
					entry.HotReady = 0
					entry.Bound = 1
					if actualBind.IsValid() {
						entry.BindFamily = int32(addrFamilyForAddr(actualBind.Addr()))
						entry.BindPort = actualBind.Port()
						uwgshared.StringToBytes(entry.BindIP[:], actualBind.Addr().String())
					}
					entry.RemoteFamily = int32(dest.family)
					entry.RemotePort = 0
					uwgshared.StringToBytes(entry.RemoteIP[:], dest.ip)
				})
				state = t.trackedSnapshot(tid, fd)
			} else {
				managerLocal, openErr := t.openManagerSocket()
				if openErr != nil {
					return t.finishEmulated(tid, regs, -errnoResult(openErr), seccompStop)
				}
				bindIP := uwgshared.BytesToString(state.BindIP[:])
				if bindIP == "" {
					bindIP = defaultBindIP(state.Domain)
				}
				reply, reqErr := managerRequestLine(managerLocal, fmt.Sprintf("LISTEN udp %s %d %d %d\n", bindIP, state.BindPort, boolToInt(state.ReuseAddr != 0), boolToInt(state.ReusePort != 0)))
				if reqErr != nil {
					_ = unix.Close(managerLocal)
					return t.finishEmulated(tid, regs, -errnoResult(reqErr), seccompStop)
				}
				actualBind, ok := parseUDPListenReplyLine(reply)
				if !ok {
					_ = unix.Close(managerLocal)
					return t.finishEmulated(tid, regs, -int64(syscall.ECONNREFUSED), seccompStop)
				}
				t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
				t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
					entry.Proxied = 1
					entry.Kind = uwgshared.KindUDPListener
					entry.HotReady = 0
					entry.Bound = 1
					if actualBind.Port() != 0 {
						entry.BindPort = actualBind.Port()
					}
					if uwgshared.BytesToString(entry.BindIP[:]) == "" {
						uwgshared.StringToBytes(entry.BindIP[:], defaultBindIP(entry.Domain))
					}
				})
				state = t.trackedSnapshot(tid, fd)
			}
		}
	}
	if state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	localFD, err := t.ensureLocalFD(procFD{pid: t.groupFor(tid), fd: fd})
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	buf, err := t.readTraceeBytes(tid, uintptr(regs.Rsi), int(regs.Rdx))
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	switch state.Kind {
	case uwgshared.KindTCPStream:
		if regs.R8 != 0 {
			return t.finishEmulated(tid, regs, -int64(syscall.EISCONN), seccompStop)
		}
		n, err := unix.Write(localFD, buf)
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		return t.finishEmulated(tid, regs, int64(n), seccompStop)
	case uwgshared.KindUDPConnected:
		if regs.R8 != 0 && !isICMPProtocol(int(state.Protocol)) {
			return t.finishEmulated(tid, regs, -int64(syscall.EISCONN), seccompStop)
		}
		if err := writePacketFD(localFD, buf); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		return t.finishEmulated(tid, regs, int64(len(buf)), seccompStop)
	case uwgshared.KindUDPListener:
		if regs.R8 == 0 {
			return t.finishEmulated(tid, regs, -int64(syscall.EDESTADDRREQ), seccompStop)
		}
		dest, err := t.readSockaddr(tid, uintptr(regs.R8), regs.R9)
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		packet, err := encodeUDPDatagram(dest, buf)
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		if err := writePacketFD(localFD, packet); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		return t.finishEmulated(tid, regs, int64(len(buf)), seccompStop)
	default:
		return t.resumeDefault(tid, seccompStop)
	}
}

func (t *tracer) handleRecvfrom(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if state.Active != 0 && state.Proxied == 0 && int(state.Type)&0xf == unix.SOCK_DGRAM && state.Kind == uwgshared.KindUDPConnected {
		dest, ok := remoteSockaddrFromState(state)
		if !ok {
			return t.finishEmulated(tid, regs, -int64(syscall.ENOTCONN), seccompStop)
		}
		var openErr error
		state, openErr = t.openUDPConnected(tid, fd, state, dest)
		if openErr != nil {
			return t.finishEmulated(tid, regs, -errnoResult(openErr), seccompStop)
		}
	}
	if state.Active != 0 && state.Proxied == 0 && int(state.Type)&0xf == unix.SOCK_DGRAM && state.Bound != 0 && !isICMPProtocol(int(state.Protocol)) {
		managerLocal, openErr := t.openManagerSocket()
		if openErr != nil {
			return t.finishEmulated(tid, regs, -errnoResult(openErr), seccompStop)
		}
		bindIP := uwgshared.BytesToString(state.BindIP[:])
		if bindIP == "" {
			bindIP = defaultBindIP(state.Domain)
		}
		reply, reqErr := managerRequestLine(managerLocal, fmt.Sprintf("LISTEN udp %s %d %d %d\n", bindIP, state.BindPort, boolToInt(state.ReuseAddr != 0), boolToInt(state.ReusePort != 0)))
		if reqErr != nil {
			_ = unix.Close(managerLocal)
			return t.finishEmulated(tid, regs, -errnoResult(reqErr), seccompStop)
		}
		actualBind, ok := parseUDPListenReplyLine(reply)
		if !ok {
			_ = unix.Close(managerLocal)
			return t.finishEmulated(tid, regs, -int64(syscall.ECONNREFUSED), seccompStop)
		}
		t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
		t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
			entry.Proxied = 1
			entry.Kind = uwgshared.KindUDPListener
			entry.HotReady = 0
			entry.Bound = 1
			if actualBind.Port() != 0 {
				entry.BindPort = actualBind.Port()
			}
			if uwgshared.BytesToString(entry.BindIP[:]) == "" {
				uwgshared.StringToBytes(entry.BindIP[:], defaultBindIP(entry.Domain))
			}
		})
		state = t.trackedSnapshot(tid, fd)
	}
	if state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	localFD, err := t.ensureLocalFD(procFD{pid: t.groupFor(tid), fd: fd})
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	switch state.Kind {
	case uwgshared.KindTCPStream:
		out := make([]byte, int(regs.Rdx))
		n, err := unix.Read(localFD, out)
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		if n > 0 {
			if err := t.writeTracee(tid, uintptr(regs.Rsi), out[:n]); err != nil {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
		}
		if regs.R8 != 0 && regs.R9 != 0 {
			sa, saLen := sockaddrBytes(tracedSockaddr{
				family: int(state.RemoteFamily),
				ip:     uwgshared.BytesToString(state.RemoteIP[:]),
				port:   state.RemotePort,
			})
			_ = t.writeTracee(tid, uintptr(regs.R8), sa)
			_ = t.writeUint32(tid, uintptr(regs.R9), uint32(saLen))
		}
		return t.finishEmulated(tid, regs, int64(n), seccompStop)
	case uwgshared.KindUDPConnected:
		packet, err := readPacketFD(localFD)
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		out := packet
		if len(out) > int(regs.Rdx) {
			out = out[:int(regs.Rdx)]
		}
		if err := t.writeTracee(tid, uintptr(regs.Rsi), out); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		if regs.R8 != 0 && regs.R9 != 0 {
			sa, saLen := sockaddrBytes(tracedSockaddr{
				family: func() int {
					if state.RemoteFamily != 0 {
						return int(state.RemoteFamily)
					}
					if state.Domain == unix.AF_INET6 {
						return unix.AF_INET6
					}
					return unix.AF_INET
				}(),
				ip:   uwgshared.BytesToString(state.RemoteIP[:]),
				port: state.RemotePort,
			})
			_ = t.writeTracee(tid, uintptr(regs.R8), sa)
			_ = t.writeUint32(tid, uintptr(regs.R9), uint32(saLen))
		}
		return t.finishEmulated(tid, regs, int64(len(out)), seccompStop)
	case uwgshared.KindUDPListener:
		packet, err := readPacketFD(localFD)
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		src, payload, err := decodeUDPDatagram(packet)
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		out := payload
		if len(out) > int(regs.Rdx) {
			out = out[:int(regs.Rdx)]
		}
		if err := t.writeTracee(tid, uintptr(regs.Rsi), out); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		if regs.R8 != 0 && regs.R9 != 0 {
			sa, saLen := sockaddrBytes(src)
			_ = t.writeTracee(tid, uintptr(regs.R8), sa)
			_ = t.writeUint32(tid, uintptr(regs.R9), uint32(saLen))
		}
		return t.finishEmulated(tid, regs, int64(len(out)), seccompStop)
	default:
		return t.resumeDefault(tid, seccompStop)
	}
}

func (t *tracer) handleSendmsg(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	msgPtr := uintptr(regs.Rsi)
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 && state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	result, handled, err := t.emulateSendmsg(tid, fd, msgPtr)
	if !handled {
		return t.resumeDefault(tid, seccompStop)
	}
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	return t.finishEmulated(tid, regs, result, seccompStop)
}

func (t *tracer) handleRecvmsg(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	msgPtr := uintptr(regs.Rsi)
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 && state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	result, handled, err := t.emulateRecvmsg(tid, fd, msgPtr)
	if !handled {
		return t.resumeDefault(tid, seccompStop)
	}
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	return t.finishEmulated(tid, regs, result, seccompStop)
}

func (t *tracer) handleSendmmsg(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	vecPtr := uintptr(regs.Rsi)
	vlen := uint64(regs.Rdx)
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 && state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	if vlen == 0 {
		return t.finishEmulated(tid, regs, 0, seccompStop)
	}
	if vecPtr == 0 {
		return t.finishEmulated(tid, regs, -int64(syscall.EFAULT), seccompStop)
	}
	if vlen > tracedMaxIov {
		vlen = tracedMaxIov
	}
	var sent uint64
	for i := uint64(0); i < vlen; i++ {
		msgPtr := vecPtr + uintptr(i*tracedMMSghdrSize)
		result, handled, err := t.emulateSendmsg(tid, fd, msgPtr)
		if !handled {
			if i == 0 {
				return t.resumeDefault(tid, seccompStop)
			}
			break
		}
		if err != nil {
			if i == 0 {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			break
		}
		if result < 0 {
			if i == 0 {
				return t.finishEmulated(tid, regs, result, seccompStop)
			}
			break
		}
		if err := t.writeUint32(tid, msgPtr+tracedMMSghdrLenOff, uint32(result)); err != nil {
			if i == 0 {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			break
		}
		sent++
	}
	return t.finishEmulated(tid, regs, int64(sent), seccompStop)
}

func (t *tracer) handleRecvmmsg(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	vecPtr := uintptr(regs.Rsi)
	vlen := uint64(regs.Rdx)
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 && state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	if vlen == 0 {
		return t.finishEmulated(tid, regs, 0, seccompStop)
	}
	if vecPtr == 0 {
		return t.finishEmulated(tid, regs, -int64(syscall.EFAULT), seccompStop)
	}
	if vlen > tracedMaxIov {
		vlen = tracedMaxIov
	}
	var received uint64
	for i := uint64(0); i < vlen; i++ {
		msgPtr := vecPtr + uintptr(i*tracedMMSghdrSize)
		result, handled, err := t.emulateRecvmsg(tid, fd, msgPtr)
		if !handled {
			if i == 0 {
				return t.resumeDefault(tid, seccompStop)
			}
			break
		}
		if err != nil {
			if i == 0 {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			break
		}
		if result < 0 {
			if i == 0 {
				return t.finishEmulated(tid, regs, result, seccompStop)
			}
			break
		}
		if err := t.writeUint32(tid, msgPtr+tracedMMSghdrLenOff, uint32(result)); err != nil {
			if i == 0 {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			break
		}
		received++
	}
	return t.finishEmulated(tid, regs, int64(received), seccompStop)
}

func (t *tracer) emulateSendmsg(tid, fd int, msgPtr uintptr) (int64, bool, error) {
	msg, err := t.readTraceMSghdr(tid, msgPtr)
	if err != nil {
		return 0, true, err
	}
	iov, total, err := t.readTraceIovecs(tid, msg.iov, msg.iovLen)
	if err != nil {
		return 0, true, err
	}
	return t.emulateSendBuffer(tid, fd, func() ([]byte, error) {
		return t.readTraceIovecPayload(tid, iov, total)
	}, msg.name, uint64(msg.nameLen))
}

func (t *tracer) emulateRecvmsg(tid, fd int, msgPtr uintptr) (int64, bool, error) {
	msg, err := t.readTraceMSghdr(tid, msgPtr)
	if err != nil {
		return 0, true, err
	}
	iov, total, err := t.readTraceIovecs(tid, msg.iov, msg.iovLen)
	if err != nil {
		return 0, true, err
	}
	result, flags, source, sourceLen, handled, err := t.emulateRecvBuffer(tid, fd, total)
	if !handled || err != nil {
		return 0, handled, err
	}
	if len(result) > 0 {
		if err := t.writeTraceIovecPayload(tid, iov, result); err != nil {
			return 0, true, err
		}
	}
	if msg.name != 0 && sourceLen > 0 {
		copyLen := sourceLen
		if copyLen > int(msg.nameLen) {
			copyLen = int(msg.nameLen)
		}
		if copyLen > 0 {
			if err := t.writeTracee(tid, msg.name, source[:copyLen]); err != nil {
				return 0, true, err
			}
		}
		if err := t.writeUint32(tid, msgPtr+tracedMSghdrNameLenOff, uint32(sourceLen)); err != nil {
			return 0, true, err
		}
	}
	if err := t.writeUint32(tid, msgPtr+tracedMSghdrFlagsOff, uint32(flags)); err != nil {
		return 0, true, err
	}
	return int64(len(result)), true, nil
}

func (t *tracer) emulateSendBuffer(tid, fd int, payload func() ([]byte, error), destPtr uintptr, destLen uint64) (int64, bool, error) {
	state := t.trackedSnapshot(tid, fd)
	if state.Active != 0 && state.Proxied == 0 && int(state.Type)&0xf == unix.SOCK_DGRAM {
		if state.Kind == uwgshared.KindUDPConnected {
			if destPtr != 0 {
				return -int64(syscall.EISCONN), true, nil
			}
			dest, ok := remoteSockaddrFromState(state)
			if !ok {
				return -int64(syscall.EDESTADDRREQ), true, nil
			}
			var openErr error
			state, openErr = t.openUDPConnected(tid, fd, state, dest)
			if openErr != nil {
				return 0, true, openErr
			}
		} else if destPtr != 0 {
			dest, err := t.readSockaddr(tid, destPtr, destLen)
			if err == nil && (dest.family == unix.AF_INET || dest.family == unix.AF_INET6) && !isLoopback(dest) {
				if isICMPProtocol(int(state.Protocol)) {
					managerLocal, openErr := t.openManagerSocket()
					if openErr != nil {
						return 0, true, openErr
					}
					bindIP := uwgshared.BytesToString(state.BindIP[:])
					if bindIP == "" {
						bindIP = defaultBindIP(state.Domain)
					}
					reply, reqErr := managerRequestLine(managerLocal, fmt.Sprintf("CONNECT icmp %s 0 %s 0\n", dest.ip, bindIP))
					if reqErr != nil {
						_ = unix.Close(managerLocal)
						return 0, true, reqErr
					}
					actualBind, ok := parseConnectReplyLine(reply)
					if !ok {
						_ = unix.Close(managerLocal)
						return -int64(syscall.ECONNREFUSED), true, nil
					}
					t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
					t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
						entry.Proxied = 1
						entry.Kind = uwgshared.KindUDPConnected
						entry.HotReady = 0
						entry.Bound = 1
						if actualBind.IsValid() {
							entry.BindFamily = int32(addrFamilyForAddr(actualBind.Addr()))
							entry.BindPort = actualBind.Port()
							uwgshared.StringToBytes(entry.BindIP[:], actualBind.Addr().String())
						}
						entry.RemoteFamily = int32(dest.family)
						entry.RemotePort = 0
						uwgshared.StringToBytes(entry.RemoteIP[:], dest.ip)
					})
					state = t.trackedSnapshot(tid, fd)
				} else {
					managerLocal, openErr := t.openManagerSocket()
					if openErr != nil {
						return 0, true, openErr
					}
					bindIP := uwgshared.BytesToString(state.BindIP[:])
					if bindIP == "" {
						bindIP = defaultBindIP(state.Domain)
					}
					reply, reqErr := managerRequestLine(managerLocal, fmt.Sprintf("LISTEN udp %s %d %d %d\n", bindIP, state.BindPort, boolToInt(state.ReuseAddr != 0), boolToInt(state.ReusePort != 0)))
					if reqErr != nil {
						_ = unix.Close(managerLocal)
						return 0, true, reqErr
					}
					actualBind, ok := parseUDPListenReplyLine(reply)
					if !ok {
						_ = unix.Close(managerLocal)
						return -int64(syscall.ECONNREFUSED), true, nil
					}
					t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
					t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
						entry.Proxied = 1
						entry.Kind = uwgshared.KindUDPListener
						entry.HotReady = 0
						entry.Bound = 1
						if actualBind.Port() != 0 {
							entry.BindPort = actualBind.Port()
						}
						if uwgshared.BytesToString(entry.BindIP[:]) == "" {
							uwgshared.StringToBytes(entry.BindIP[:], defaultBindIP(entry.Domain))
						}
					})
					state = t.trackedSnapshot(tid, fd)
				}
			}
		}
	}
	if state.Proxied == 0 {
		return 0, false, nil
	}
	localFD, err := t.ensureLocalFD(procFD{pid: t.groupFor(tid), fd: fd})
	if err != nil {
		return 0, true, err
	}
	buf, err := payload()
	if err != nil {
		return 0, true, err
	}
	switch state.Kind {
	case uwgshared.KindTCPStream:
		if destPtr != 0 {
			return -int64(syscall.EISCONN), true, nil
		}
		n, err := unix.Write(localFD, buf)
		if err != nil {
			return 0, true, err
		}
		return int64(n), true, nil
	case uwgshared.KindUDPConnected:
		if destPtr != 0 && !isICMPProtocol(int(state.Protocol)) {
			return -int64(syscall.EISCONN), true, nil
		}
		if err := writePacketFD(localFD, buf); err != nil {
			return 0, true, err
		}
		return int64(len(buf)), true, nil
	case uwgshared.KindUDPListener:
		if destPtr == 0 {
			return -int64(syscall.EDESTADDRREQ), true, nil
		}
		dest, err := t.readSockaddr(tid, destPtr, destLen)
		if err != nil {
			return 0, true, err
		}
		packet, err := encodeUDPDatagram(dest, buf)
		if err != nil {
			return 0, true, err
		}
		if err := writePacketFD(localFD, packet); err != nil {
			return 0, true, err
		}
		return int64(len(buf)), true, nil
	default:
		return 0, false, nil
	}
}

func (t *tracer) emulateRecvBuffer(tid, fd, max int) ([]byte, int32, []byte, int, bool, error) {
	state := t.trackedSnapshot(tid, fd)
	if state.Active != 0 && state.Proxied == 0 && int(state.Type)&0xf == unix.SOCK_DGRAM && state.Kind == uwgshared.KindUDPConnected {
		dest, ok := remoteSockaddrFromState(state)
		if !ok {
			return nil, 0, nil, 0, true, syscall.ENOTCONN
		}
		var openErr error
		state, openErr = t.openUDPConnected(tid, fd, state, dest)
		if openErr != nil {
			return nil, 0, nil, 0, true, openErr
		}
	}
	if state.Active != 0 && state.Proxied == 0 && int(state.Type)&0xf == unix.SOCK_DGRAM && state.Bound != 0 && !isICMPProtocol(int(state.Protocol)) {
		managerLocal, openErr := t.openManagerSocket()
		if openErr != nil {
			return nil, 0, nil, 0, true, openErr
		}
		bindIP := uwgshared.BytesToString(state.BindIP[:])
		if bindIP == "" {
			bindIP = defaultBindIP(state.Domain)
		}
		reply, reqErr := managerRequestLine(managerLocal, fmt.Sprintf("LISTEN udp %s %d %d %d\n", bindIP, state.BindPort, boolToInt(state.ReuseAddr != 0), boolToInt(state.ReusePort != 0)))
		if reqErr != nil {
			_ = unix.Close(managerLocal)
			return nil, 0, nil, 0, true, reqErr
		}
		actualBind, ok := parseUDPListenReplyLine(reply)
		if !ok {
			_ = unix.Close(managerLocal)
			return nil, 0, nil, 0, true, syscall.ECONNREFUSED
		}
		t.setLocalFD(procFD{pid: t.groupFor(tid), fd: fd}, managerLocal)
		t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
			entry.Proxied = 1
			entry.Kind = uwgshared.KindUDPListener
			entry.HotReady = 0
			entry.Bound = 1
			if actualBind.Port() != 0 {
				entry.BindPort = actualBind.Port()
			}
			if uwgshared.BytesToString(entry.BindIP[:]) == "" {
				uwgshared.StringToBytes(entry.BindIP[:], defaultBindIP(entry.Domain))
			}
		})
		state = t.trackedSnapshot(tid, fd)
	}
	if state.Proxied == 0 {
		return nil, 0, nil, 0, false, nil
	}
	localFD, err := t.ensureLocalFD(procFD{pid: t.groupFor(tid), fd: fd})
	if err != nil {
		return nil, 0, nil, 0, true, err
	}
	if max < 0 {
		return nil, 0, nil, 0, true, syscall.EINVAL
	}
	switch state.Kind {
	case uwgshared.KindTCPStream:
		out := make([]byte, max)
		n, err := unix.Read(localFD, out)
		if err != nil {
			return nil, 0, nil, 0, true, err
		}
		source, sourceLen := sockaddrBytes(tracedSockaddr{
			family: int(state.RemoteFamily),
			ip:     uwgshared.BytesToString(state.RemoteIP[:]),
			port:   state.RemotePort,
		})
		return out[:n], 0, source, sourceLen, true, nil
	case uwgshared.KindUDPConnected:
		packet, err := readPacketFD(localFD)
		if err != nil {
			return nil, 0, nil, 0, true, err
		}
		flags := int32(0)
		out := packet
		if len(out) > max {
			out = out[:max]
			flags |= unix.MSG_TRUNC
		}
		source, sourceLen := sockaddrBytes(tracedSockaddr{
			family: func() int {
				if state.RemoteFamily != 0 {
					return int(state.RemoteFamily)
				}
				if state.Domain == unix.AF_INET6 {
					return unix.AF_INET6
				}
				return unix.AF_INET
			}(),
			ip:   uwgshared.BytesToString(state.RemoteIP[:]),
			port: state.RemotePort,
		})
		return out, flags, source, sourceLen, true, nil
	case uwgshared.KindUDPListener:
		packet, err := readPacketFD(localFD)
		if err != nil {
			return nil, 0, nil, 0, true, err
		}
		src, payload, err := decodeUDPDatagram(packet)
		if err != nil {
			return nil, 0, nil, 0, true, err
		}
		flags := int32(0)
		out := payload
		if len(out) > max {
			out = out[:max]
			flags |= unix.MSG_TRUNC
		}
		source, sourceLen := sockaddrBytes(src)
		return out, flags, source, sourceLen, true, nil
	default:
		return nil, 0, nil, 0, false, nil
	}
}

func (t *tracer) handleDup(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	oldfd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, oldfd)
	t.pending[tid] = pendingSyscall{kind: pendingDup, oldfd: oldfd, group: t.groupFor(tid), state: state}
	return t.resumeForExit(tid)
}

func (t *tracer) handleDupN(tid int, regs unix.PtraceRegs, dup3 bool, seccompStop bool) error {
	oldfd := int(int32(regs.Rdi))
	newfd := int(int32(regs.Rsi))
	state := t.trackedSnapshot(tid, oldfd)
	t.pending[tid] = pendingSyscall{kind: pendingDupN, oldfd: oldfd, newfd: newfd, group: t.groupFor(tid), state: state}
	_ = dup3
	return t.resumeForExit(tid)
}

func (t *tracer) handleGetSockName(tid int, regs unix.PtraceRegs, peer bool, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	state := t.trackedSnapshot(tid, fd)
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: getsockname fd=%d peer=%t active=%d proxied=%d kind=%d\n", fd, peer, state.Active, state.Proxied, state.Kind)
	}
	if state.Proxied == 0 {
		if state.Active == 0 || state.Kind != uwgshared.KindUDPConnected {
			return t.resumeDefault(tid, seccompStop)
		}
		if peer {
			if _, ok := remoteSockaddrFromState(state); !ok {
				return t.resumeDefault(tid, seccompStop)
			}
		}
	}
	var sa tracedSockaddr
	switch {
	case peer:
		if state.Kind != uwgshared.KindTCPStream && state.Kind != uwgshared.KindUDPConnected {
			return t.finishEmulated(tid, regs, -int64(syscall.ENOTCONN), seccompStop)
		}
		family := int(state.RemoteFamily)
		if family == 0 {
			if state.Domain == unix.AF_INET6 {
				family = unix.AF_INET6
			} else {
				family = unix.AF_INET
			}
		}
		sa = tracedSockaddr{family: family, ip: uwgshared.BytesToString(state.RemoteIP[:]), port: state.RemotePort}
	default:
		family := int(state.BindFamily)
		if family == 0 {
			if state.Domain == unix.AF_INET6 {
				family = unix.AF_INET6
			} else {
				family = unix.AF_INET
			}
		}
		ip := uwgshared.BytesToString(state.BindIP[:])
		if ip == "" {
			if family == unix.AF_INET6 {
				ip = "::"
			} else {
				ip = "0.0.0.0"
			}
		}
		sa = tracedSockaddr{family: family, ip: ip, port: state.BindPort}
	}
	if regs.Rsi != 0 && regs.Rdx != 0 {
		if t.verbose {
			fmt.Fprintf(os.Stderr, "uwgwrapper: sockname result fd=%d peer=%t family=%d ip=%s port=%d\n", fd, peer, sa.family, sa.ip, sa.port)
		}
		raw, rawLen := sockaddrBytes(sa)
		if err := t.writeTracee(tid, uintptr(regs.Rsi), raw); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		if err := t.writeUint32(tid, uintptr(regs.Rdx), uint32(rawLen)); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
	}
	return t.finishEmulated(tid, regs, 0, seccompStop)
}

func (t *tracer) handleShutdown(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	how := int(int32(regs.Rsi))
	state := t.trackedSnapshot(tid, fd)
	if state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	if state.HotReady == 0 && (state.Kind == uwgshared.KindTCPStream || state.Kind == uwgshared.KindTCPListener) {
		localFD, err := t.ensureLocalFD(procFD{pid: t.groupFor(tid), fd: fd})
		if err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		if err := unix.Shutdown(localFD, how); err != nil {
			return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
		}
		return t.finishEmulated(tid, regs, 0, seccompStop)
	}
	if state.Kind == uwgshared.KindUDPConnected || state.Kind == uwgshared.KindUDPListener {
		if how == unix.SHUT_RD || how == unix.SHUT_WR || how == unix.SHUT_RDWR {
			return t.finishEmulated(tid, regs, 0, seccompStop)
		}
		return t.finishEmulated(tid, regs, -int64(syscall.EINVAL), seccompStop)
	}
	return t.resumeDefault(tid, seccompStop)
}

func (t *tracer) handlePoll(tid int, regs unix.PtraceRegs, ppoll bool, seccompStop bool) error {
	ptr := uintptr(regs.Rdi)
	nfds := regs.Rsi
	if ptr == 0 || nfds == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	if nfds > 1<<20 {
		return t.finishEmulated(tid, regs, -int64(syscall.EINVAL), seccompStop)
	}
	size := int(nfds) * 8
	raw, err := t.readTraceeBytes(tid, ptr, size)
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	type pollEntry struct {
		fd      int
		events  int16
		revents int16
		proxied bool
	}
	entries := make([]pollEntry, int(nfds))
	hasProxied := false
	for i := range entries {
		off := i * 8
		fd := int(int32(binary.LittleEndian.Uint32(raw[off : off+4])))
		events := int16(binary.LittleEndian.Uint16(raw[off+4 : off+6]))
		entry := pollEntry{fd: fd, events: events}
		if fd >= 0 {
			state := t.trackedSnapshot(tid, fd)
			if state.Proxied != 0 && (state.Kind == uwgshared.KindTCPStream || state.Kind == uwgshared.KindUDPConnected || state.Kind == uwgshared.KindUDPListener || state.Kind == uwgshared.KindTCPListener) {
				entry.proxied = true
				hasProxied = true
			}
		}
		entries[i] = entry
	}
	if !hasProxied {
		return t.resumeDefault(tid, seccompStop)
	}
	timeout, err := t.pollTimeoutMillis(tid, regs, ppoll)
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	localPoll := make([]unix.PollFd, len(entries))
	tempFDs := make([]int, 0)
	invalidReady := 0
	group := t.groupFor(tid)
	for i, entry := range entries {
		localPoll[i].Fd = int32(entry.fd)
		localPoll[i].Events = entry.events
		if entry.fd < 0 {
			localPoll[i].Fd = int32(entry.fd)
			continue
		}
		var localFD int
		if entry.proxied {
			localFD, err = t.ensureLocalFD(procFD{pid: group, fd: entry.fd})
		} else {
			localFD, err = t.dupTraceeFD(group, entry.fd)
			if err == nil {
				tempFDs = append(tempFDs, localFD)
			}
		}
		if err != nil {
			entries[i].revents = int16(unix.POLLNVAL)
			localPoll[i].Fd = -1
			invalidReady++
			continue
		}
		localPoll[i].Fd = int32(localFD)
	}
	defer func() {
		for _, fd := range tempFDs {
			_ = unix.Close(fd)
		}
	}()
	if invalidReady > 0 && timeout != 0 {
		timeout = 0
	}
	n, err := unix.Poll(localPoll, timeout)
	if err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	ready := invalidReady
	for i := range entries {
		if entries[i].revents == 0 {
			entries[i].revents = localPoll[i].Revents
			if entries[i].revents != 0 {
				ready++
			}
		}
		off := i * 8
		binary.LittleEndian.PutUint16(raw[off+6:off+8], uint16(entries[i].revents))
	}
	if n > ready {
		ready = n
	}
	if err := t.writeTracee(tid, ptr, raw); err != nil {
		return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
	}
	return t.finishEmulated(tid, regs, int64(ready), seccompStop)
}

func (t *tracer) pollTimeoutMillis(tid int, regs unix.PtraceRegs, ppoll bool) (int, error) {
	if !ppoll {
		return int(int32(regs.Rdx)), nil
	}
	if regs.Rdx == 0 {
		return -1, nil
	}
	raw, err := t.readTraceeBytes(tid, uintptr(regs.Rdx), 16)
	if err != nil {
		return 0, err
	}
	if len(raw) < 16 {
		return 0, syscall.EFAULT
	}
	sec := int64(binary.LittleEndian.Uint64(raw[:8]))
	nsec := int64(binary.LittleEndian.Uint64(raw[8:16]))
	if sec < 0 || nsec < 0 || nsec >= int64(time.Second) {
		return 0, syscall.EINVAL
	}
	const maxMillis = int64(^uint(0) >> 1)
	if sec > maxMillis/1000 {
		return int(maxMillis), nil
	}
	ms := sec*1000 + (nsec+int64(time.Millisecond)-1)/int64(time.Millisecond)
	if ms > maxMillis {
		return int(maxMillis), nil
	}
	return int(ms), nil
}

func (t *tracer) handleFcntl(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	cmd := int(int32(regs.Rsi))
	arg := int32(regs.Rdx)
	state := t.trackedSnapshot(tid, fd)
	if state.Proxied == 0 {
		if state.Active != 0 {
			switch cmd {
			case unix.F_SETFL:
				t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) { entry.SavedFL = arg })
			case unix.F_SETFD:
				t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) { entry.SavedFDFL = arg })
			}
		}
		return t.resumeDefault(tid, seccompStop)
	}
	switch cmd {
	case unix.F_GETFL:
		return t.finishEmulated(tid, regs, int64(state.SavedFL), seccompStop)
	case unix.F_SETFL:
		t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) { entry.SavedFL = arg })
		if state.HotReady == 0 {
			return t.finishEmulated(tid, regs, 0, seccompStop)
		}
		return t.resumeDefault(tid, seccompStop)
	case unix.F_GETFD:
		return t.finishEmulated(tid, regs, int64(state.SavedFDFL), seccompStop)
	case unix.F_SETFD:
		t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) { entry.SavedFDFL = arg })
		if state.HotReady == 0 {
			return t.finishEmulated(tid, regs, 0, seccompStop)
		}
		return t.resumeDefault(tid, seccompStop)
	default:
		return t.resumeDefault(tid, seccompStop)
	}
}

func (t *tracer) handleGetSockOpt(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	level := int(int32(regs.Rsi))
	optname := int(int32(regs.Rdx))
	optval := uintptr(regs.R10)
	optlenp := uintptr(regs.R8)
	state := t.trackedSnapshot(tid, fd)
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: getsockopt fd=%d level=%d opt=%d active=%d proxied=%d kind=%d\n", fd, level, optname, state.Active, state.Proxied, state.Kind)
	}
	if state.Proxied == 0 || optval == 0 || optlenp == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	writeInt := func(v int32) error {
		if err := t.writeTracee(tid, optval, int32Bytes(v)); err != nil {
			return err
		}
		return t.writeUint32(tid, optlenp, 4)
	}
	switch level {
	case unix.SOL_SOCKET:
		switch optname {
		case unix.SO_ERROR:
			if err := writeInt(0); err != nil {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			return t.finishEmulated(tid, regs, 0, seccompStop)
		case unix.SO_TYPE:
			if err := writeInt(state.Type & 0xf); err != nil {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			return t.finishEmulated(tid, regs, 0, seccompStop)
		case unix.SO_REUSEADDR:
			if err := writeInt(state.ReuseAddr); err != nil {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			return t.finishEmulated(tid, regs, 0, seccompStop)
		case unix.SO_REUSEPORT:
			if err := writeInt(state.ReusePort); err != nil {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			return t.finishEmulated(tid, regs, 0, seccompStop)
		}
	}
	return t.resumeDefault(tid, seccompStop)
}

func (t *tracer) handleSetSockOpt(tid int, regs unix.PtraceRegs, seccompStop bool) error {
	fd := int(int32(regs.Rdi))
	level := int(int32(regs.Rsi))
	optname := int(int32(regs.Rdx))
	state := t.trackedSnapshot(tid, fd)
	if state.Active == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	if level == unix.SOL_SOCKET {
		switch optname {
		case unix.SO_REUSEADDR:
			value, err := t.readTraceeInt32(tid, uintptr(regs.R10))
			if err != nil {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) { entry.ReuseAddr = boolToInt32(value != 0) })
			if state.Proxied != 0 {
				return t.finishEmulated(tid, regs, 0, seccompStop)
			}
			return t.resumeDefault(tid, seccompStop)
		case unix.SO_REUSEPORT:
			value, err := t.readTraceeInt32(tid, uintptr(regs.R10))
			if err != nil {
				return t.finishEmulated(tid, regs, -errnoResult(err), seccompStop)
			}
			t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) { entry.ReusePort = boolToInt32(value != 0) })
			if state.Proxied != 0 {
				return t.finishEmulated(tid, regs, 0, seccompStop)
			}
			return t.resumeDefault(tid, seccompStop)
		}
	}
	if state.Proxied == 0 {
		return t.resumeDefault(tid, seccompStop)
	}
	if level == unix.SOL_SOCKET {
		switch optname {
		case unix.SO_KEEPALIVE, unix.SO_SNDBUF, unix.SO_RCVBUF:
			return t.finishEmulated(tid, regs, 0, seccompStop)
		}
	}
	return t.resumeDefault(tid, seccompStop)
}

func (t *tracer) handlePendingExit(tid int, pending pendingSyscall, regs unix.PtraceRegs) error {
	switch pending.kind {
	case pendingSocket:
		fd := int(int64(regs.Rax))
		if t.verbose {
			fmt.Fprintf(os.Stderr, "uwgwrapper: socket exit tid=%d fd=%d\n", tid, fd)
		}
		if fd >= 0 && fd < uwgshared.MaxTrackedFD {
			savedFL := int32(0)
			if pending.typ&unix.SOCK_NONBLOCK != 0 {
				savedFL = unix.O_NONBLOCK
			}
			savedFDFL := int32(0)
			if pending.typ&unix.SOCK_CLOEXEC != 0 {
				savedFDFL = unix.FD_CLOEXEC
			}
			t.trackedUpdate(tid, fd, func(entry *uwgshared.TrackedFD) {
				*entry = uwgshared.TrackedFD{}
				entry.Active = 1
				entry.Domain = int32(pending.domain)
				entry.Type = int32(pending.typ)
				entry.Protocol = int32(pending.proto)
				entry.HotReady = 0
				entry.SavedFL = savedFL
				entry.SavedFDFL = savedFDFL
			})
			t.allocEpoch(procFD{pid: t.groupFor(tid), fd: fd})
		}
	case pendingClose:
		if int64(regs.Rax) == 0 {
			key := procFD{pid: pending.group, fd: pending.fd}
			if t.epochFor(key) == pending.epoch {
				t.trackedClearGroup(pending.group, pending.fd)
				t.clearLocalFD(key)
				t.clearEpoch(key)
			}
		}
	case pendingDup:
		newfd := int(int64(regs.Rax))
		if newfd >= 0 && pending.state.Active != 0 {
			key := procFD{pid: pending.group, fd: newfd}
			copyState := pending.state
			t.trackedUpdateGroup(pending.group, newfd, func(entry *uwgshared.TrackedFD) {
				*entry = copyState
			})
			t.allocEpoch(key)
			if copyState.Proxied != 0 {
				if err := t.copyLocalFD(procFD{pid: pending.group, fd: pending.oldfd}, key); err != nil && t.verbose {
					fmt.Fprintf(os.Stderr, "uwgwrapper: dup local fd copy %d->%d failed: %v\n", pending.oldfd, newfd, err)
				}
			}
		}
	case pendingDupN:
		if int64(regs.Rax) >= 0 && pending.state.Active != 0 {
			key := procFD{pid: pending.group, fd: pending.newfd}
			copyState := pending.state
			t.trackedUpdateGroup(pending.group, pending.newfd, func(entry *uwgshared.TrackedFD) {
				*entry = copyState
			})
			t.allocEpoch(key)
			if copyState.Proxied != 0 {
				if err := t.copyLocalFD(procFD{pid: pending.group, fd: pending.oldfd}, key); err != nil && t.verbose {
					fmt.Fprintf(os.Stderr, "uwgwrapper: dup local fd copy %d->%d failed: %v\n", pending.oldfd, pending.newfd, err)
				}
			}
		}
	case pendingAccept:
		newfd := int(int64(regs.Rax))
		if newfd < 0 {
			_ = unix.Close(pending.localFD)
			break
		}
		key := procFD{pid: pending.group, fd: newfd}
		t.setLocalFD(key, pending.localFD)
		t.allocEpoch(key)
		savedFL := int32(0)
		if pending.typ&unix.SOCK_NONBLOCK != 0 {
			savedFL = unix.O_NONBLOCK
		}
		savedFDFL := int32(0)
		if pending.typ&unix.SOCK_CLOEXEC != 0 {
			savedFDFL = unix.FD_CLOEXEC
		}
		t.trackedUpdateGroup(pending.group, newfd, func(entry *uwgshared.TrackedFD) {
			*entry = uwgshared.TrackedFD{}
			entry.Active = 1
			entry.Domain = int32(pending.domain)
			entry.Type = int32(pending.typ)
			entry.Proxied = 1
			entry.Kind = uwgshared.KindTCPStream
			entry.HotReady = 0
			entry.RemoteFamily = int32(pending.peer.family)
			entry.RemotePort = pending.peer.port
			entry.SavedFL = savedFL
			entry.SavedFDFL = savedFDFL
			uwgshared.StringToBytes(entry.RemoteIP[:], pending.peer.ip)
		})
		if pending.addrPtr != 0 && pending.addrLen != 0 {
			sa, saLen := sockaddrBytes(pending.peer)
			_ = t.writeTracee(tid, uintptr(pending.addrPtr), sa)
			_ = t.writeUint32(tid, uintptr(pending.addrLen), uint32(saLen))
		}
	}
	return t.resume(tid)
}

func (t *tracer) resumeDefault(tid int, seccompStop bool) error {
	return t.resume(tid)
}

func (t *tracer) resumeForExit(tid int) error {
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("resume tid %d waiting for exit: %w", tid, err)
	}
	return nil
}

func (t *tracer) resume(tid int) error {
	if t.seccompMode != SeccompNone {
		if err := unix.PtraceCont(tid, 0); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return fmt.Errorf("resume tid %d with cont: %w", tid, err)
		}
		return nil
	}
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("resume tid %d with syscall: %w", tid, err)
	}
	return nil
}

func (t *tracer) resumeSignal(tid int, sig int) error {
	if t.seccompMode != SeccompNone {
		if err := unix.PtraceCont(tid, sig); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return fmt.Errorf("resume tid %d with cont signal %d: %w", tid, sig, err)
		}
		return nil
	}
	if err := unix.PtraceSyscall(tid, sig); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("resume tid %d with syscall signal %d: %w", tid, sig, err)
	}
	return nil
}

func (t *tracer) runToSyscallExit(tid int, seccompStop bool) (unix.PtraceRegs, error) {
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: wait syscall-exit tid=%d seccomp=%t\n", tid, seccompStop)
	}
	if seccompStop {
		if err := unix.PtraceSyscall(tid, 0); err != nil {
			return unix.PtraceRegs{}, err
		}
	} else {
		if err := unix.PtraceSyscall(tid, 0); err != nil {
			return unix.PtraceRegs{}, err
		}
	}
	for {
		var status syscall.WaitStatus
		if _, err := syscall.Wait4(tid, &status, unix.WALL, nil); err != nil {
			return unix.PtraceRegs{}, err
		}
		if status.Stopped() && status.StopSignal() == syscall.Signal(syscall.SIGTRAP|0x80) {
			if t.verbose {
				fmt.Fprintf(os.Stderr, "uwgwrapper: got syscall-exit tid=%d\n", tid)
			}
			return t.getRegs(tid)
		}
		if status.Exited() || status.Signaled() {
			return unix.PtraceRegs{}, fmt.Errorf("tracee %d exited while waiting for syscall exit: %v", tid, status)
		}
		if t.verbose {
			fmt.Fprintf(os.Stderr, "uwgwrapper: intermediate stop tid=%d status=%v trap=%d sig=%v\n", tid, status, status.TrapCause(), status.StopSignal())
		}
		if err := unix.PtraceSyscall(tid, 0); err != nil {
			return unix.PtraceRegs{}, fmt.Errorf("resume tid %d after intermediate stop %v: %w", tid, status, err)
		}
	}
}

func (t *tracer) finishEmulated(tid int, regs unix.PtraceRegs, result int64, seccompStop bool) error {
	if regs.Orig_rax >= 0 {
		regs.Orig_rax = ^uint64(0)
	}
	regs.Rax = uint64(result)
	if err := unix.PtraceSetRegs(tid, &regs); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("set regs for emulated syscall on tid %d: %w", tid, err)
	}
	if seccompStop {
		if err := unix.PtraceCont(tid, 0); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return fmt.Errorf("resume emulated seccomp tid %d: %w", tid, err)
		}
		return nil
	}
	if err := unix.PtraceSyscall(tid, 0); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return fmt.Errorf("resume emulated ptrace tid %d: %w", tid, err)
	}
	return nil
}

func (t *tracer) getRegs(tid int) (unix.PtraceRegs, error) {
	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(tid, &regs); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return regs, err
		}
		return regs, err
	}
	return regs, nil
}

func (t *tracer) readSockaddr(pid int, ptr uintptr, length uint64) (tracedSockaddr, error) {
	if ptr == 0 || length < 2 {
		return tracedSockaddr{}, syscall.EFAULT
	}
	buf, err := t.readTraceeBytes(pid, ptr, int(length))
	if err != nil {
		return tracedSockaddr{}, err
	}
	if len(buf) < 2 {
		return tracedSockaddr{}, syscall.EINVAL
	}
	family := int(binary.LittleEndian.Uint16(buf[:2]))
	switch family {
	case unix.AF_INET:
		if len(buf) < unix.SizeofSockaddrInet4 {
			return tracedSockaddr{}, syscall.EINVAL
		}
		return tracedSockaddr{
			family: family,
			port:   binary.BigEndian.Uint16(buf[2:4]),
			ip:     net.IP(buf[4:8]).String(),
		}, nil
	case unix.AF_INET6:
		if len(buf) < unix.SizeofSockaddrInet6 {
			return tracedSockaddr{}, syscall.EINVAL
		}
		return tracedSockaddr{
			family: family,
			port:   binary.BigEndian.Uint16(buf[2:4]),
			ip:     net.IP(buf[8:24]).String(),
		}, nil
	default:
		return tracedSockaddr{family: family}, nil
	}
}

func (t *tracer) readTraceeBytes(pid int, ptr uintptr, size int) ([]byte, error) {
	if size < 0 {
		return nil, syscall.EINVAL
	}
	buf := make([]byte, size)
	if size == 0 {
		return buf, nil
	}
	local := []unix.Iovec{{Base: &buf[0], Len: uint64(size)}}
	remote := []unix.RemoteIovec{{Base: ptr, Len: size}}
	n, err := unix.ProcessVMReadv(pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *tracer) readTraceMSghdr(pid int, ptr uintptr) (tracedMSghdr, error) {
	if ptr == 0 {
		return tracedMSghdr{}, syscall.EFAULT
	}
	raw, err := t.readTraceeBytes(pid, ptr, tracedMSghdrSize)
	if err != nil {
		return tracedMSghdr{}, err
	}
	if len(raw) < tracedMSghdrSize {
		return tracedMSghdr{}, syscall.EFAULT
	}
	return tracedMSghdr{
		name:       uintptr(binary.LittleEndian.Uint64(raw[0:8])),
		nameLen:    binary.LittleEndian.Uint32(raw[8:12]),
		iov:        uintptr(binary.LittleEndian.Uint64(raw[16:24])),
		iovLen:     binary.LittleEndian.Uint64(raw[24:32]),
		control:    uintptr(binary.LittleEndian.Uint64(raw[32:40])),
		controlLen: binary.LittleEndian.Uint64(raw[40:48]),
		flags:      int32(binary.LittleEndian.Uint32(raw[48:52])),
	}, nil
}

func (t *tracer) readTraceIovecs(pid int, ptr uintptr, count uint64) ([]tracedIovec, int, error) {
	if count == 0 {
		return nil, 0, nil
	}
	if ptr == 0 {
		return nil, 0, syscall.EFAULT
	}
	if count > tracedMaxIov {
		return nil, 0, syscall.EMSGSIZE
	}
	size := int(count) * tracedIovecSize
	raw, err := t.readTraceeBytes(pid, ptr, size)
	if err != nil {
		return nil, 0, err
	}
	if len(raw) < size {
		return nil, 0, syscall.EFAULT
	}
	out := make([]tracedIovec, 0, int(count))
	total := 0
	for i := 0; i < int(count); i++ {
		off := i * tracedIovecSize
		length64 := binary.LittleEndian.Uint64(raw[off+8 : off+16])
		if length64 > uint64(tracedMaxIOBytes-total) {
			return nil, 0, syscall.EMSGSIZE
		}
		length := int(length64)
		out = append(out, tracedIovec{
			base: uintptr(binary.LittleEndian.Uint64(raw[off : off+8])),
			len:  length,
		})
		total += length
	}
	return out, total, nil
}

func (t *tracer) readTraceIovecPayload(pid int, iov []tracedIovec, total int) ([]byte, error) {
	out := make([]byte, 0, total)
	for _, entry := range iov {
		if entry.len == 0 {
			continue
		}
		chunk, err := t.readTraceeBytes(pid, entry.base, entry.len)
		if err != nil {
			return nil, err
		}
		if len(chunk) < entry.len {
			return nil, syscall.EFAULT
		}
		out = append(out, chunk...)
	}
	return out, nil
}

func (t *tracer) writeTraceIovecPayload(pid int, iov []tracedIovec, data []byte) error {
	offset := 0
	for _, entry := range iov {
		if offset >= len(data) {
			break
		}
		if entry.len == 0 {
			continue
		}
		n := entry.len
		if n > len(data)-offset {
			n = len(data) - offset
		}
		if err := t.writeTracee(pid, entry.base, data[offset:offset+n]); err != nil {
			return err
		}
		offset += n
	}
	return nil
}

func (t *tracer) writeTracee(pid int, ptr uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	local := []unix.Iovec{{Base: &data[0], Len: uint64(len(data))}}
	remote := []unix.RemoteIovec{{Base: ptr, Len: len(data)}}
	_, err := unix.ProcessVMWritev(pid, local, remote, 0)
	return err
}

func (t *tracer) writeUint32(pid int, ptr uintptr, v uint32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return t.writeTracee(pid, ptr, buf[:])
}

func (t *tracer) ensureLocalFD(key procFD) (int, error) {
	t.localMu.Lock()
	fd, ok := t.localFDs[key]
	t.localMu.Unlock()
	if ok {
		if t.verbose {
			fmt.Fprintf(os.Stderr, "uwgwrapper: local fd hit group=%d fd=%d local=%d\n", key.pid, key.fd, fd)
		}
		return fd, nil
	}
	pidfd := t.pidfdFor(key.pid)
	if pidfd < 0 {
		if t.verbose {
			fmt.Fprintf(os.Stderr, "uwgwrapper: local fd miss group=%d fd=%d without pidfd\n", key.pid, key.fd)
		}
		return 0, syscall.ESRCH
	}
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: local fd miss group=%d fd=%d via pidfd=%d\n", key.pid, key.fd, pidfd)
	}
	fd, err := unix.PidfdGetfd(pidfd, key.fd, 0)
	if err != nil {
		return 0, err
	}
	t.setLocalFD(key, fd)
	return fd, nil
}

func (t *tracer) dupTraceeFD(group, fd int) (int, error) {
	pidfd := t.pidfdFor(group)
	if pidfd < 0 {
		return 0, syscall.ESRCH
	}
	return unix.PidfdGetfd(pidfd, fd, 0)
}

func (t *tracer) setLocalFD(key procFD, fd int) {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	if old, ok := t.localFDs[key]; ok && old != fd {
		_ = unix.Close(old)
	}
	t.localFDs[key] = fd
	if t.verbose {
		fmt.Fprintf(os.Stderr, "uwgwrapper: local fd set group=%d fd=%d local=%d\n", key.pid, key.fd, fd)
	}
}

func (t *tracer) copyLocalFD(src, dst procFD) error {
	srcFD, err := t.ensureLocalFD(src)
	if err != nil {
		return err
	}
	dupFD, err := unix.Dup(srcFD)
	if err != nil {
		return err
	}
	t.setLocalFD(dst, dupFD)
	return nil
}

func (t *tracer) clearLocalFD(key procFD) {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	if fd, ok := t.localFDs[key]; ok {
		if t.verbose {
			fmt.Fprintf(os.Stderr, "uwgwrapper: local fd clear group=%d fd=%d local=%d\n", key.pid, key.fd, fd)
		}
		_ = unix.Close(fd)
		delete(t.localFDs, key)
	}
}

func (t *tracer) clearProcess(pid int) {
	delete(t.blocked, pid)
	delete(t.pending, pid)
	t.localMu.Lock()
	defer t.localMu.Unlock()
	delete(t.pending, pid)
	group := t.taskGroup[pid]
	if group == 0 {
		group = pid
	}
	delete(t.taskGroup, pid)
	if group != pid {
		return
	}
	for tid, taskGroup := range t.taskGroup {
		if taskGroup == group {
			delete(t.taskGroup, tid)
		}
	}
	for key, fd := range t.localFDs {
		if key.pid == group {
			_ = unix.Close(fd)
			delete(t.localFDs, key)
		}
	}
	for key := range t.fdEpoch {
		if key.pid == group {
			delete(t.fdEpoch, key)
		}
	}
	t.shared.ClearProcess(group)
	delete(t.pidfds, group)
}

func (t *tracer) setTaskGroup(tid, group int) {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	t.taskGroup[tid] = group
}

func (t *tracer) setPidfd(group, fd int) {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	if old, ok := t.pidfds[group]; ok && old != fd && old >= 0 {
		_ = unix.Close(old)
	}
	t.pidfds[group] = fd
}

func (t *tracer) pidfdFor(group int) int {
	t.localMu.Lock()
	if fd, ok := t.pidfds[group]; ok {
		t.localMu.Unlock()
		return fd
	}
	t.localMu.Unlock()
	fd, err := unix.PidfdOpen(group, 0)
	if err != nil {
		return -1
	}
	t.setPidfd(group, fd)
	return fd
}

func (t *tracer) groupFor(tid int) int {
	t.localMu.Lock()
	if group := t.taskGroup[tid]; group != 0 {
		t.localMu.Unlock()
		return group
	}
	t.localMu.Unlock()
	group := readTgid(tid)
	if group == 0 {
		group = tid
	}
	t.setTaskGroup(tid, group)
	return group
}

func (t *tracer) copyProcess(srcGroup, dstGroup int) error {
	t.shared.CopyProcess(srcGroup, dstGroup)
	t.localMu.Lock()
	keys := make([]procFD, 0, len(t.localFDs))
	for key := range t.localFDs {
		if key.pid == srcGroup {
			keys = append(keys, key)
		}
	}
	t.localMu.Unlock()
	for _, key := range keys {
		if err := t.copyLocalFD(key, procFD{pid: dstGroup, fd: key.fd}); err != nil {
			return err
		}
	}
	return nil
}

func (t *tracer) reconcileExecGroup(group int) {
	if group <= 0 {
		return
	}
	pidfd := t.pidfdFor(group)
	if pidfd < 0 {
		return
	}
	for _, fd := range t.shared.ProcessFDs(group) {
		probe, err := unix.PidfdGetfd(pidfd, fd, 0)
		if err == nil {
			_ = unix.Close(probe)
			continue
		}
		if !errors.Is(err, syscall.EBADF) {
			continue
		}
		key := procFD{pid: group, fd: fd}
		t.trackedClearGroup(group, fd)
		t.clearLocalFD(key)
		t.clearEpoch(key)
	}
}

func (t *tracer) allocEpoch(key procFD) uint64 {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	t.nextEpoch++
	if t.nextEpoch == 0 {
		t.nextEpoch++
	}
	t.fdEpoch[key] = t.nextEpoch
	return t.nextEpoch
}

func (t *tracer) epochFor(key procFD) uint64 {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	return t.fdEpoch[key]
}

func (t *tracer) clearEpoch(key procFD) {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	delete(t.fdEpoch, key)
}

func (t *tracer) openManagerSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	addr := &unix.SockaddrUnix{Name: strings.TrimPrefix(strings.TrimPrefix(t.fdproxy, "unix://"), "unix:")}
	if err := unix.Connect(fd, addr); err != nil {
		_ = unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

func readTgid(tid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return 0
	}
	const prefix = "Tgid:\t"
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			group, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
			return group
		}
	}
	return 0
}

func managerRequestLine(fd int, line string) (string, error) {
	if err := writeAllFD(fd, []byte(line)); err != nil {
		return "", err
	}
	return readLineFD(fd)
}

func parseConnectReplyLine(reply string) (netip.AddrPort, bool) {
	reply = strings.TrimSpace(reply)
	if !strings.HasPrefix(reply, "OK") {
		return netip.AddrPort{}, false
	}
	fields := strings.Fields(reply)
	if len(fields) >= 3 {
		ip, err := netip.ParseAddr(fields[1])
		if err == nil {
			port, err := strconv.ParseUint(fields[2], 10, 16)
			if err == nil {
				return netip.AddrPortFrom(ip, uint16(port)), true
			}
		}
	}
	return netip.AddrPort{}, true
}

func parseUDPListenReplyLine(reply string) (netip.AddrPort, bool) {
	reply = strings.TrimSpace(reply)
	if !strings.HasPrefix(reply, "OKUDP") {
		return netip.AddrPort{}, false
	}
	fields := strings.Fields(reply)
	if len(fields) >= 3 {
		ip, err := netip.ParseAddr(fields[1])
		if err == nil {
			port, err := strconv.ParseUint(fields[2], 10, 16)
			if err == nil {
				return netip.AddrPortFrom(ip, uint16(port)), true
			}
		}
	}
	return netip.AddrPort{}, true
}

func parseTCPListenReplyLine(reply string) (string, netip.AddrPort, bool) {
	reply = strings.TrimSpace(reply)
	if !strings.HasPrefix(reply, "OKLISTEN ") {
		return "", netip.AddrPort{}, false
	}
	fields := strings.Fields(reply)
	if len(fields) < 2 {
		return "", netip.AddrPort{}, false
	}
	token := fields[1]
	if len(fields) >= 4 {
		ip, err := netip.ParseAddr(fields[2])
		if err == nil {
			port, err := strconv.ParseUint(fields[3], 10, 16)
			if err == nil {
				return token, netip.AddrPortFrom(ip, uint16(port)), true
			}
		}
	}
	return token, netip.AddrPort{}, true
}

func defaultBindIP(domain int32) string {
	if domain == unix.AF_INET6 {
		return "::"
	}
	return "0.0.0.0"
}

func (t *tracer) readTraceeInt32(pid int, ptr uintptr) (int32, error) {
	buf, err := t.readTraceeBytes(pid, ptr, 4)
	if err != nil {
		return 0, err
	}
	if len(buf) < 4 {
		return 0, syscall.EFAULT
	}
	return int32(binary.LittleEndian.Uint32(buf)), nil
}

func readLineFD(fd int) (string, error) {
	var out bytes.Buffer
	var b [1]byte
	for {
		n, err := unix.Read(fd, b[:])
		if n > 0 {
			out.WriteByte(b[0])
			if b[0] == '\n' {
				return out.String(), nil
			}
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", ioEOF
		}
	}
}

func writeAllFD(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func writePacketFD(fd int, payload []byte) error {
	if len(payload) > 1<<20 {
		return syscall.EMSGSIZE
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(payload)))
	if err := writeAllFD(fd, h[:]); err != nil {
		return err
	}
	return writeAllFD(fd, payload)
}

func readPacketFD(fd int) ([]byte, error) {
	var h [4]byte
	if err := readAllFD(fd, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n > 1<<20 {
		return nil, syscall.EMSGSIZE
	}
	buf := make([]byte, n)
	if err := readAllFD(fd, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readAllFD(fd int, buf []byte) error {
	for len(buf) > 0 {
		n, err := unix.Read(fd, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return ioEOF
		}
		buf = buf[n:]
	}
	return nil
}

func sockaddrBytes(addr tracedSockaddr) ([]byte, int) {
	switch addr.family {
	case unix.AF_INET6:
		var raw [unix.SizeofSockaddrInet6]byte
		binary.LittleEndian.PutUint16(raw[:2], unix.AF_INET6)
		binary.BigEndian.PutUint16(raw[2:4], addr.port)
		ip := net.ParseIP(addr.ip).To16()
		if ip != nil {
			copy(raw[8:24], ip)
		}
		return raw[:], len(raw)
	default:
		var raw [unix.SizeofSockaddrInet4]byte
		binary.LittleEndian.PutUint16(raw[:2], unix.AF_INET)
		binary.BigEndian.PutUint16(raw[2:4], addr.port)
		ip := net.ParseIP(addr.ip).To4()
		if ip != nil {
			copy(raw[4:8], ip)
		}
		return raw[:], len(raw)
	}
}

func encodeUDPDatagram(dest tracedSockaddr, payload []byte) ([]byte, error) {
	switch dest.family {
	case unix.AF_INET:
		ip := net.ParseIP(dest.ip).To4()
		if ip == nil {
			return nil, syscall.EINVAL
		}
		out := make([]byte, 4+4+len(payload))
		out[0] = 4
		binary.BigEndian.PutUint16(out[2:4], dest.port)
		copy(out[4:8], ip)
		copy(out[8:], payload)
		return out, nil
	case unix.AF_INET6:
		ip := net.ParseIP(dest.ip).To16()
		if ip == nil {
			return nil, syscall.EINVAL
		}
		out := make([]byte, 4+16+len(payload))
		out[0] = 6
		binary.BigEndian.PutUint16(out[2:4], dest.port)
		copy(out[4:20], ip)
		copy(out[20:], payload)
		return out, nil
	default:
		return nil, syscall.EDESTADDRREQ
	}
}

func decodeUDPDatagram(packet []byte) (tracedSockaddr, []byte, error) {
	if len(packet) < 8 {
		return tracedSockaddr{}, nil, syscall.EPROTO
	}
	switch packet[0] {
	case 4:
		if len(packet) < 8 {
			return tracedSockaddr{}, nil, syscall.EPROTO
		}
		return tracedSockaddr{
			family: unix.AF_INET,
			port:   binary.BigEndian.Uint16(packet[2:4]),
			ip:     net.IP(packet[4:8]).String(),
		}, packet[8:], nil
	case 6:
		if len(packet) < 20 {
			return tracedSockaddr{}, nil, syscall.EPROTO
		}
		return tracedSockaddr{
			family: unix.AF_INET6,
			port:   binary.BigEndian.Uint16(packet[2:4]),
			ip:     net.IP(packet[4:20]).String(),
		}, packet[20:], nil
	default:
		return tracedSockaddr{}, nil, syscall.EPROTO
	}
}

func ptraceTraceme() error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func errnoResult(err error) int64 {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int64(errno)
	}
	return int64(syscall.EIO)
}

func (m SeccompMode) String() string {
	switch m {
	case SeccompSimple:
		return "simple"
	case SeccompSecret:
		return "secret"
	default:
		return "none"
	}
}

func parseSeccompMode(raw string) SeccompMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "simple":
		return SeccompSimple
	case "secret", "combo", "both":
		return SeccompSecret
	default:
		return SeccompNone
	}
}

func setNoNewPrivileges() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func SetNoNewPrivileges() error {
	return setNoNewPrivileges()
}

func (t *tracer) countSyscall(nr int64) {
	if t == nil || t.stats.Syscalls == nil {
		return
	}
	t.stats.Syscalls[syscallName(nr)]++
}

func (t *tracer) writeStats() {
	if t == nil || t.statsPath == "" {
		return
	}
	data, err := json.MarshalIndent(t.stats, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(t.statsPath, append(data, '\n'), 0o644)
}

func syscallName(nr int64) string {
	switch nr {
	case unix.SYS_SOCKET:
		return "socket"
	case unix.SYS_CONNECT:
		return "connect"
	case unix.SYS_BIND:
		return "bind"
	case unix.SYS_LISTEN:
		return "listen"
	case unix.SYS_ACCEPT:
		return "accept"
	case unix.SYS_ACCEPT4:
		return "accept4"
	case unix.SYS_CLOSE:
		return "close"
	case unix.SYS_SENDTO:
		return "sendto"
	case unix.SYS_RECVFROM:
		return "recvfrom"
	case unix.SYS_SENDMSG:
		return "sendmsg"
	case unix.SYS_RECVMSG:
		return "recvmsg"
	case unix.SYS_SENDMMSG:
		return "sendmmsg"
	case unix.SYS_RECVMMSG:
		return "recvmmsg"
	case unix.SYS_WRITE:
		return "write"
	case unix.SYS_READ:
		return "read"
	case unix.SYS_WRITEV:
		return "writev"
	case unix.SYS_READV:
		return "readv"
	case unix.SYS_DUP:
		return "dup"
	case unix.SYS_DUP2:
		return "dup2"
	case unix.SYS_DUP3:
		return "dup3"
	case unix.SYS_GETSOCKNAME:
		return "getsockname"
	case unix.SYS_GETPEERNAME:
		return "getpeername"
	case unix.SYS_SHUTDOWN:
		return "shutdown"
	case unix.SYS_FCNTL:
		return "fcntl"
	case unix.SYS_GETSOCKOPT:
		return "getsockopt"
	case unix.SYS_SETSOCKOPT:
		return "setsockopt"
	case unix.SYS_POLL:
		return "poll"
	case unix.SYS_PPOLL:
		return "ppoll"
	default:
		return strconv.FormatInt(nr, 10)
	}
}

func int32Bytes(v int32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(v))
	return buf[:]
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func boolToInt32(v bool) int32 {
	if v {
		return 1
	}
	return 0
}

func addrFamilyForAddr(addr netip.Addr) int {
	if addr.Is6() {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

func parseSecret(raw string) uint64 {
	if raw == "" {
		return 0
	}
	secret, _ := strconv.ParseUint(raw, 10, 64)
	return secret
}

func traceSecret(shared *uwgshared.Table, env []string) uint64 {
	if secret := shared.Secret(); secret != 0 {
		return secret
	}
	prefix := envTraceSecret + "="
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			return parseSecret(strings.TrimPrefix(entry, prefix))
		}
	}
	return 0
}

func boolString(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func isLoopback(addr tracedSockaddr) bool {
	ip := net.ParseIP(addr.ip)
	return ip != nil && ip.IsLoopback()
}

func isICMPProtocol(protocol int) bool {
	return protocol == unix.IPPROTO_ICMP || protocol == unix.IPPROTO_ICMPV6
}

var ioEOF = io.EOF
