package preload_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type behavior int32

const (
	behaveNormal behavior = iota
	behaveCloseMidResponse
	behaveInvalidID
	behaveShortGarbage
	behaveMissingRecord
	behaveNoResponse
	behaveInvalidRDLen
	behaveCompressedLoop
)

type queryInfo struct {
	Name string
	Type uint16
	ID   uint16
}

type dnsTestServer struct {
	ln       net.Listener
	behavior atomic.Int32
	active   atomic.Int64
}

func newDNSTestServer(t *testing.T) *dnsTestServer {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &dnsTestServer{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.active.Add(1)
			go func() { defer s.active.Add(-1); defer c.Close(); s.handle(c) }()
		}
	}()
	return s
}
func (s *dnsTestServer) port() string           { return fmt.Sprintf("%d", s.ln.Addr().(*net.TCPAddr).Port) }
func (s *dnsTestServer) close()                 { _ = s.ln.Close() }
func (s *dnsTestServer) setBehavior(b behavior) { s.behavior.Store(int32(b)) }
func (s *dnsTestServer) handle(c net.Conn) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(hdr))
	if n < 12 || n > 4096 {
		return
	}
	q := make([]byte, n)
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	qi, err := parseQuery(q)
	if err != nil {
		return
	}
	switch behavior(s.behavior.Load()) {
	case behaveCloseMidResponse:
		resp := buildAResponse(qi.ID, qi.Name, qi.Type)
		frame := make([]byte, 2+len(resp)/2)
		binary.BigEndian.PutUint16(frame[:2], uint16(len(resp)))
		copy(frame[2:], resp[:len(resp)/2])
		_, _ = c.Write(frame)
	case behaveInvalidID:
		writeFrame(c, buildAResponse(qi.ID+1, qi.Name, qi.Type))
	case behaveShortGarbage:
		_, _ = c.Write([]byte{0, 1, 0xff})
	case behaveMissingRecord:
		writeFrame(c, buildNX(qi.ID, qi.Name, qi.Type))
	case behaveNoResponse:
		time.Sleep(1500 * time.Millisecond)
	case behaveInvalidRDLen:
		writeFrame(c, buildBadRDLen(qi.ID, qi.Name, qi.Type))
	case behaveCompressedLoop:
		writeFrame(c, buildCompressedLoop(qi.ID, qi.Name, qi.Type))
	default:
		switch qi.Type {
		case 1, 28:
			writeFrame(c, buildAResponse(qi.ID, qi.Name, qi.Type))
		case 12:
			writeFrame(c, buildPTRResponse(qi.ID, qi.Name, qi.Type))
		default:
			writeFrame(c, buildNX(qi.ID, qi.Name, qi.Type))
		}
	}
}
func writeFrame(c net.Conn, msg []byte) {
	frame := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(msg)))
	copy(frame[2:], msg)
	_, _ = c.Write(frame)
}
func parseName(msg []byte, off int) (string, int, error) {
	var parts []string
	for {
		if off >= len(msg) {
			return "", 0, errors.New("oob")
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(msg) {
			return "", 0, errors.New("bad")
		}
		parts = append(parts, string(msg[off:off+l]))
		off += l
	}
	return strings.Join(parts, "."), off, nil
}
func parseQuery(q []byte) (queryInfo, error) {
	if len(q) < 12 {
		return queryInfo{}, errors.New("short")
	}
	name, off, err := parseName(q, 12)
	if err != nil || off+4 > len(q) {
		return queryInfo{}, errors.New("badq")
	}
	return queryInfo{Name: name, Type: binary.BigEndian.Uint16(q[off:]), ID: binary.BigEndian.Uint16(q[:2])}, nil
}
func encName(name string) []byte {
	var out []byte
	for _, p := range strings.Split(name, ".") {
		out = append(out, byte(len(p)))
		out = append(out, p...)
	}
	return append(out, 0)
}
func hdr(id, flags, qd, an uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], flags)
	binary.BigEndian.PutUint16(b[4:6], qd)
	binary.BigEndian.PutUint16(b[6:8], an)
	return b
}
func buildAResponse(id uint16, name string, qtype uint16) []byte {
	qn := encName(name)
	msg := hdr(id, 0x8180, 1, 1)
	msg = append(msg, qn...)
	msg = append(msg, byte(qtype>>8), byte(qtype), 0, 1)
	msg = append(msg, 0xc0, 0x0c, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 60)
	if qtype == 28 {
		msg = append(msg, 0, 16)
		msg = append(msg, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}...)
	} else {
		msg = append(msg, 0, 4, 203, 0, 113, 7)
	}
	return msg
}
func buildPTRResponse(id uint16, name string, qtype uint16) []byte {
	qn := encName(name)
	ptr := encName("dummy.test")
	msg := hdr(id, 0x8180, 1, 1)
	msg = append(msg, qn...)
	msg = append(msg, 0, 12, 0, 1, 0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60, byte(len(ptr)>>8), byte(len(ptr)))
	msg = append(msg, ptr...)
	return msg
}
func buildNX(id uint16, name string, qtype uint16) []byte {
	qn := encName(name)
	msg := hdr(id, 0x8183, 1, 0)
	msg = append(msg, qn...)
	msg = append(msg, byte(qtype>>8), byte(qtype), 0, 1)
	return msg
}
func buildBadRDLen(id uint16, name string, qtype uint16) []byte {
	qn := encName(name)
	msg := hdr(id, 0x8180, 1, 1)
	msg = append(msg, qn...)
	msg = append(msg, byte(qtype>>8), byte(qtype), 0, 1, 0xc0, 0x0c, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 60, 0, 10, 1, 2, 3, 4)
	return msg
}
func buildCompressedLoop(id uint16, name string, qtype uint16) []byte {
	qn := encName(name)
	msg := hdr(id, 0x8180, 1, 1)
	msg = append(msg, qn...)
	msg = append(msg, byte(qtype>>8), byte(qtype), 0, 1)
	msg = append(msg, 0xc0, 0x2d, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 7)
	for len(msg) < 0x2d {
		msg = append(msg, 0)
	}
	msg = append(msg, 0xc0, 0x2d)
	return msg
}

type built struct{ libPath, cliPath string }

func buildArtifacts(t *testing.T) built {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	dir := t.TempDir()
	src := filepath.Join(".", "..")
	run := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = src
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v failed: %v\n%s", args, err, out)
		}
	}
	lib := filepath.Join(dir, "libpreload_dns_test.so")
	cli := filepath.Join(dir, "client_helper")
	run("cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-O2", "-o", lib, "../preload/dns/preload_dns.c", "../tests/preload/dns_transport_test.c", "-ldl", "-pthread")
	run("cc", "-Wall", "-Wextra", "-O2", "-o", cli, "../preload/dns/client_helper.c", "-pthread", "-lresolv")
	return built{libPath: lib, cliPath: cli}
}
func runClient(t *testing.T, b built, s *dnsTestServer, mode string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, b.cliPath, append([]string{mode}, args...)...)
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+b.libPath, "PRELOAD_DNS_TEST_HOST=127.0.0.1", "PRELOAD_DNS_TEST_PORT="+s.port(), "PRELOAD_DNS_TIMEOUT_MS=200")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestPreloadDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("preload DNS integration test skipped in -short mode")
	}
	b := buildArtifacts(t)
	t.Run("happy", func(t *testing.T) {
		s := newDNSTestServer(t)
		defer s.close()
		s.setBehavior(behaveNormal)
		cases := []struct {
			mode string
			args []string
			want string
		}{
			{"gai4", []string{"dummy.test"}, "OK 203.0.113.7 80"},
			{"gai6", []string{"localhost"}, "OK ::1"},
			{"legacy", []string{"dummy.test"}, "OK 203.0.113.7"},
			{"reverse", []string{"203.0.113.7"}, "OK dummy.test 443"},
			{"ghba", []string{"203.0.113.7"}, "OK dummy.test"},
			{"resq", []string{"dummy.test", "1"}, "OK "},
		}
		for _, tc := range cases {
			out, err := runClient(t, b, s, tc.mode, tc.args...)
			if err != nil || !strings.Contains(out, tc.want) {
				t.Fatalf("%s failed err=%v out=%q", tc.mode, err, out)
			}
		}
	})
	t.Run("invalid-hostnames-no-contact", func(t *testing.T) {
		s := newDNSTestServer(t)
		defer s.close()
		bad := []string{".bad", "bad.", "a..b", "-x.test", "x-.test", "bad_underscore.test", strings.Repeat("a", 64) + ".test"}
		for _, name := range bad {
			_, _ = runClient(t, b, s, "gai4", name)
		}
		time.Sleep(100 * time.Millisecond)
		if got := s.active.Load(); got != 0 {
			t.Fatalf("server contacted for invalid names: %d", got)
		}
	})
	mkFail := func(name string, beh behavior) {
		t.Run(name, func(t *testing.T) {
			s := newDNSTestServer(t)
			defer s.close()
			s.setBehavior(beh)
			out, err := runClient(t, b, s, "gai4", "dummy.test")
			if err == nil {
				t.Fatalf("expected failure got %q", out)
			}
		})
	}
	mkFail("close-before-finished-response", behaveCloseMidResponse)
	mkFail("invalid-transaction-id", behaveInvalidID)
	mkFail("garbage-short-length", behaveShortGarbage)
	mkFail("missing-records", behaveMissingRecord)
	mkFail("invalid-record-rdlen", behaveInvalidRDLen)
	mkFail("compression-loop", behaveCompressedLoop)
	t.Run("timeout-no-hang-no-active-leak", func(t *testing.T) {
		s := newDNSTestServer(t)
		defer s.close()
		s.setBehavior(behaveNoResponse)
		for i := 0; i < 8; i++ {
			_, _ = runClient(t, b, s, "gai4", "dummy.test")
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if s.active.Load() == 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("connections still active: %d", s.active.Load())
	})
	t.Run("concurrent-10x20", func(t *testing.T) {
		s := newDNSTestServer(t)
		defer s.close()
		out, err := runClient(t, b, s, "concurrent", "dummy.test", "10", "20")
		if err != nil || !strings.Contains(out, "OK concurrent 10 20") {
			t.Fatalf("concurrent err=%v out=%q", err, out)
		}
	})
	t.Run("parallel-process-thread-safety", func(t *testing.T) {
		s := newDNSTestServer(t)
		defer s.close()
		modes := [][]string{{"gai4", "dummy.test"}, {"legacy", "dummy.test"}, {"reverse", "203.0.113.7"}, {"resq", "dummy.test", "1"}}
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				m := modes[i%len(modes)]
				out, err := runClient(t, b, s, m[0], m[1:]...)
				if err != nil {
					errs <- fmt.Errorf("%v: %v %s", m, err, out)
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
	})
	t.Run("fuzzish-hostnames-never-crash", func(t *testing.T) {
		s := newDNSTestServer(t)
		defer s.close()
		rnd := rand.New(rand.NewSource(1))
		alpha := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._\x01\x7f")
		for i := 0; i < 200; i++ {
			n := 1 + rnd.Intn(80)
			bts := make([]byte, n)
			for j := range bts {
				bts[j] = alpha[rnd.Intn(len(alpha))]
			}
			_, _ = runClient(t, b, s, "gai4", string(bts))
		}
	})
}

