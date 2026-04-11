// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package malicious

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func mustStartEngine(t testing.TB, cfg config.Config) *engine.Engine {
	t.Helper()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

func mustKey(t testing.TB) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func socksConnectReply(t testing.TB, socksAddr string, dst netip.AddrPort) byte {
	t.Helper()
	conn := socksControl(t, socksAddr)
	defer conn.Close()
	if _, err := conn.Write(socksConnectRequest(dst)); err != nil {
		t.Fatal(err)
	}
	rep, _, err := readSOCKSReply(conn)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func socksControl(t testing.TB, socksAddr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if resp != [2]byte{0x05, 0x00} {
		_ = conn.Close()
		t.Fatalf("SOCKS greeting failed: %v", resp)
	}
	return conn
}

func socksConnectRequest(dst netip.AddrPort) []byte {
	out := []byte{0x05, 0x01, 0x00}
	if dst.Addr().Is6() {
		out = append(out, 0x04)
		ip := dst.Addr().As16()
		out = append(out, ip[:]...)
	} else {
		out = append(out, 0x01)
		ip := dst.Addr().As4()
		out = append(out, ip[:]...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], dst.Port())
	out = append(out, port[:]...)
	return out
}

func readSOCKSReply(r io.Reader) (byte, netip.AddrPort, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if hdr[0] != 0x05 {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid SOCKS reply version %d", hdr[0])
	}
	var addr netip.Addr
	switch hdr[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		addr = netip.AddrFrom4(b)
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		addr = netip.AddrFrom16(b)
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported SOCKS reply address type %d", hdr[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	return hdr[1], netip.AddrPortFrom(addr, binary.BigEndian.Uint16(port[:])), nil
}

func apiRequest(t testing.TB, addr, token, method, path string, body any) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
		r = &buf
	}
	req, err := http.NewRequest(method, "http://"+addr+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	text, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, text
}
