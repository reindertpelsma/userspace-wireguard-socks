// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package wgbind

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
	"golang.zx2c4.com/wireguard/conn"
)

type TURNBind struct {
	Server   string
	Username string
	Password string
	Realm    string
	// Permissions are updated dynamically
	AllowedPeers []string
	AllocatedPeers []string

	IncludeWGPublicKey bool
	WGPublicKey        [32]byte

	mu         sync.Mutex
	client     *turn.Client
	relayConn  net.PacketConn
	mappedAddr net.Addr
	closed     chan struct{}
	open       bool
}

func (b *TURNBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	username := b.Username
	if b.IncludeWGPublicKey {
		encrypted, err := encryptPublicKey(b.WGPublicKey[:], b.Password)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to encrypt WG public key: %w", err)
		}
		username = fmt.Sprintf("%s---%s", b.Username, encrypted)
	}

	// Create a local UDP socket to communicate with TURN server
	network := "udp4" // Default to IPv4 for TURN for now
	c, err := net.ListenPacket(network, "0.0.0.0:0")
	if err != nil {
		return nil, 0, err
	}

	cfg := &turn.ClientConfig{
		STUNServerAddr: b.Server,
		TURNServerAddr: b.Server,
		Conn:           c,
		Username:       username,
		Password:       b.Password,
		Realm:          b.Realm,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	b.client = client

	err = client.Listen()
	if err != nil {
		client.Close()
		return nil, 0, err
	}

	// Allocate a relay
	relayConn, err := client.Allocate()
	if err != nil {
		client.Close()
		return nil, 0, err
	}
	b.relayConn = relayConn
	b.mappedAddr = relayConn.LocalAddr()

	log.Printf("WireGuard TURN relay allocated: %s", b.mappedAddr.String())

	b.closed = make(chan struct{})
	b.open = true

	// Initial permissions if any
	b.refreshPermissionsLocked()

	return []conn.ReceiveFunc{b.receive}, uint16(b.mappedAddr.(*net.UDPAddr).Port), nil
}

func (b *TURNBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n, addr, err := b.relayConn.ReadFrom(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	ap := addr.(*net.UDPAddr).AddrPort()
	eps[0] = &Endpoint{AddrPort: ap}
	return 1, nil
}

func (b *TURNBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	ap, err := endpointAddrPort(ep)
	if err != nil {
		return err
	}
	dest := net.UDPAddrFromAddrPort(ap)
	
	b.mu.Lock()
	if !b.open {
		b.mu.Unlock()
		return net.ErrClosed
	}
	b.mu.Unlock()

	for _, buf := range bufs {
		if _, err := b.relayConn.WriteTo(buf, dest); err != nil {
			return err
		}
	}
	return nil
}

func (b *TURNBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	close(b.closed)
	if b.relayConn != nil {
		b.relayConn.Close()
	}
	if b.client != nil {
		b.client.Close()
	}
	b.open = false
	return nil
}

func (b *TURNBind) SetMark(uint32) error { return nil }
func (b *TURNBind) BatchSize() int       { return 1 }

func (b *TURNBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := resolveAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &Endpoint{AddrPort: ap}, nil
}

func (b *TURNBind) UpdatePermissions(ips []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.AllowedPeers = ips
	if b.open {
		b.refreshPermissionsLocked()
	}
}

func (b *TURNBind) refreshPermissionsLocked() {
	if b.client == nil {
		return
	}
	for _, ip := range b.AllowedPeers {
		found := false
		for _, ip2 := range b.AllocatedPeers {
                    if ip == ip2 {
                        found = true
			break
	            }
		}
		if found {
		    continue // Changed to continue from break for clarity
		}
		b.AllocatedPeers = append(b.AllocatedPeers, ip)
		addr, err := net.ResolveUDPAddr("udp", ip)
		if err != nil {
                        // TURN permissions do not need port, lets set port to 0 assuming the caller did only specify an IP
			ip_parsed := net.ParseIP(ip)
			if ip_parsed != nil {
			        addr = &net.UDPAddr{
                                        IP:  ip_parsed, 
                                        Port: 5, // ignored by TURN CreatePermission
                                }
				err = nil
		        }
		}
		if err == nil {
			_ = b.client.CreatePermission(addr)
		} else {
                       log.Printf("Failed to create permission on TURN for invalid address: %v\n", err)
		}
	}
}

func encryptPublicKey(pubKey []byte, password string) (string, error) {
	key := make([]byte, 32)
	copy(key, password)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nil, nonce, pubKey, nil)
	// Combine nonce and ciphertext for Base64 encoding
	combined := make([]byte, len(nonce)+len(ciphertext))
	copy(combined, nonce)
	copy(combined[len(nonce):], ciphertext)
	return base64.StdEncoding.EncodeToString(combined), nil
}
