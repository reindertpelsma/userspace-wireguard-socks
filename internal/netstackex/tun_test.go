// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package netstackex

import (
	"encoding/binary"
	"testing"
)

func TestClampMSS_IPv4(t *testing.T) {
	tun := &netTun{
		mtu:         1420,
		tcpMSSClamp: true,
	}

	// IPv4 TCP SYN packet with MSS 1460 (standard Ethernet)
	packet := make([]byte, 44)
	packet[0] = 0x45 // IPv4, IHL 5
	packet[9] = 6    // TCP
	copy(packet[12:16], []byte{10, 0, 0, 1}) // Src
	copy(packet[16:20], []byte{10, 0, 0, 2}) // Dst

	tcp := packet[20:]
	tcp[13] = 0x02 // SYN
	tcp[12] = 0x60 // Data offset 6 (24 bytes)
	
	// MSS option: type 2, size 4, value 1460
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], 1460)

	// Original checksum (not validated here, just set to non-zero)
	tcp[16] = 0xAB
	tcp[17] = 0xCD

	tun.clampMSS(packet)

	// Max MSS for MTU 1420 should be 1420 - 40 = 1380
	gotMSS := binary.BigEndian.Uint16(tcp[22:24])
	if gotMSS != 1380 {
		t.Errorf("got MSS %d, want 1380", gotMSS)
	}

	// Checksum should be zeroed
	if tcp[16] != 0 || tcp[17] != 0 {
		t.Error("TCP checksum was not zeroed after modification")
	}
}

func TestClampMSS_IPv6(t *testing.T) {
	tun := &netTun{
		mtu:         1280,
		tcpMSSClamp: true,
	}

	// IPv6 TCP SYN packet with MSS 1440
	packet := make([]byte, 64)
	packet[0] = 0x60 // IPv6
	packet[6] = 6    // TCP
	
	tcp := packet[40:]
	tcp[13] = 0x02 // SYN
	tcp[12] = 0x60 // Data offset 6 (24 bytes)
	
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], 1440)

	tun.clampMSS(packet)

	// Max MSS for IPv6 on MTU 1280 should be 1280 - 60 = 1220
	gotMSS := binary.BigEndian.Uint16(tcp[22:24])
	if gotMSS != 1220 {
		t.Errorf("got MSS %d, want 1220", gotMSS)
	}
}

func TestClampMSS_NoSYN(t *testing.T) {
	tun := &netTun{
		mtu:         1420,
		tcpMSSClamp: true,
	}

	packet := make([]byte, 44)
	packet[0] = 0x45
	packet[9] = 6
	tcp := packet[20:]
	tcp[13] = 0x10 // ACK only
	tcp[12] = 0x60
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], 1460)

	tun.clampMSS(packet)

	gotMSS := binary.BigEndian.Uint16(tcp[22:24])
	if gotMSS != 1460 {
		t.Errorf("MSS was clamped on non-SYN packet: got %d, want 1460", gotMSS)
	}
}

func TestClampMSS_Disabled(t *testing.T) {
	tun := &netTun{
		mtu:         1420,
		tcpMSSClamp: false,
	}

	packet := make([]byte, 44)
	packet[0] = 0x45
	packet[9] = 6
	tcp := packet[20:]
	tcp[13] = 0x02 // SYN
	tcp[12] = 0x60
	tcp[20] = 2
	tcp[21] = 4
	binary.BigEndian.PutUint16(tcp[22:24], 1460)

	tun.clampMSS(packet)

	gotMSS := binary.BigEndian.Uint16(tcp[22:24])
	if gotMSS != 1460 {
		t.Errorf("MSS was clamped while disabled: got %d, want 1460", gotMSS)
	}
}
