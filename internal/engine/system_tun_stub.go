// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !linux

package engine

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

func systemCreateTUNDevice(name string, mtu int) (tun.Device, error) {
	return nil, errors.New("host TUN is only supported on Linux")
}

func configureHostTUNKernel(cfg hostTUNKernelConfig) error {
	return errors.New("host TUN kernel configuration is only supported on Linux")
}
