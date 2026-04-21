// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package config

import "fmt"

func validateBuildConfig(c *Config) error {
	if !c.TrafficShaper.IsZero() {
		return fmt.Errorf("traffic_shaper is not supported in lite builds")
	}
	for i, peer := range c.WireGuard.Peers {
		if !peer.TrafficShaper.IsZero() {
			return fmt.Errorf("wireguard.peers[%d].traffic_shaper is not supported in lite builds", i)
		}
		if peer.ControlURL != "" || peer.MeshEnabled || peer.MeshAdvertise != nil || peer.MeshDisableACLs || peer.MeshAcceptACLs || (peer.MeshTrust != "" && peer.MeshTrust != MeshTrustUntrusted) {
			return fmt.Errorf("wireguard.peers[%d] mesh settings are not supported in lite builds", i)
		}
	}
	if c.MeshControl.Listen != "" || c.MeshControl.AdvertiseSelf {
		return fmt.Errorf("mesh_control is not supported in lite builds")
	}
	if c.TURN.Server != "" {
		return fmt.Errorf("turn is not supported in lite builds")
	}
	if len(c.Transports) > 0 {
		return fmt.Errorf("transports are not supported in lite builds; use the built-in UDP listener")
	}
	if c.WireGuard.DefaultTransport != "" {
		return fmt.Errorf("wireguard.default_transport is not supported in lite builds")
	}
	return nil
}
