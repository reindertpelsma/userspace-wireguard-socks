// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build lite

package buildcfg

const (
	Lite                    = true
	HasMeshControl          = false
	HasTrafficShaper        = false
	HasAdvancedWGTransports = false
)
