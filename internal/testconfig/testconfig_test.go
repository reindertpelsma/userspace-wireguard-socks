// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package testconfig

import (
	"testing"
)

func TestEnvBool(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"yes", true},
		{"YES", true},
		{"0", false},
		{"false", false},
		{"", false},
		{"  ", false},
	} {
		t.Setenv("UWGS_TEST_ENVBOOL_TMP", tc.val)
		if got := envBool("UWGS_TEST_ENVBOOL_TMP"); got != tc.want {
			t.Errorf("envBool(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("UWGS_TEST_ENVINT_TMP", "42")
	if got := envInt("UWGS_TEST_ENVINT_TMP"); got != 42 {
		t.Errorf("envInt = %d, want 42", got)
	}
	t.Setenv("UWGS_TEST_ENVINT_TMP", "0")
	if got := envInt("UWGS_TEST_ENVINT_TMP"); got != 0 {
		t.Errorf("envInt(0) = %d, want 0", got)
	}
	t.Setenv("UWGS_TEST_ENVINT_TMP", "bad")
	if got := envInt("UWGS_TEST_ENVINT_TMP"); got != 0 {
		t.Errorf("envInt(bad) = %d, want 0", got)
	}
}

func TestApplyEnvBoolGates(t *testing.T) {
	cfg := Config{}
	t.Setenv("UWGS_SOAK", "1")
	t.Setenv("UWGS_STRESS", "1")
	t.Setenv("UWGS_SOAK_SECONDS", "300")
	t.Setenv("UWGS_CHROME_BIN", "/usr/bin/chromium")
	applyEnv(&cfg)
	if !cfg.Soak {
		t.Error("expected Soak=true")
	}
	if !cfg.Stress {
		t.Error("expected Stress=true")
	}
	if cfg.SoakSeconds != 300 {
		t.Errorf("expected SoakSeconds=300, got %d", cfg.SoakSeconds)
	}
	if cfg.ChromeBin != "/usr/bin/chromium" {
		t.Errorf("expected ChromeBin=/usr/bin/chromium, got %q", cfg.ChromeBin)
	}
}

func TestEnableAllSetsGates(t *testing.T) {
	cfg := Config{All: true}
	enableAll(&cfg)
	for _, tc := range []struct {
		name string
		val  bool
	}{
		{"RealTUN", cfg.RealTUN},
		{"Soak", cfg.Soak},
		{"Stress", cfg.Stress},
		{"MeshChaos", cfg.MeshChaos},
		{"Perf", cfg.Perf},
		{"Examples", cfg.Examples},
	} {
		if !tc.val {
			t.Errorf("enableAll: %s should be true", tc.name)
		}
	}
	// These are modifiers, not gates — must NOT be set by enableAll.
	if cfg.StrictStdioHotpath {
		t.Error("enableAll should not set StrictStdioHotpath")
	}
	if cfg.VerboseStress {
		t.Error("enableAll should not set VerboseStress")
	}
}
