//go:build windows

package tray

import (
	"strings"
	"testing"

	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
)

func TestTrayRunningIndicators(t *testing.T) {
	cfg := sheriff.Config{
		Mode:   defender.ModeActive,
		Policy: defender.Policy{PresetID: "local-protection"},
	}

	tipOK := formatTrayTip(defender.Status{
		InCompliance:       true,
		RealtimeProtection: true,
	}, cfg)
	if tipOK != "ShieldSheriff: Local Protection" {
		t.Fatalf("unexpected preset tip: %q", tipOK)
	}

	tipPassive := formatTrayTip(defender.Status{
		InCompliance: true,
	}, sheriff.Config{Mode: defender.ModePassive})
	if !strings.Contains(tipPassive, "Passive Mode") {
		t.Fatalf("unexpected passive tip: %q", tipPassive)
	}

	tipDrift := formatTrayTip(defender.Status{
		InCompliance: false,
		DriftItems:   []string{"Real-Time Protection"},
	}, cfg)
	if !strings.Contains(tipDrift, "Local Protection") || !strings.Contains(tipDrift, "1 Drift Item(s)") {
		t.Fatalf("unexpected drift tip: %q", tipDrift)
	}

	cfgPaused := cfg
	cfgPaused.Pause = defender.PauseState{Active: true, Reason: "15m Pause"}
	tipPaused := formatTrayTip(defender.Status{}, cfgPaused)
	if !strings.Contains(tipPaused, "Paused (15m Pause)") {
		t.Fatalf("unexpected pause tip: %q", tipPaused)
	}
}
