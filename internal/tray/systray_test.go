package tray

import (
	"strings"
	"testing"

	"shieldsheriff/internal/defender"
)

func TestTrayRunningIndicators(t *testing.T) {
	ord := defender.StandingOrders{PresetName: "local-protection", Elected: true}

	tipOK := formatTrayTip("http://127.0.0.1:38419", defender.DeputyStatus{
		InCompliance:       true,
		RealtimeProtection: true,
	}, ord, defender.StandDownState{})
	if tipOK != "ShieldSheriff: Local Protection" {
		t.Fatalf("unexpected preset tip: %q", tipOK)
	}

	tipPassive := formatTrayTip("http://127.0.0.1:38419", defender.DeputyStatus{
		InCompliance: true,
	}, defender.StandingOrders{PresetName: "passive", Elected: false}, defender.StandDownState{})
	if !strings.Contains(tipPassive, "Passive Mode") {
		t.Fatalf("unexpected passive tip: %q", tipPassive)
	}

	tipDrift := formatTrayTip("http://127.0.0.1:38419", defender.DeputyStatus{
		InCompliance: false,
		DriftItems:   []string{"Real-Time Protection"},
	}, ord, defender.StandDownState{})
	if !strings.Contains(tipDrift, "Local Protection") || !strings.Contains(tipDrift, "1 Drift Item(s)") {
		t.Fatalf("unexpected drift tip: %q", tipDrift)
	}

	tipSD := formatTrayTip("http://127.0.0.1:38419", defender.DeputyStatus{}, ord, defender.StandDownState{
		Active: true,
		Reason: "15m Pause",
	})
	if !strings.Contains(tipSD, "Paused (15m Pause)") {
		t.Fatalf("unexpected pause tip: %q", tipSD)
	}
}
