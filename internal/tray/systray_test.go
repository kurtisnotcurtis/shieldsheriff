package tray

import (
	"strings"
	"testing"

	"shieldsheriff/internal/defender"
)

func TestTrayRunningIndicators(t *testing.T) {
	ord := defender.StandingOrders{PresetName: "quiet-guardian"}

	tipOK := formatTrayTip("http://127.0.0.1:38419", defender.DeputyStatus{
		InCompliance:       true,
		RealtimeProtection: true,
	}, ord, defender.StandDownState{})
	if !strings.Contains(tipOK, "Running (127.0.0.1:38419)") {
		t.Fatalf("expected compliance tip to indicate running server, got %q", tipOK)
	}

	tipDrift := formatTrayTip("http://127.0.0.1:38419", defender.DeputyStatus{
		InCompliance: false,
		DriftItems:   []string{"Real-Time Protection"},
	}, ord, defender.StandDownState{})
	if !strings.Contains(tipDrift, "Running (127.0.0.1:38419)") {
		t.Fatalf("expected drift tip to indicate running server, got %q", tipDrift)
	}

	tipSD := formatTrayTip("http://127.0.0.1:38419", defender.DeputyStatus{}, ord, defender.StandDownState{
		Active: true,
		Reason: "15m Manual Stand-Down",
	})
	if !strings.Contains(tipSD, "Running (127.0.0.1:38419)") {
		t.Fatalf("expected stand-down tip to indicate running server, got %q", tipSD)
	}

	lblAdmin := formatTrayStatusLabel("http://127.0.0.1:38419", defender.DeputyStatus{IsElevated: true})
	if !strings.Contains(lblAdmin, "Running") || !strings.Contains(lblAdmin, "127.0.0.1:38419") || !strings.Contains(lblAdmin, "Admin") {
		t.Fatalf("unexpected admin status label: %q", lblAdmin)
	}

	lblUser := formatTrayStatusLabel("", defender.DeputyStatus{IsElevated: false})
	if !strings.Contains(lblUser, "Running") || !strings.Contains(lblUser, "Read-Only") {
		t.Fatalf("unexpected read-only status label: %q", lblUser)
	}
}
