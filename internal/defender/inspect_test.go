package defender

import (
	"testing"
	"time"
)

func TestEvaluateComplianceAndPresets(t *testing.T) {
	orders := DefaultStandingOrders()
	if orders.PresetName != "quiet-guardian" {
		t.Fatalf("expected default preset quiet-guardian, got %s", orders.PresetName)
	}

	// Simulate matching live state
	st := DeputyStatus{
		ServiceRunning:         true,
		TamperProtectionActive: false,
		RealtimeProtection:     true,
		BehaviorMonitoring:     true,
		IOAVProtection:         true,
		ScriptScanning:         true,
		NetworkProtection:      0,
		CloudProtection:        0,
		SampleSubmission:       2,
		NagsSuppressed:         true,
		EnhancedNagsSuppressed: true,
	}

	ok, drift := EvaluateCompliance(st, orders, nil)
	if !ok || len(drift) != 0 {
		t.Fatalf("expected full compliance, got drift: %v", drift)
	}

	// Simulate active Stand-Down where Real-Time Protection is temporarily OFF
	sd := &StandDownState{
		Active:    true,
		Reason:    "30m Pause",
		StartedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	st.RealtimeProtection = false
	ok, drift = EvaluateCompliance(st, orders, sd)
	if !ok || len(drift) != 0 {
		t.Fatalf("expected compliance during active Stand-Down, got drift: %v", drift)
	}

	// Simulate Windows Update turning Cloud Protection back on and Nags back on
	st.RealtimeProtection = true
	st.CloudProtection = 2
	st.NagsSuppressed = false
	ok, drift = EvaluateCompliance(st, orders, nil)
	if ok || len(drift) != 2 {
		t.Fatalf("expected 2 drift items, got ok=%v drift=%v", ok, drift)
	}
}

func TestLiveInspectRunsCleanly(t *testing.T) {
	orders := DefaultStandingOrders()
	st := Inspect(&orders, nil)
	if st.InspectedAt.IsZero() {
		t.Fatal("expected non-zero InspectedAt")
	}
}
