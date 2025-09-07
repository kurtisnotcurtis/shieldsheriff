package sheriff

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindRunningWatchedProcess(t *testing.T) {
	if m := FindRunningWatchedProcess([]string{"definitely_not_running_xyz999.exe"}); m != "" {
		t.Fatalf("expected empty match, got %q", m)
	}
	selfExe := filepath.Base(os.Args[0])
	if m := FindRunningWatchedProcess([]string{selfExe}); m == "" {
		t.Fatalf("expected current test binary %q to be detected via Toolhelp32 snapshot", selfExe)
	}
}

func TestGovernorStandDownLifecycle(t *testing.T) {
	gov := NewGovernor()
	gov.StartStandDown(10*time.Minute, "Unit Test Pause")
	_, _, sd, _, _ := gov.Snapshot()
	if !sd.Active || sd.Reason != "Unit Test Pause" {
		t.Fatalf("expected active stand-down, got %+v", sd)
	}

	gov.ResumeFromStandDown()
	_, _, sd, _, _ = gov.Snapshot()
	if sd.Active {
		t.Fatalf("expected stand-down to be inactive after resume")
	}
}
