package defender

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRegVal struct {
	kind   RegValueKind
	dword  uint32
	strVal string
}

type recordedCmd struct {
	name        string
	args        []string
	hasDeadline bool
}

type fakeBackend struct {
	mu          sync.Mutex
	elevated    bool
	vals        map[string]fakeRegVal
	files       map[string]bool
	failWrites  map[string]error
	failDeletes map[string]error
	failCmd     error
	commands    []recordedCmd
}

func newFakeBackend(elevated bool) *fakeBackend {
	return &fakeBackend{
		elevated:    elevated,
		vals:        make(map[string]fakeRegVal),
		files:       make(map[string]bool),
		failWrites:  make(map[string]error),
		failDeletes: make(map[string]error),
	}
}

func fakeKey(root RegRoot, subkey, name string) string {
	r := "HKLM"
	if root == HKCU {
		r = "HKCU"
	}
	return r + `\` + subkey + `\` + name
}

func (f *fakeBackend) IsElevated() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.elevated
}

func (f *fakeBackend) ReadDword(root RegRoot, subkey, name string) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vals[fakeKey(root, subkey, name)]
	if !ok || v.kind != RegDword {
		return 0, false
	}
	return v.dword, true
}

func (f *fakeBackend) ReadString(root RegRoot, subkey, name string) (string, RegValueKind, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vals[fakeKey(root, subkey, name)]
	if !ok || (v.kind != RegSZ && v.kind != RegExpandSZ) {
		return "", 0, false
	}
	return v.strVal, v.kind, true
}

func (f *fakeBackend) WriteDword(root RegRoot, subkey, name string, val uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := fakeKey(root, subkey, name)
	if err := f.failWrites[k]; err != nil {
		return err
	}
	f.vals[k] = fakeRegVal{kind: RegDword, dword: val}
	return nil
}

func (f *fakeBackend) WriteString(root RegRoot, subkey, name string, val string, kind RegValueKind) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := fakeKey(root, subkey, name)
	if err := f.failWrites[k]; err != nil {
		return err
	}
	f.vals[k] = fakeRegVal{kind: kind, strVal: val}
	return nil
}

func (f *fakeBackend) DeleteValue(root RegRoot, subkey, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := fakeKey(root, subkey, name)
	if err := f.failDeletes[k]; err != nil {
		return err
	}
	delete(f.vals, k)
	return nil
}

func (f *fakeBackend) RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, hasDeadline := ctx.Deadline()
	f.commands = append(f.commands, recordedCmd{name: name, args: args, hasDeadline: hasDeadline})
	if f.failCmd != nil {
		return "simulated failure", f.failCmd
	}
	return "ok", nil
}

func (f *fakeBackend) FileExists(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.files[path]
}

func TestEvaluateComplianceAndPresets(t *testing.T) {
	pol := DefaultPolicy()
	if pol.PresetID != "local-protection" {
		t.Fatalf("expected default preset local-protection, got %s", pol.PresetID)
	}
	if _, ok := FindPreset("workstation"); !ok {
		t.Fatal("expected workstation preset to be found")
	}
	if got := PresetDisplayName("cloud-local"); got != "Cloud + Local" {
		t.Fatalf("unexpected display name: %q", got)
	}

	st := Status{
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

	ok, drift := EvaluateCompliance(st, pol, nil)
	if !ok || len(drift) != 0 {
		t.Fatalf("expected full compliance, got drift: %v", drift)
	}

	pause := &PauseState{
		Active:    true,
		Reason:    "30m Pause",
		StartedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}
	st.RealtimeProtection = false
	ok, drift = EvaluateCompliance(st, pol, pause)
	if !ok || len(drift) != 0 {
		t.Fatalf("expected compliance during active Pause, got drift: %v", drift)
	}

	st.RealtimeProtection = true
	st.CloudProtection = 2
	st.NagsSuppressed = false
	ok, drift = EvaluateCompliance(st, pol, nil)
	if ok || len(drift) != 2 {
		t.Fatalf("expected 2 drift items, got ok=%v drift=%v", ok, drift)
	}
}

func TestEnforceSnapshotAndFullRevert(t *testing.T) {
	b := newFakeBackend(true)

	// Pre-existing Defender & Windows state before ShieldSheriff ever runs
	_ = b.WriteDword(HKLM, keyDefRTP, "DisableRealtimeMonitoring", 0)
	_ = b.WriteDword(HKLM, keyDefSpynet, "SpyNetReporting", 2)
	_ = b.WriteDword(HKLM, keyDefSpynet, "SubmitSamplesConsent", 1)
	_ = b.WriteDword(HKLM, keyDefUX, "Notification_Suppress", 0)
	_ = b.WriteDword(HKCU, keyToastSec, "Enabled", 1)
	_ = b.WriteString(HKLM, keyWinRun, "SecurityHealth", `%windir%\system32\SecurityHealthSystray.exe`, RegExpandSZ)

	// Apply On-Demand Only (mutes systray, disables RTP, silences nags, writes policies + live keys)
	preset, _ := FindPreset("on-demand")
	res := EnforceWith(b, preset.Policy, nil)
	if !res.Success {
		t.Fatalf("expected EnforceWith success, got warnings: %v", res.Warnings)
	}

	// Verify PowerShell command ran with an explicit timeout deadline
	foundPS := false
	for _, c := range b.commands {
		if c.name == "powershell.exe" {
			foundPS = true
			if !c.hasDeadline {
				t.Fatal("expected powershell.exe Set-MpPreference call to have a context deadline")
			}
		}
	}
	if !foundPS {
		t.Fatal("expected powershell.exe WMI sync command to run")
	}

	// Verify InspectWith sees full compliance after EnforceWith
	st := InspectWith(b, &preset.Policy, nil)
	if !st.InCompliance {
		t.Fatalf("expected full compliance after EnforceWith, got drift: %v", st.DriftItems)
	}
	if st.RealtimeProtection {
		t.Fatal("expected RealtimeProtection=false in on-demand preset")
	}

	// Now revert via RevertPoliciesWith and verify ALL pre-ShieldSheriff values are restored
	rev := RevertPoliciesWith(b)
	if !rev.Success {
		t.Fatalf("expected RevertPoliciesWith success, got warnings: %v", rev.Warnings)
	}

	// Policy keys that didn't exist before must be deleted (including DisableAntiSpyware, DisableRealtimeMonitoring, etc.)
	for _, check := range [][2]string{
		{keyPolBase, "DisableAntiSpyware"},
		{keyPolBase, "DisableAntiVirus"},
		{keyPolRTP, "DisableRealtimeMonitoring"},
		{keyPolSpynet, "SpynetReporting"},
		{keyPolWSCNotif, "DisableNotifications"},
		{keyPolWSCSystray, "HideSystray"},
	} {
		if _, ok := b.ReadDword(HKLM, check[0], check[1]); ok {
			t.Fatalf("expected policy key %s\\%s to be deleted after revert", check[0], check[1])
		}
	}

	// Live keys & Run entry that existed before must be restored to their exact original values
	if v, ok := b.ReadDword(HKLM, keyDefRTP, "DisableRealtimeMonitoring"); !ok || v != 0 {
		t.Fatalf("expected live DisableRealtimeMonitoring restored to 0, got %d (ok=%v)", v, ok)
	}
	if v, ok := b.ReadDword(HKLM, keyDefSpynet, "SpyNetReporting"); !ok || v != 2 {
		t.Fatalf("expected live SpyNetReporting restored to 2, got %d (ok=%v)", v, ok)
	}
	if v, ok := b.ReadDword(HKLM, keyDefUX, "Notification_Suppress"); !ok || v != 0 {
		t.Fatalf("expected defUX Notification_Suppress restored to 0, got %d (ok=%v)", v, ok)
	}
	if v, ok := b.ReadDword(HKCU, keyToastSec, "Enabled"); !ok || v != 1 {
		t.Fatalf("expected HKCU toast Enabled restored to 1, got %d (ok=%v)", v, ok)
	}
	if s, _, ok := b.ReadString(HKLM, keyWinRun, "SecurityHealth"); !ok || !strings.Contains(s, "SecurityHealthSystray.exe") {
		t.Fatalf("expected SecurityHealth Run value restored, got %q (ok=%v)", s, ok)
	}
}

func TestInspectDetectsEngineIgnoringPolicy(t *testing.T) {
	b := newFakeBackend(true)
	// Policy says RTP disabled (1), but live Defender engine key says enabled (0)
	_ = b.WriteDword(HKLM, keyPolRTP, "DisableRealtimeMonitoring", 1)
	_ = b.WriteDword(HKLM, keyDefRTP, "DisableRealtimeMonitoring", 0)

	pol := DefaultPolicy()
	pol.RealtimeProtection = false
	st := InspectWith(b, &pol, nil)
	if !st.RealtimeProtection {
		t.Fatal("expected InspectWith to report live Defender state (ON) rather than masking with Policy key")
	}
	if st.InCompliance {
		t.Fatal("expected drift when live Defender key disagrees with Policy")
	}
}

func TestEnforceAndRevertPropagateErrors(t *testing.T) {
	b := newFakeBackend(true)
	b.failWrites[fakeKey(HKLM, keyPolRTP, "DisableRealtimeMonitoring")] = errors.New("access denied")

	res := EnforceWith(b, DefaultPolicy(), nil)
	if res.Success {
		t.Fatal("expected EnforceWith Success=false when a policy write fails")
	}
	if len(res.Warnings) == 0 {
		t.Fatal("expected failure warning to be recorded")
	}
	for _, a := range res.Applied {
		if strings.Contains(a, "DisableRealtimeMonitoring") {
			t.Fatalf("failed write must not be reported in Applied: %v", res.Applied)
		}
	}

	b.failDeletes[fakeKey(HKLM, keyPolRTP, "DisableBehaviorMonitoring")] = errors.New("delete denied")
	rev := RevertPoliciesWith(b)
	if rev.Success {
		t.Fatal("expected RevertPoliciesWith Success=false when a registry delete fails")
	}
}

func TestPolicyValidateRejectsInvalidEnums(t *testing.T) {
	p := DefaultPolicy()
	p.NetworkProtection = 9
	if err := p.Validate(); err == nil {
		t.Fatal("expected invalid NetworkProtection to fail validation")
	}
	p = DefaultPolicy()
	p.CloudProtection = 4
	if err := p.Validate(); err == nil {
		t.Fatal("expected invalid CloudProtection to fail validation")
	}
	p = DefaultPolicy()
	p.SampleSubmission = 7
	if err := p.Validate(); err == nil {
		t.Fatal("expected invalid SampleSubmission to fail validation")
	}
}
