//go:build windows

package sheriff

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"shieldsheriff/internal/defender"
)

// ControlEndpoint describes the running elevated interactive instance's authenticated
// loopback control API. It is stored under %ProgramData%\ShieldSheriff\control.json
// with a protected DACL granting access ONLY to Built-in Administrators and SYSTEM,
// so unelevated local processes cannot read the control token.
type ControlEndpoint struct {
	PID      int    `json:"pid"`
	Port     int    `json:"port"`
	Token    string `json:"token"`
	Elevated bool   `json:"elevated"`
}

// FocusEndpoint describes the running interactive instance's window-focus endpoint.
// Its focusToken is accepted ONLY by POST /api/focus and cannot mutate any setting.
type FocusEndpoint struct {
	PID        int    `json:"pid"`
	Port       int    `json:"port"`
	FocusToken string `json:"focusToken"`
}

func controlEndpointPath() string {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	return filepath.Join(progData, "ShieldSheriff", "control.json")
}

func focusEndpointPath() string {
	if localApp := os.Getenv("LOCALAPPDATA"); localApp != "" {
		return filepath.Join(localApp, "ShieldSheriff", "focus.json")
	}
	return filepath.Join(os.TempDir(), "shieldsheriff-focus.json")
}

// restrictToAdminsOnly applies a protected Windows DACL granting Full Control ONLY
// to Built-in Administrators (BA) and LocalSystem (SY), blocking unelevated processes.
func restrictToAdminsOnly(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;BA)(A;;GA;;;SY)")
	if err != nil {
		return fmt.Errorf("build admin-only SDDL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("extract DACL: %w", err)
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

func writeJSONAtomic(path string, v any, adminOnly bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "runtime-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if adminOnly {
		if err := restrictToAdminsOnly(tmpName); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if adminOnly {
		_ = restrictToAdminsOnly(path)
	}
	cleanup = false
	return nil
}

// WriteControlEndpoint publishes the running elevated server's authenticated endpoint
// so elevated CLI invocations coordinate with the running tray Governor.
func WriteControlEndpoint(ep ControlEndpoint) error {
	if !defender.IsProcessElevated() {
		return nil
	}
	return writeJSONAtomic(controlEndpointPath(), ep, true)
}

// ReadControlEndpoint reads the running elevated server's control endpoint (only readable when elevated).
func ReadControlEndpoint() (ControlEndpoint, error) {
	var ep ControlEndpoint
	data, err := os.ReadFile(controlEndpointPath())
	if err != nil {
		return ep, err
	}
	if err := json.Unmarshal(data, &ep); err != nil {
		return ep, err
	}
	if ep.Port <= 0 || ep.Token == "" {
		return ep, fmt.Errorf("incomplete control endpoint")
	}
	return ep, nil
}

// RemoveControlEndpoint cleans up control.json on shutdown if owned by pid.
func RemoveControlEndpoint(pid int) {
	ep, err := ReadControlEndpoint()
	if err == nil && ep.PID != pid {
		return
	}
	_ = os.Remove(controlEndpointPath())
}

// WriteFocusEndpoint publishes the listening port and focus-only token for window focus handoff.
func WriteFocusEndpoint(ep FocusEndpoint) error {
	return writeJSONAtomic(focusEndpointPath(), ep, false)
}

// ReadFocusEndpoint reads the running interactive instance's focus endpoint.
func ReadFocusEndpoint() (FocusEndpoint, error) {
	var ep FocusEndpoint
	data, err := os.ReadFile(focusEndpointPath())
	if err != nil {
		return ep, err
	}
	if err := json.Unmarshal(data, &ep); err != nil {
		return ep, err
	}
	if ep.Port <= 0 || ep.FocusToken == "" {
		return ep, fmt.Errorf("incomplete focus endpoint")
	}
	return ep, nil
}

// RemoveFocusEndpoint cleans up focus.json on shutdown if owned by pid.
func RemoveFocusEndpoint(pid int) {
	ep, err := ReadFocusEndpoint()
	if err == nil && ep.PID != pid {
		return
	}
	_ = os.Remove(focusEndpointPath())
}
