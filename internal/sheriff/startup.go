//go:build windows

package sheriff

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	trayStartupTaskName = "ShieldSheriff Tray"
	schtasksTimeout     = 10 * time.Second
)

func runSchtasks(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), schtasksTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "schtasks.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// IsTrayStartupEnabled reports whether the Windows logon task for ShieldSheriff tray exists.
func IsTrayStartupEnabled() bool {
	_, err := runSchtasks("/Query", "/TN", trayStartupTaskName)
	return err == nil
}

// SetTrayStartup creates or removes the elevated logon task that launches `shiesh.exe tray`.
func SetTrayStartup(enabled bool) error {
	if !enabled {
		if !IsTrayStartupEnabled() {
			return nil
		}
		out, err := runSchtasks("/Delete", "/TN", trayStartupTaskName, "/F")
		if err != nil {
			return fmt.Errorf("schtasks delete failed: %w (%s)", err, out)
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" tray`, exe)
	out, err := runSchtasks(
		"/Create",
		"/TN", trayStartupTaskName,
		"/TR", tr,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	)
	if err != nil {
		return fmt.Errorf("schtasks create failed: %w (%s)", err, out)
	}
	return nil
}
