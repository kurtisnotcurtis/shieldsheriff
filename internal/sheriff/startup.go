package sheriff

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const trayStartupTaskName = "ShieldSheriff Tray"

func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

// IsTrayStartupEnabled reports whether the Windows logon task for ShieldSheriff tray exists.
func IsTrayStartupEnabled() bool {
	return hiddenCmd("schtasks.exe", "/Query", "/TN", trayStartupTaskName).Run() == nil
}

// SetTrayStartup creates or removes the elevated logon task that launches `shiesh.exe tray`.
func SetTrayStartup(enabled bool) error {
	if !enabled {
		out, err := hiddenCmd("schtasks.exe", "/Delete", "/TN", trayStartupTaskName, "/F").CombinedOutput()
		if err != nil && !strings.Contains(strings.ToLower(string(out)), "cannot find") {
			return fmt.Errorf("schtasks delete failed: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tr := fmt.Sprintf(`"%s" tray`, exe)
	out, err := hiddenCmd(
		"schtasks.exe", "/Create",
		"/TN", trayStartupTaskName,
		"/TR", tr,
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/F",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks create failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
