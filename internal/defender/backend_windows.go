//go:build windows

package defender

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type windowsBackend struct{}

var defaultWinBackend Backend = windowsBackend{}

// DefaultBackend returns the production Windows Registry/process Backend.
func DefaultBackend() Backend {
	return defaultWinBackend
}

func toRegistryKey(root RegRoot) registry.Key {
	if root == HKCU {
		return registry.CURRENT_USER
	}
	return registry.LOCAL_MACHINE
}

func (windowsBackend) IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func (windowsBackend) ReadDword(root RegRoot, subkey, name string) (uint32, bool) {
	k, err := registry.OpenKey(toRegistryKey(root), subkey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return 0, false
	}
	defer k.Close()

	val, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return uint32(val), true
}

func (windowsBackend) ReadString(root RegRoot, subkey, name string) (string, RegValueKind, bool) {
	k, err := registry.OpenKey(toRegistryKey(root), subkey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", 0, false
	}
	defer k.Close()

	val, valType, err := k.GetStringValue(name)
	if err != nil {
		return "", 0, false
	}
	switch valType {
	case registry.EXPAND_SZ:
		return val, RegExpandSZ, true
	case registry.SZ:
		return val, RegSZ, true
	default:
		return "", 0, false
	}
}

func (windowsBackend) WriteDword(root RegRoot, subkey, name string, val uint32) error {
	k, _, err := registry.CreateKey(toRegistryKey(root), subkey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("CreateKey(%s): %w", subkey, err)
	}
	defer k.Close()

	if err := k.SetDWordValue(name, val); err != nil {
		return fmt.Errorf("SetDWordValue(%s\\%s): %w", subkey, name, err)
	}
	return nil
}

func (windowsBackend) WriteString(root RegRoot, subkey, name string, val string, kind RegValueKind) error {
	k, _, err := registry.CreateKey(toRegistryKey(root), subkey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("CreateKey(%s): %w", subkey, err)
	}
	defer k.Close()

	if kind == RegExpandSZ {
		if err := k.SetExpandStringValue(name, val); err != nil {
			return fmt.Errorf("SetExpandStringValue(%s\\%s): %w", subkey, name, err)
		}
		return nil
	}
	if err := k.SetStringValue(name, val); err != nil {
		return fmt.Errorf("SetStringValue(%s\\%s): %w", subkey, name, err)
	}
	return nil
}

func (windowsBackend) DeleteValue(root RegRoot, subkey, name string) error {
	k, err := registry.OpenKey(toRegistryKey(root), subkey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("OpenKey(%s): %w", subkey, err)
	}
	defer k.Close()

	err = k.DeleteValue(name)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("DeleteValue(%s\\%s): %w", subkey, name, err)
	}
	return nil
}

func (windowsBackend) RunCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (windowsBackend) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ReadHKCUDword reads a REG_DWORD value from HKEY_CURRENT_USER.
func ReadHKCUDword(subkey, valueName string) (uint32, bool) {
	return DefaultBackend().ReadDword(HKCU, subkey, valueName)
}
