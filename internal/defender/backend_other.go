//go:build !windows

package defender

import (
	"context"
	"errors"
)

var errWindowsOnly = errors.New("Windows Defender operations require Windows")

type unsupportedBackend struct{}

func DefaultBackend() Backend { return unsupportedBackend{} }

func IsProcessElevated() bool { return false }

func (unsupportedBackend) IsElevated() bool                                 { return false }
func (unsupportedBackend) ReadDword(RegRoot, string, string) (uint32, bool) { return 0, false }
func (unsupportedBackend) ReadString(RegRoot, string, string) (string, RegValueKind, bool) {
	return "", 0, false
}
func (unsupportedBackend) WriteDword(RegRoot, string, string, uint32) error { return errWindowsOnly }
func (unsupportedBackend) WriteString(RegRoot, string, string, string, RegValueKind) error {
	return errWindowsOnly
}
func (unsupportedBackend) DeleteValue(RegRoot, string, string) error { return errWindowsOnly }
func (unsupportedBackend) RunCommand(context.Context, string, ...string) (string, error) {
	return "", errWindowsOnly
}
func (unsupportedBackend) FileExists(string) bool { return false }
