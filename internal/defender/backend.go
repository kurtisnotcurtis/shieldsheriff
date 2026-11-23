package defender

import "context"

// RegRoot identifies a Windows Registry root hive.
type RegRoot uint32

const (
	HKLM RegRoot = iota + 1
	HKCU
)

// RegValueKind identifies the Windows Registry value type.
type RegValueKind uint32

const (
	RegDword RegValueKind = iota + 1
	RegSZ
	RegExpandSZ
)

// Backend abstracts OS interactions (Registry, elevation, command execution, filesystem)
// so Defender inspection, enforcement, and revert logic can be unit-tested without
// touching the host machine.
type Backend interface {
	IsElevated() bool
	ReadDword(root RegRoot, subkey, name string) (uint32, bool)
	ReadString(root RegRoot, subkey, name string) (string, RegValueKind, bool)
	WriteDword(root RegRoot, subkey, name string, val uint32) error
	WriteString(root RegRoot, subkey, name string, val string, kind RegValueKind) error
	DeleteValue(root RegRoot, subkey, name string) error
	RunCommand(ctx context.Context, name string, args ...string) (string, error)
	FileExists(path string) bool
}
