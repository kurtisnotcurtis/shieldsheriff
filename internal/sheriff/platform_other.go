//go:build !windows

package sheriff

import "errors"

func FindRunningWatchedProcess([]string) string { return "" }
func IsTrayStartupEnabled() bool                { return false }
func SetTrayStartup(bool) error                 { return errors.New("logon startup task requires Windows") }
