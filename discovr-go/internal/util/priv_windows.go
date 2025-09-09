//go:build windows

package util

// On Windows, requesting elevation requires ShellExecute with runas and a GUI prompt.
// We do not implement automatic elevation here to avoid extra deps.
// These stubs keep the cross-platform API consistent.

func IsAdmin() bool { return true }

func RelaunchWithSudo() error { return nil }

