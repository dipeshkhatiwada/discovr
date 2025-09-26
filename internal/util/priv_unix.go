//go:build !windows

package util

import (
    "fmt"
    "os"
    "os/exec"
)

// IsAdmin reports whether the current process has root privileges.
func IsAdmin() bool {
    return os.Geteuid() == 0
}

// RelaunchWithSudo re-executes the current binary with sudo, preserving args and env.
// It attaches stdio so the user can enter a password in the current terminal.
func RelaunchWithSudo() error {
    exe, err := os.Executable()
    if err != nil { return fmt.Errorf("get executable: %w", err) }
    args := append([]string{"-E", exe}, os.Args[1:]...)
    cmd := exec.Command("sudo", args...)
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    return cmd.Run()
}

