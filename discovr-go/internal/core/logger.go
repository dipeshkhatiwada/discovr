package core

import (
    "errors"
    "fmt"
    "io"
    "log"
    "os"
    "path/filepath"
    "time"
)

type LogInfo struct {
    FilePath string
    Timestamp string
}

// SetupLogger initializes logging. If logDir is empty, it tries:
// 1) ~/Documents/discovr_reports/logs
// 2) ./discovr_reports/logs (cwd)
// 3) $TMPDIR/discovr_logs
func SetupLogger(feature string, logDir string) (*LogInfo, error) {
    ts := time.Now().Format("20060102_150405")

    tryOpen := func(base string) (*LogInfo, error) {
        if err := os.MkdirAll(base, 0o755); err != nil { return nil, err }
        logPath := filepath.Join(base, fmt.Sprintf("discovr_%s_log_%s.log", feature, ts))
        f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
        if err != nil { return nil, err }
        mw := io.MultiWriter(os.Stdout, f)
        log.SetOutput(mw)
        log.SetFlags(0)
        fmt.Printf("[+] Logs saved at %s\n", logPath)
        return &LogInfo{FilePath: logPath, Timestamp: ts}, nil
    }

    // If user provided a directory, try it first.
    if logDir != "" {
        if li, err := tryOpen(logDir); err == nil {
            return li, nil
        } else {
            fmt.Printf("[!] Failed to open provided log dir %q: %v\n", logDir, err)
        }
    }

    // 1) ~/Documents/discovr_reports/logs
    if home, err := os.UserHomeDir(); err == nil {
        base := filepath.Join(home, "Documents", "discovr_reports", "logs")
        if li, err := tryOpen(base); err == nil {
            return li, nil
        } else if !isPerm(err) {
            // If it's not a permissions error, return it directly
            fmt.Printf("[!] Could not use %s: %v\n", base, err)
        } else {
            fmt.Printf("[!] Permission denied for %s; falling back.\n", base)
        }
    }

    // 2) ./discovr_reports/logs
    if cwd, err := os.Getwd(); err == nil {
        base := filepath.Join(cwd, "discovr_reports", "logs")
        if li, err := tryOpen(base); err == nil {
            return li, nil
        } else {
            fmt.Printf("[!] Could not use %s: %v\n", base, err)
        }
    }

    // 3) $TMPDIR/discovr_logs
    base := filepath.Join(os.TempDir(), "discovr_logs")
    if li, err := tryOpen(base); err == nil {
        fmt.Printf("[!] Using temp directory for logs.\n")
        return li, nil
    } else {
        return nil, fmt.Errorf("open log file: %w", err)
    }
}

func isPerm(err error) bool {
    if err == nil { return false }
    var pathErr *os.PathError
    if errors.As(err, &pathErr) {
        return errors.Is(pathErr, os.ErrPermission)
    }
    return false
}
