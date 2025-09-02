# Discovr — Network Scan (Python and Go)

Discovr is an open-source, cross-platform tool designed to quickly find and profile assets across on-prem networks and cloud (AWS, Azure) — with a primary focus on hosts that can run security agents (servers, endpoints, cloud VMs). It’s built for rapid use in unknown client environments where time and visibility are limited.

## Prerequisites

- Python: 3.8 or newer
- Go: 1.20 or newer
- OS: macOS, Linux, or Windows

## Install Python

- macOS (Homebrew):
  ```bash
  brew install python
  ```
- Ubuntu/Debian:
  ```bash
  sudo apt update && sudo apt install -y python3 python3-venv python3-pip
  ```
- Fedora:
  ```bash
  sudo dnf install -y python3 python3-pip
  ```
- Windows:
  - Download from https://www.python.org/downloads/ and check “Add python.exe to PATH”.

Optional (recommended) virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -V
```

## Install Go

- macOS (Homebrew):
  ```bash
  brew install go
  ```
- Ubuntu/Debian (from apt, version may lag):
  ```bash
  sudo apt update && sudo apt install -y golang
  ```
- Official installers and other OSes: https://go.dev/dl/

Verify:
```bash
go version
```

## Quick Start

Run either the Python or Go version with the same flags.

- Python:
  ```bash
  python3 discovr.py --target 192.168.1.0/24 --quick-scan --out out/report.csv
  ```
- Go (runs without building):
  ```bash
  go run discovr.go --target 192.168.1.0/24 --quick-scan --out outgo/report.csv
  ```


remove `--quick-scan` to run full scan in the system

Output files are written to the `out/` (Python) and `outgo/` (Go) folders respectively. Create the folders first if your environment doesn’t auto-create them:
```bash
mkdir -p out outgo
```

## Build

- Local build (current OS/arch):
  ```bash
  mkdir -p dist
  go build -o dist/discovr .
  # Run
  ./dist/discovr --target 192.168.1.0/24 --quick-scan --out outgo/report.csv
  ```

- Using Makefile targets:
  - Build current platform:
    ```bash
    make build
    # binary: dist/discovr
    ```
  - Cross-compile for Linux/macOS/Windows (amd64/arm64):
    ```bash
    make cross
    # binaries: dist/discovr-$GOOS-$GOARCH[.exe]
    ```

- Windows (PowerShell/CMD):
  ```powershell
  go build -o dist/discovr.exe .
  dist\discovr.exe --target 192.168.1.0/24 --quick-scan --out outgo/report.csv
  ```

## Notes

- Replace `192.168.1.0/24` with the CIDR/subnet you want to scan.
- Running scans may require elevated privileges or appropriate firewall settings depending on your network.
- If you want reproducible Go builds, you can add a `go.mod` file later with `go mod init <module>`.

## Troubleshooting

- Command not found: Ensure `python3`/`go` are on your `PATH` (`which python3`, `which go`).
- Permission issues: Try a smaller scope or run with appropriate privileges.
- Empty output: Verify the target CIDR is reachable from your machine.
