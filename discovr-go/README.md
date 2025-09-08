Discovr (Go) — Asset Discovery Tool

This is a Go reimplementation of the Python Discovr tool. It provides the same major features: Network discovery, Cloud discovery (AWS, Azure, GCP), Active Directory discovery, Passive sniffing, tagging and risk assessment, with CSV/JSON export and logs.

Prerequisites
- Go 1.22+
- Network: nmap binary (recommended) for OS detection, otherwise falls back to basic TCP scan
- Passive: libpcap/WinPcap/Npcap installed, run with sudo/Administrator
- AWS: Valid AWS credentials/profile configured (aws configure)
- Azure: Azure CLI logged in or environment credentials available; provide `--subscription`
- GCP: Application default creds and project access (gcloud auth application-default login)

Project Layout
- cmd/discovr: CLI entrypoint
- internal/core: logger, exporter, reporter
- internal/network: network scanning via nmap or fallback
- internal/cloud: AWS and GCP discovery
- internal/ad: Active Directory discovery (LDAP)
- internal/passive: Passive sniffing (gopacket)
- internal/tagger, internal/risk: enrichment logic

Build
```bash
cd discovr-go
go build -o discovr ./cmd/discovr
```

Run Examples
- Network scan (manual):
  - `./discovr --scan-network 192.168.1.0/24`
  - With ports: `./discovr --scan-network 192.168.1.0/24 --ports 22,80,443`
  - With parallel: `./discovr --scan-network 192.168.1.0/24 --parallel 10`
- Auto-detect local subnet:
  - `./discovr --autoipaddr`
  - If you hit a permissions prompt or see "permission denied" for `~/Documents`, set a log dir: `./discovr --autoipaddr --log-dir ./discovr_reports/logs`
- Cloud (AWS):
  - `./discovr --cloud aws --profile default --region us-east-1`
- Cloud (Azure):
  - `./discovr --cloud azure --subscription <SUBSCRIPTION_ID>`
- Cloud (GCP):
  - Default build excludes GCP to simplify first-run setup. Enable with build tag:
    - Build: `go build -tags gcp -o discovr ./cmd/discovr`
    - Run: `go run -tags gcp ./cmd/discovr --cloud gcp --project my-project --zone us-central1-a`
- Active Directory:
  - `./discovr --ad --domain mydomain.local --username user@mydomain.local --password Secret123`
- Passive discovery (requires pcap):
  - `sudo ./discovr --passive --iface eth0 --timeout 180`

- CI helpers:
  - Smoke test (simulated, no external calls): `./discovr --smoke-test --save yes --format all`
  - Dry run (validate and show plan only):
    - Network: `./discovr --scan-network 192.168.1.0/24 --dry-run`
    - AWS: `./discovr --cloud aws --profile default --region us-east-1 --dry-run`
    - Azure: `./discovr --cloud azure --subscription <SUBSCRIPTION_ID> --dry-run`
    - GCP: `./discovr --cloud gcp --project my-project --zone us-central1-a --dry-run`
    - AD: `./discovr --ad --domain mydomain.local --username user@mydomain.local --password ***** --dry-run`

Exporting
- Add `--save yes --format csv|json|html|all` to auto-save without prompt.
- Files are saved to `~/Documents/discovr_reports/{csv,json,html}` and logs to `~/Documents/discovr_reports/logs`.
- HTML report includes a built-in search box to filter the table in-browser.

Notes
- nmap detection: If `nmap` is present, Discovr uses `nmap -O -T4 -oX -` to retrieve OS and open ports in one pass. Otherwise, it performs a basic TCP connect scan over common ports and guesses the OS from ports.
- Azure discovery is implemented. Use `--cloud azure --subscription <SUBSCRIPTION_ID>`.
- GCP discovery is optional (build tag `gcp`). If you see module errors on first run, use:
  - `go env -w GOPROXY=https://proxy.golang.org,direct && go mod tidy`
  - then build/run with `-tags gcp` as shown above.

First Run (Dependencies)
```bash
cd discovr-go
# fetch deps for default build (no GCP)
go mod tidy

# optional: enable GCP (adds cloud.google.com/go/compute)
go get cloud.google.com/go/compute/apiv1@latest
go mod tidy
```
- Logging directory:
  - Default: `~/Documents/discovr_reports/logs`.
  - If not writable (e.g., macOS Documents permissions), Discovr falls back to `./discovr_reports/logs`, then the OS temp directory.
  - Override anytime with `--log-dir <PATH>`.
