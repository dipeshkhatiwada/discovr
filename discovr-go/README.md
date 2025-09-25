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
- Interactive mode (no flags):
  - `./discovr` and follow the prompts to select Active scan, Passive discovery, AWS, Azure, GCP, or Active Directory. The CLI will ask for any required inputs (CIDR/ports, interface, AWS profile/region, Azure subscription, GCP project/zone, or AD domain/user/password) and then export options. The menu loops so you can run multiple discovery modes before choosing Exit.

Interactive UI (example)
```text
$ ./discovr

Discovr can elevate for better scanning (pcap/nmap OS). Elevate now? (y/N): y

Discovr Interactive Mode
Select an option:
  1) Active network scan
  2) Passive discovery
  3) Active Directory
  4) Cloud: AWS
  5) Cloud: Azure
  6) Cloud: GCP
  7) Exit
Enter choice [1-7]: 1
Auto-detect local subnet? (y/N): y
[+] Auto-detected local subnet: 192.168.1.0/24
Ports to scan (e.g., 22,80,443) [leave blank for default]: 22,80,443
Parallel workers [1]: 10

[+] ... scan output ...

Do you want to save results? (yes/no): yes
Choose format (csv/json/html/all): all
[+] CSV saved: /Users/<you>/Documents/discovr_reports/csv/discovr_network_YYYYMMDD_HHMMSS.csv
[+] JSON saved: /Users/<you>/Documents/discovr_reports/json/discovr_network_YYYYMMDD_HHMMSS.json
[+] HTML saved: /Users/<you>/Documents/discovr_reports/html/discovr_network_YYYYMMDD_HHMMSS.html
```

Notes for interactive mode
- `Passive discovery` may require elevated privileges. On Linux/macOS use `sudo ./discovr` when selecting passive mode.
- If prompted for an interface, type the number shown or the exact interface name (e.g., `eth0`, `en0`).
- Logs are written under `~/Documents/discovr_reports/logs` by default; override with `--log-dir <PATH>` if needed.
- Elevation prompt: When needed (e.g., Passive), Discovr can ask to elevate and re-launch with `sudo` automatically.
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
  - Default preference: `./discovr_reports/logs` (local workspace), then `~/Documents/discovr_reports/logs`, then OS temp.
  - Override anytime with `--log-dir <PATH>` or set env `DISCOVR_LOG_DIR=<PATH>` to avoid permission prompts on macOS Documents.

Environment Variables (.env)
- Copy `discovr-go/.env.example` to `discovr-go/.env` and fill in values.
- Load it before running Discovr so SDKs pick up credentials and defaults:
  - bash/zsh: `set -a; source .env; set +a`
- Common variables supported by underlying SDKs:
  - AWS: `AWS_PROFILE`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
  - Azure: `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
  - GCP: `GOOGLE_APPLICATION_CREDENTIALS` (when built with `-tags gcp`)
- For AD, use env vars as a convenience and pass flags:
  - Example: `./discovr --ad --domain "$AD_DOMAIN" --username "$AD_USERNAME" --password "$AD_PASSWORD"`
