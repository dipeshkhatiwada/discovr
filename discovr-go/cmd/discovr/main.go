package main

import (
    "bufio"
    "context"
    "flag"
    "fmt"
    "log"
    "os"
    "strconv"
    "strings"
    "time"

    "discovr/internal/ad"
    "discovr/internal/cloud"
    "discovr/internal/core"
    "discovr/internal/network"
    "discovr/internal/passive"
    "discovr/internal/risk"
    "discovr/internal/tagger"
    "discovr/internal/types"
    "discovr/internal/util"
)

func main() {
    // Network
    scanNetwork := flag.String("scan-network", "", "Network range, e.g. 192.168.1.0/24")
    ports := flag.String("ports", "", "Ports to scan, e.g. 22,80,443")
    parallel := flag.Int("parallel", 1, "Number of parallel workers for network scan (default: 1)")
    autoip := flag.Bool("autoipaddr", false, "Auto-detect local IP and subnet for scanning")

    // Cloud
    cloudProv := flag.String("cloud", "", "Cloud provider to scan (aws|azure|gcp)")
    profile := flag.String("profile", "default", "AWS profile (default: default)")
    region := flag.String("region", "us-east-1", "AWS region (default: us-east-1)")
    subscription := flag.String("subscription", "", "Azure subscription ID")
    project := flag.String("project", "", "GCP project ID for discovery")
    zone := flag.String("zone", "", "GCP zone for discovery (e.g., us-central1-a)")

    // Active Directory
    adFlag := flag.Bool("ad", false, "Run Active Directory discovery")
    domain := flag.String("domain", "", "Active Directory domain, e.g. mydomain.local")
    username := flag.String("username", "", "AD username, e.g. user@mydomain.local")
    password := flag.String("password", "", "AD password")

    // Passive
    passiveFlag := flag.Bool("passive", false, "Run passive discovery")
    iface := flag.String("iface", "", "Network interface (optional)")
    timeoutSec := flag.Int("timeout", 180, "Passive discovery timeout in seconds (default: 180)")

    // Export
    save := flag.String("save", "", "Auto-save results without prompt (yes/no)")
    format := flag.String("format", "", "Export format if saving is enabled (csv/json/html/all)")

    // CI helpers
    smokeTest := flag.Bool("smoke-test", false, "Run a quick, simulated discovery to verify binary works")
    dryRun := flag.Bool("dry-run", false, "Validate flags and show planned action without external calls")

    // Logging
    logDir := flag.String("log-dir", "", "Directory to write logs (overrides default)")

    flag.Parse()

    var (
        feature string
        timestamp string
        assets []types.Asset
        total int
        start time.Time
    )

    // Smoke test shortcut: run a simulated pipeline with no external calls
    if *smokeTest {
        runSmokeTest(*save, *format)
        return
    }

    // Dry-run validation: print what would be done and exit
    if *dryRun {
        handleDryRun(*autoip, *scanNetwork, *ports, *parallel, *cloudProv, *profile, *region, *subscription, *project, *zone, *adFlag, *domain, *username, *password, *passiveFlag, *iface, *timeoutSec)
        return
    }

    // Note: elevation is requested contextually (e.g., passive capture) rather than at startup.

    // Decide feature
    if *autoip {
        feature = "network"
        li, err := core.SetupLogger(feature, *logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp
        subnet, err := util.DetectLocalSubnet()
        if err != nil { log.Fatalf("[!] Failed to auto-detect local subnet: %v", err) }
        fmt.Printf("[+] Auto-detected local subnet: %s\n", subnet)
        start = time.Now()
        as, tot, err := network.RunNetworkDiscovery(subnet, *ports, *parallel)
        if err != nil { log.Fatalf("[!] Network scan failed: %v", err) }
        assets, total = as, tot
        elapsed(start)
        assets = enrich(assets)
        core.PrintResults(assets, total, "active assets")
    } else if *scanNetwork != "" {
        feature = "network"
        li, err := core.SetupLogger(feature, *logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp
        start = time.Now()
        as, tot, err := network.RunNetworkDiscovery(*scanNetwork, *ports, *parallel)
        if err != nil { log.Fatalf("[!] Network scan failed: %v", err) }
        assets, total = as, tot
        elapsed(start)
        assets = enrich(assets)
        core.PrintResults(assets, total, "active assets")
    } else if *cloudProv != "" {
        feature = "cloud"
        li, err := core.SetupLogger(feature, *logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp
        ctx := context.Background()
        start = time.Now()
        switch strings.ToLower(*cloudProv) {
        case "aws":
            fmt.Println("[+] Discovering AWS assets...")
            as, err := cloud.DiscoverAWS(ctx, cloud.AWSConfig{Profile: *profile, Region: *region})
            if err != nil { log.Fatalf("[!] AWS discovery failed: %v", err) }
            assets = enrich(as)
            core.PrintResults(assets, len(assets), "cloud assets")
        case "gcp":
            if *project == "" || *zone == "" { log.Fatalf("[!] GCP discovery requires --project and --zone") }
            fmt.Printf("[+] Discovering GCP assets in project %s, zone %s\n", *project, *zone)
            as, err := cloud.DiscoverGCP(ctx, cloud.GCPConfig{Project: *project, Zone: *zone})
            if err != nil { log.Fatalf("[!] GCP discovery failed: %v", err) }
            assets = enrich(as)
            core.PrintResults(assets, len(assets), "cloud assets")
        case "azure":
            if *subscription == "" { log.Fatalf("[!] Azure discovery requires --subscription") }
            fmt.Println("[+] Discovering AZURE assets...")
            as, err := cloud.DiscoverAzure(ctx, cloud.AzureConfig{Subscription: *subscription})
            if err != nil { log.Fatalf("[!] Azure discovery failed: %v", err) }
            assets = enrich(as)
            core.PrintResults(assets, len(assets), "cloud assets")
        default:
            log.Fatalf("[!] Unsupported cloud provider. Choose aws, azure, or gcp")
        }
        elapsed(start)
    } else if *adFlag {
        feature = "ad"
        li, err := core.SetupLogger(feature, *logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp
        if *domain == "" || *username == "" || *password == "" { log.Fatalf("[!] AD discovery requires --domain, --username, and --password") }
        fmt.Printf("[+] Discovering Active Directory assets in %s\n", *domain)
        start = time.Now()
        as, err := ad.Discover(ad.Config{Domain: *domain, Username: *username, Password: *password})
        if err != nil { log.Fatalf("[!] Active Directory discovery failed: %v", err) }
        assets = enrich(as)
        core.PrintResults(assets, len(assets), "AD assets")
        elapsed(start)
    } else if *passiveFlag {
        feature = "passive"
        li, err := core.SetupLogger(feature, *logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp
        // Request elevation if not already admin/root
        if !util.IsAdmin() {
            reader := bufio.NewReader(os.Stdin)
            fmt.Print("Passive discovery may require admin privileges. Elevate with sudo now? (y/N): ")
            resp, _ := reader.ReadString('\n')
            resp = strings.TrimSpace(strings.ToLower(resp))
            if resp == "y" || resp == "yes" {
                if err := util.RelaunchWithSudo(); err != nil {
                    log.Fatalf("[!] Elevation failed: %v", err)
                }
                return
            }
        }
        if *iface == "" {
            // List and ask user to choose
            devs, err := passive.ListInterfaces()
            if err != nil { log.Fatalf("[!] List interfaces failed: %v", err) }
            fmt.Println("[+] Available interfaces:")
            for i, d := range devs { fmt.Printf("    [%d] %s\n", i+1, d.Name) }
            fmt.Print("\nSelect interface by number: ")
            var idx int
            if _, err := fmt.Scanf("%d", &idx); err != nil || idx < 1 || idx > len(devs) { log.Fatalf("[!] Invalid choice") }
            *iface = devs[idx-1].Name
        }
        fmt.Printf("[+] Running passive discovery on interface: %s\n", *iface)
        fmt.Printf("[+] Listening for ARP, DNS, DHCP, and mDNS traffic (auto-stop after %d seconds or Ctrl+C)...)\n\n", *timeoutSec)
        as, count, err := passive.Discover(passive.Config{Iface: *iface, Timeout: time.Duration(*timeoutSec) * time.Second})
        if err != nil { log.Fatalf("[!] Passive discovery failed: %v", err) }
        assets = enrich(as)
        if len(assets) > 0 {
            core.PrintResults(assets, count, "assets")
        } else {
            fmt.Println("\n[!] No assets discovered during passive monitoring.")
        }
    } else {
        // Launch interactive menu when no flags are provided
        runInteractive(*logDir)
        return
    }

    if feature != "" && timestamp != "" {
        fmt.Printf("[+] Logs saved at Documents/discovr_reports/logs/discovr_%s_log_%s.log\n", feature, timestamp)
    }
    handleExport(assets, feature, timestamp, *save, *format)
}

func enrich(in []types.Asset) []types.Asset {
    out := make([]types.Asset, 0, len(in))
    for _, a := range in {
        a.Tag = tagger.AssignTag(a.Hostname, a.OS, a.Ports)
        a.Risk = risk.Assess(a.OS, a.Ports, a.Tag)
        out = append(out, a)
    }
    return out
}

func runSmokeTest(save, format string) {
    // No logging, no external calls; simulate a few assets
    fmt.Println("[+] Running smoke test (simulated)")
    start := time.Now()
    sample := []types.Asset{
        {IP: "192.168.1.1", Hostname: "router", OS: "Linux/Unix", Ports: "80,443"},
        {IP: "192.168.1.10", Hostname: "laptop01", OS: "Windows 10 Pro", Ports: "135,445"},
        {IP: "192.168.1.20", Hostname: "server01", OS: "Linux 5.x kernel", Ports: "22,80,443"},
    }
    sample = enrich(sample)
    core.PrintResults(sample, len(sample), "assets")
    elapsed(start)
    // Simulate a feature/timestamp for export filenames
    ts := time.Now().Format("20060102_150405")
    handleExport(sample, "smoke", ts, save, format)
}

func handleDryRun(autoip bool, scanNetwork, ports string, parallel int, cloudProv, profile, region, subscription, project, zone string, adFlag bool, domain, username, password string, passiveFlag bool, iface string, timeoutSec int) {
    switch {
    case autoip:
        fmt.Printf("[DRY-RUN] Would scan auto-detected local subnet with parallel=%d ports=%q\n", parallel, ports)
    case scanNetwork != "":
        fmt.Printf("[DRY-RUN] Would scan network %s with parallel=%d ports=%q\n", scanNetwork, parallel, ports)
    case cloudProv != "":
        switch strings.ToLower(cloudProv) {
        case "aws":
            fmt.Printf("[DRY-RUN] Would discover AWS assets with profile=%q region=%q\n", profile, region)
        case "azure":
            if subscription == "" { log.Fatalf("[DRY-RUN] Missing --subscription for Azure") }
            fmt.Printf("[DRY-RUN] Would discover Azure assets with subscription=%q\n", subscription)
        case "gcp":
            if project == "" || zone == "" { log.Fatalf("[DRY-RUN] Missing --project and/or --zone for GCP") }
            fmt.Printf("[DRY-RUN] Would discover GCP assets with project=%q zone=%q\n", project, zone)
        default:
            log.Fatalf("[DRY-RUN] Unsupported cloud provider: %s", cloudProv)
        }
    case adFlag:
        if domain == "" || username == "" || password == "" { log.Fatalf("[DRY-RUN] Missing --domain, --username, or --password for AD") }
        fmt.Printf("[DRY-RUN] Would discover AD assets in domain=%q as user=%q\n", domain, username)
    case passiveFlag:
        if iface == "" {
            fmt.Printf("[DRY-RUN] Would run passive discovery and prompt for interface; timeout=%ds\n", timeoutSec)
        } else {
            fmt.Printf("[DRY-RUN] Would run passive discovery on iface=%q; timeout=%ds\n", iface, timeoutSec)
        }
    default:
        fmt.Println("[DRY-RUN] No action selected; provide one of --scan-network/--autoipaddr/--cloud/--ad/--passive")
    }
}

func handleExport(assets []types.Asset, feature, ts, save, format string) {
    if len(assets) == 0 { return }
    if save != "" || format != "" {
        if strings.ToLower(save) == "yes" || strings.ToLower(save) == "y" {
            fmtChoice := strings.ToLower(format)
            switch fmtChoice {
            case "csv": _ = core.SaveResults(assets, []string{"csv"}, feature, ts)
            case "json": _ = core.SaveResults(assets, []string{"json"}, feature, ts)
            case "html": _ = core.SaveResults(assets, []string{"html"}, feature, ts)
            case "all": _ = core.SaveResults(assets, []string{"csv","json","html"}, feature, ts)
            default:
                fmt.Println("[!] Invalid format option, not saving.")
            }
        } else {
            fmt.Println("[+] Results not saved.")
        }
        return
    }
    // interactive
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("\nDo you want to save results? (yes/no): ")
    resp, _ := reader.ReadString('\n')
    resp = strings.TrimSpace(strings.ToLower(resp))
    if resp == "yes" || resp == "y" {
        fmt.Print("Choose format (csv/html/all): ")
        fmtChoice, _ := reader.ReadString('\n')
        fmtChoice = strings.TrimSpace(strings.ToLower(fmtChoice))
        switch fmtChoice {
        case "csv": _ = core.SaveResults(assets, []string{"csv"}, feature, ts)
        case "json": _ = core.SaveResults(assets, []string{"json"}, feature, ts)
        case "html": _ = core.SaveResults(assets, []string{"html"}, feature, ts)
        case "all": _ = core.SaveResults(assets, []string{"csv","json","html"}, feature, ts)
        default:
            fmt.Println("[!] Invalid choice, not saving.")
        }
    } else {
        fmt.Println("[+] Results not saved.")
    }
}

func elapsed(start time.Time) {
    fmt.Printf("[+] Total execution time: %.2f seconds\n", time.Since(start).Seconds())
}

// runInteractive provides a simple terminal menu for selecting discovery modes
func runInteractive(logDir string) {
    reader := bufio.NewReader(os.Stdin)
    fmt.Println("\nDiscovr asset scan Mode")
    fmt.Println("Select one option from list:")
    fmt.Println("  1) Active network scan")
    fmt.Println("  2) Passive discovery")
    fmt.Println("  3) Cloud: AWS")
    fmt.Println("  4) Cloud: Azure")
    fmt.Print("Enter choice [1-4]: ")
    choiceStr, _ := reader.ReadString('\n')
    choiceStr = strings.TrimSpace(choiceStr)
    choice, _ := strconv.Atoi(choiceStr)

    var (
        feature   string
        timestamp string
        assets    []types.Asset
        total     int
        start     time.Time
    )

    switch choice {
    case 1:
        // Active network scan
        feature = "network"
        li, err := core.SetupLogger(feature, logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp

        // Subnet selection
        fmt.Print("Auto-detect local subnet? (y/N): ")
        autodStr, _ := reader.ReadString('\n')
        autodStr = strings.TrimSpace(strings.ToLower(autodStr))
        var subnet string
        if autodStr == "y" || autodStr == "yes" {
            s, err := util.DetectLocalSubnet()
            if err != nil { log.Fatalf("[!] Failed to auto-detect local subnet: %v", err) }
            subnet = s
            fmt.Printf("[+] Auto-detected local subnet: %s\n", subnet)
        } else {
            fmt.Print("Enter CIDR (e.g., 192.168.1.0/24): ")
            s, _ := reader.ReadString('\n')
            subnet = strings.TrimSpace(s)
            if subnet == "" { log.Fatalf("[!] Network range is required") }
        }

        // Ports
        fmt.Print("Ports to scan (e.g., 22,80,443) [leave blank for default]: ")
        pStr, _ := reader.ReadString('\n')
        pStr = strings.TrimSpace(pStr)

        // Parallel workers
        fmt.Print("Parallel workers [1]: ")
        parStr, _ := reader.ReadString('\n')
        parStr = strings.TrimSpace(parStr)
        parallel := 1
        if parStr != "" { if v, err := strconv.Atoi(parStr); err == nil && v > 0 { parallel = v } }

        // Offer elevation to improve OS detection when available
        if !util.IsAdmin() {
            fmt.Print("Use elevated privileges for better OS detection? (y/N): ")
            resp, _ := reader.ReadString('\n')
            resp = strings.TrimSpace(strings.ToLower(resp))
            if resp == "y" || resp == "yes" {
                if err := util.RelaunchWithSudo(); err != nil { log.Fatalf("[!] Elevation failed: %v", err) }
                return
            }
        }
        start = time.Now()
        as, tot, err := network.RunNetworkDiscovery(subnet, pStr, parallel)
        if err != nil { log.Fatalf("[!] Network scan failed: %v", err) }
        assets, total = enrich(as), tot
        core.PrintResults(assets, total, "active assets")
        elapsed(start)

    case 2:
        // Passive discovery
        feature = "passive"
        li, err := core.SetupLogger(feature, logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp

        // Interface selection
        chosenIface := ""
        ifs, err := passive.ListInterfaces()
        if err == nil && len(ifs) > 0 {
            fmt.Println("Available interfaces:")
            for i, inf := range ifs {
                desc := inf.Description
                fmt.Printf("  %d) %s  %s\n", i+1, inf.Name, desc)
            }
            fmt.Print("Select interface by number (or enter name): ")
            sel, _ := reader.ReadString('\n')
            sel = strings.TrimSpace(sel)
            if n, err := strconv.Atoi(sel); err == nil && n >= 1 && n <= len(ifs) {
                chosenIface = ifs[n-1].Name
            } else if sel != "" {
                chosenIface = sel
            }
        }
        for chosenIface == "" { // ensure we have an interface
            fmt.Print("Enter interface name (e.g., eth0, en0): ")
            s, _ := reader.ReadString('\n')
            chosenIface = strings.TrimSpace(s)
        }

        // Timeout
        fmt.Print("Timeout seconds [180]: ")
        tStr, _ := reader.ReadString('\n')
        tStr = strings.TrimSpace(tStr)
        timeoutSec := 180
        if tStr != "" { if v, err := strconv.Atoi(tStr); err == nil && v > 0 { timeoutSec = v } }
        // Request elevation if not already admin/root
        if !util.IsAdmin() {
            fmt.Print("Passive discovery may require admin privileges. Elevate with sudo now? (y/N): ")
            resp, _ := reader.ReadString('\n')
            resp = strings.TrimSpace(strings.ToLower(resp))
            if resp == "y" || resp == "yes" {
                if err := util.RelaunchWithSudo(); err != nil { log.Fatalf("[!] Elevation failed: %v", err) }
                return
            }
        }

        start = time.Now()
        as, tot, err := passive.Discover(passive.Config{Iface: chosenIface, Timeout: time.Duration(timeoutSec) * time.Second})
        if err != nil { log.Fatalf("[!] Passive discovery failed: %v", err) }
        if tot == 0 {
            fmt.Println("\n[!] No assets discovered during passive monitoring.")
        }
        assets, total = enrich(as), tot
        core.PrintResults(assets, total, "passive assets")
        elapsed(start)

    case 3:
        // Cloud: AWS
        feature = "cloud"
        li, err := core.SetupLogger(feature, logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp
        fmt.Print("AWS profile [default]: ")
        prof, _ := reader.ReadString('\n')
        prof = strings.TrimSpace(prof)
        if prof == "" { prof = "default" }
        fmt.Print("AWS region [us-east-1]: ")
        reg, _ := reader.ReadString('\n')
        reg = strings.TrimSpace(reg)
        if reg == "" { reg = "us-east-1" }
        ctx := context.Background()
        start = time.Now()
        as, err := cloud.DiscoverAWS(ctx, cloud.AWSConfig{Profile: prof, Region: reg})
        if err != nil { log.Fatalf("[!] AWS discovery failed: %v", err) }
        assets = enrich(as)
        total = len(assets)
        core.PrintResults(assets, total, "cloud assets")
        elapsed(start)

    case 4:
        // Cloud: Azure
        feature = "cloud"
        li, err := core.SetupLogger(feature, logDir)
        if err != nil { log.Fatalf("[!] Logger setup failed: %v", err) }
        timestamp = li.Timestamp
        fmt.Print("Azure subscription ID: ")
        sub, _ := reader.ReadString('\n')
        sub = strings.TrimSpace(sub)
        if sub == "" { log.Fatalf("[!] Subscription ID is required for Azure discovery") }
        ctx := context.Background()
        start = time.Now()
        as, err := cloud.DiscoverAzure(ctx, cloud.AzureConfig{Subscription: sub})
        if err != nil { log.Fatalf("[!] Azure discovery failed: %v", err) }
        assets = enrich(as)
        total = len(assets)
        core.PrintResults(assets, total, "cloud assets")
        elapsed(start)

    default:
        fmt.Println("[!] Invalid choice. Exiting.")
        return
    }

    if feature != "" && timestamp != "" {
        fmt.Printf(" Logs saved at Documents/discovr_reports/logs/discovr_%s_log_%s.log\n", feature, timestamp)
    }

    // Export prompt
    handleExport(assets, feature, timestamp, "", "")
}
