package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armsubscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"

	"discovr/internal/ad"
	"discovr/internal/cloud"
	"discovr/internal/cloudreport"
	"discovr/internal/core"
	"discovr/internal/network"
	"discovr/internal/passive"
	"discovr/internal/portlists"
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
	gcpCredPath := flag.String("gcp-credentials", "", "Path to GCP service account JSON")
	awsAccessKey := flag.String("aws-access-key", "", "AWS access key ID")
	awsSecretKey := flag.String("aws-secret-key", "", "AWS secret access key")
	awsSessionToken := flag.String("aws-session-token", "", "AWS session token")
	azureTenant := flag.String("azure-tenant", "", "Azure tenant ID")
	azureClientID := flag.String("azure-client-id", "", "Azure client ID")
	azureClientSecret := flag.String("azure-client-secret", "", "Azure client secret")

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
		feature           string
		timestamp         string
		assets            []types.Asset
		total             int
		start             time.Time
		cloudProviderUsed string
		cloudReport       *cloudreport.Report
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

	// Ask for admin/root at startup to improve scanning capabilities
	if !util.IsAdmin() {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Discovr can work for better scanning with admin access. Do you want to provide the access? (y/N): ")
		resp, _ := reader.ReadString('\n')
		resp = strings.TrimSpace(strings.ToLower(resp))
		if resp == "y" || resp == "yes" {
			if err := util.RelaunchWithSudo(); err != nil {
				log.Fatalf("[!] Elevation failed: %v", err)
			}
			return
		}
	}

	// Note: elevation is requested contextually (e.g., passive capture) rather than at startup.

	// Decide feature
	if *autoip {
		feature = "network"
		li, err := core.SetupLogger(feature, *logDir)
		if err != nil {
			log.Fatalf("[!] Logger setup failed: %v", err)
		}
		timestamp = li.Timestamp
		subnet, err := util.DetectLocalSubnet()
		if err != nil {
			log.Fatalf("[!] Failed to auto-detect local subnet: %v", err)
		}
		fmt.Printf("[+] Auto-detected local subnet: %s\n", subnet)
		// Offer elevation again for better OS detection if user declined earlier
		if !util.IsAdmin() {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Do you want to provide admin privileges? (y/N): ")
			resp, _ := reader.ReadString('\n')
			resp = strings.TrimSpace(strings.ToLower(resp))
			if resp == "y" || resp == "yes" {
				if err := util.RelaunchWithSudo(); err != nil {
					log.Fatalf("[!] Elevation failed: %v", err)
				}
				return
			}
		}
		start = time.Now()
		as, tot, err := network.RunNetworkDiscovery(subnet, *ports, *parallel)
		if err != nil {
			log.Fatalf("[!] Network scan failed: %v", err)
		}
		assets, total = as, tot
		elapsed(start)
		assets = enrich(assets)
		core.PrintResults(assets, total, "active assets")
	} else if *scanNetwork != "" {
		feature = "network"
		li, err := core.SetupLogger(feature, *logDir)
		if err != nil {
			log.Fatalf("[!] Logger setup failed: %v", err)
		}
		timestamp = li.Timestamp
		// Offer elevation again for better OS detection if user declined earlier
		if !util.IsAdmin() {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Use elevated privileges for better OS detection? (y/N): ")
			resp, _ := reader.ReadString('\n')
			resp = strings.TrimSpace(strings.ToLower(resp))
			if resp == "y" || resp == "yes" {
				if err := util.RelaunchWithSudo(); err != nil {
					log.Fatalf("[!] Elevation failed: %v", err)
				}
				return
			}
		}
		start = time.Now()
		as, tot, err := network.RunNetworkDiscovery(*scanNetwork, *ports, *parallel)
		if err != nil {
			log.Fatalf("[!] Network scan failed: %v", err)
		}
		assets, total = as, tot
		elapsed(start)
		assets = enrich(assets)
		core.PrintResults(assets, total, "active assets")
	} else if *cloudProv != "" {
		feature = "cloud"
		li, err := core.SetupLogger(feature, *logDir)
		if err != nil {
			log.Fatalf("[!] Logger setup failed: %v", err)
		}
		timestamp = li.Timestamp
		ctx := context.Background()
		start = time.Now()
		switch strings.ToLower(*cloudProv) {
		case "aws":
			fmt.Println("[+] Discovering AWS assets...")
			awsCfg := cloud.AWSConfig{
				Profile:         strings.TrimSpace(*profile),
				Region:          strings.TrimSpace(*region),
				AccessKeyID:     strings.TrimSpace(*awsAccessKey),
				SecretAccessKey: strings.TrimSpace(*awsSecretKey),
				SessionToken:    strings.TrimSpace(*awsSessionToken),
			}
			reader := bufio.NewReader(os.Stdin)
			awsCfg = resolveAWSProfileRegion(reader, awsCfg)
			retry := true
			for {
				as, err := cloud.DiscoverAWS(ctx, awsCfg)
				if err == nil {
					assets = enrich(as)
					break
				}
				if !retry || !strings.Contains(strings.ToLower(err.Error()), "credentials") {
					log.Fatalf("[!] AWS discovery failed: %v", err)
				}
				retry = false
				fmt.Println("[!] AWS credentials not detected. Please provide them (leave access key blank to cancel).")
				fmt.Print("AWS access key ID: ")
				ak, _ := reader.ReadString('\n')
				ak = strings.TrimSpace(ak)
				if ak == "" {
					log.Fatalf("[!] AWS discovery cancelled; credentials required")
				}
				fmt.Print("AWS secret access key: ")
				sk, _ := reader.ReadString('\n')
				sk = strings.TrimSpace(sk)
				fmt.Print("AWS session token (optional): ")
				st, _ := reader.ReadString('\n')
				awsCfg.AccessKeyID = ak
				awsCfg.SecretAccessKey = sk
				awsCfg.SessionToken = strings.TrimSpace(st)
			}
			cloudProviderUsed = "aws"
			rpt := cloudreport.Generate(cloudProviderUsed, assets)
			cloudreport.RenderConsole(rpt)
			cloudReport = &rpt
			total = len(assets)
			fmt.Printf("\n[+] %d AWS assets discovered.\n", total)
		case "gcp":
			reader := bufio.NewReader(os.Stdin)
			cfgGCP, err := resolveGCPConfig(reader, *project, *zone, *gcpCredPath)
			if err != nil {
				log.Fatalf("[!] GCP discovery failed: %v", err)
			}
			fmt.Printf("[+] Discovering GCP assets in project %s, zone %s\n", cfgGCP.Project, cfgGCP.Zone)
			retries := 0
			for {
				as, err := cloud.DiscoverGCP(ctx, cfgGCP)
				if err == nil {
					assets = enrich(as)
					break
				}
				retries++
				if retries > 1 {
					log.Fatalf("[!] GCP discovery failed: %v", err)
				}
				fmt.Printf("[!] GCP discovery failed: %v\n", err)
				fmt.Print("Enter path to GCP service account JSON (leave blank to abort): ")
				path, _ := reader.ReadString('\n')
				path = strings.TrimSpace(path)
				if path == "" {
					log.Fatalf("[!] GCP discovery cancelled; credentials required")
				}
				cfgGCP.CredentialsFile = path
			}
			cloudProviderUsed = "gcp"
			rpt := cloudreport.Generate(cloudProviderUsed, assets)
			cloudreport.RenderConsole(rpt)
			cloudReport = &rpt
			total = len(assets)
			fmt.Printf("\n[+] %d GCP assets discovered.\n", total)
		case "azure":
			reader := bufio.NewReader(os.Stdin)
			cfgAzure, err := resolveAzureConfig(ctx, reader, *subscription, *azureTenant, *azureClientID, *azureClientSecret)
			if err != nil {
				log.Fatalf("[!] Azure discovery failed: %v", err)
			}
			fmt.Printf("[+] Discovering AZURE assets in subscription %s...\n", cfgAzure.Subscription)
			as, err := cloud.DiscoverAzure(ctx, cfgAzure)
			if err != nil {
				log.Fatalf("[!] Azure discovery failed: %v", err)
			}
			assets = enrich(as)
			cloudProviderUsed = "azure"
			rpt := cloudreport.Generate(cloudProviderUsed, assets)
			cloudreport.RenderConsole(rpt)
			cloudReport = &rpt
			total = len(assets)
			fmt.Printf("\n[+] %d Azure assets discovered.\n", total)
		default:
			log.Fatalf("[!] Unsupported cloud provider. Choose aws, azure, or gcp")
		}
		elapsed(start)
	} else if *adFlag {
		feature = "ad"
		li, err := core.SetupLogger(feature, *logDir)
		if err != nil {
			log.Fatalf("[!] Logger setup failed: %v", err)
		}
		timestamp = li.Timestamp
		if *username == "" || *password == "" {
			log.Fatalf("[!] AD discovery requires --username and --password")
		}
		resolvedDomain, err := ad.ResolveDomain(*domain, *username)
		if err != nil {
			log.Fatalf("[!] Active Directory discovery failed to determine domain: %v", err)
		}
		if *domain == "" {
			fmt.Printf("[+] Using detected Active Directory domain: %s\n", resolvedDomain)
		}
		fmt.Printf("[+] Discovering Active Directory assets in %s\n", resolvedDomain)
		start = time.Now()
		as, err := ad.Discover(ad.Config{Domain: resolvedDomain, Username: *username, Password: *password})
		if err != nil {
			log.Fatalf("[!] Active Directory discovery failed: %v", err)
		}
		assets = enrich(as)
		core.PrintResults(assets, len(assets), "AD assets")
		elapsed(start)
	} else if *passiveFlag {
		feature = "passive"
		li, err := core.SetupLogger(feature, *logDir)
		if err != nil {
			log.Fatalf("[!] Logger setup failed: %v", err)
		}
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
			if err != nil {
				log.Fatalf("[!] List interfaces failed: %v", err)
			}
			fmt.Println("[+] Available interfaces:")
			for i, d := range devs {
				fmt.Printf("    [%d] %s\n", i+1, d.Name)
			}
			fmt.Print("\nSelect interface by number: ")
			var idx int
			if _, err := fmt.Scanf("%d", &idx); err != nil || idx < 1 || idx > len(devs) {
				log.Fatalf("[!] Invalid choice")
			}
			*iface = devs[idx-1].Name
		}
		fmt.Printf("[+] Running passive discovery on interface: %s\n", *iface)
		fmt.Printf("[+] Listening for ARP, DNS, DHCP, and mDNS traffic (auto-stop after %d seconds or Ctrl+C)...)\n\n", *timeoutSec)
		as, count, err := passive.Discover(passive.Config{Iface: *iface, Timeout: time.Duration(*timeoutSec) * time.Second})
		if err != nil {
			log.Fatalf("[!] Passive discovery failed: %v", err)
		}
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
	if feature != "" {
		handleExport(assets, feature, timestamp, *save, *format, cloudProviderUsed, cloudReport)
	}
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
	handleExport(sample, "smoke", ts, save, format, "", nil)
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
			if subscription == "" {
				log.Fatalf("[DRY-RUN] Missing --subscription for Azure")
			}
			fmt.Printf("[DRY-RUN] Would discover Azure assets with subscription=%q\n", subscription)
		case "gcp":
			if project == "" || zone == "" {
				log.Fatalf("[DRY-RUN] Missing --project and/or --zone for GCP")
			}
			fmt.Printf("[DRY-RUN] Would discover GCP assets with project=%q zone=%q\n", project, zone)
		default:
			log.Fatalf("[DRY-RUN] Unsupported cloud provider: %s", cloudProv)
		}
	case adFlag:
		if domain == "" || username == "" || password == "" {
			log.Fatalf("[DRY-RUN] Missing --domain, --username, or --password for AD")
		}
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

func handleExport(assets []types.Asset, feature, ts, save, format, cloudProvider string, rpt *cloudreport.Report) {
	if len(assets) == 0 {
		return
	}
	if strings.TrimSpace(ts) == "" {
		ts = time.Now().Format("20060102_150405")
	}

	ensureReport := func() *cloudreport.Report {
		if rpt != nil {
			return rpt
		}
		generated := cloudreport.Generate(cloudProvider, assets)
		rpt = &generated
		return rpt
	}

	exportCloud := func(choice string) {
		report := ensureReport()
		upper := strings.ToUpper(cloudProvider)
		switch choice {
		case "csv":
			if paths, err := cloudreport.ExportCSVs(cloudProvider, ts, *report); err != nil {
				fmt.Printf("[!] Failed to export %s CSVs: %v\n", upper, err)
			} else {
				for _, p := range paths {
					fmt.Printf("[+] %s CSV saved: %s\n", upper, p)
				}
			}
		case "html":
			if path, err := cloudreport.SaveHTML(cloudProvider, ts, *report); err != nil {
				fmt.Printf("[!] Failed to save %s HTML report: %v\n", upper, err)
			} else {
				fmt.Printf("[+] %s HTML report saved: %s\n", upper, path)
			}
		case "json":
			if err := core.SaveResults(assets, []string{"json"}, feature, ts); err != nil {
				fmt.Printf("[!] Failed to save %s JSON: %v\n", upper, err)
			}
		case "text":
			if path, err := cloudreport.Save(cloudProvider, ts, *report); err != nil {
				fmt.Printf("[!] Failed to save %s text report: %v\n", upper, err)
			} else {
				fmt.Printf("[+] %s text report saved: %s\n", upper, path)
			}
		case "all":
			if path, err := cloudreport.Save(cloudProvider, ts, *report); err != nil {
				fmt.Printf("[!] Failed to save %s text report: %v\n", upper, err)
			} else {
				fmt.Printf("[+] %s text report saved: %s\n", upper, path)
			}
			if path, err := cloudreport.SaveHTML(cloudProvider, ts, *report); err != nil {
				fmt.Printf("[!] Failed to save %s HTML report: %v\n", upper, err)
			} else {
				fmt.Printf("[+] %s HTML report saved: %s\n", upper, path)
			}
			if paths, err := cloudreport.ExportCSVs(cloudProvider, ts, *report); err != nil {
				fmt.Printf("[!] Failed to export %s CSVs: %v\n", upper, err)
			} else {
				for _, p := range paths {
					fmt.Printf("[+] %s CSV saved: %s\n", upper, p)
				}
			}
			if err := core.SaveResults(assets, []string{"json"}, feature, ts); err != nil {
				fmt.Printf("[!] Failed to save %s JSON: %v\n", upper, err)
			}
		default:
			fmt.Println("[!] Invalid format option, not saving.")
		}
	}

	exportGeneric := func(choice string) {
		switch choice {
		case "csv":
			if err := core.SaveResults(assets, []string{"csv"}, feature, ts); err != nil {
				fmt.Printf("[!] Failed to save CSV: %v\n", err)
			}
		case "json":
			if err := core.SaveResults(assets, []string{"json"}, feature, ts); err != nil {
				fmt.Printf("[!] Failed to save JSON: %v\n", err)
			}
		case "html":
			if err := core.SaveResults(assets, []string{"html"}, feature, ts); err != nil {
				fmt.Printf("[!] Failed to save HTML: %v\n", err)
			}
		case "all":
			if err := core.SaveResults(assets, []string{"csv", "json", "html"}, feature, ts); err != nil {
				fmt.Printf("[!] Failed to save results: %v\n", err)
			}
		default:
			fmt.Println("[!] Invalid format option, not saving.")
		}
	}

	execute := func(choice string) {
		choice = strings.ToLower(strings.TrimSpace(choice))
		if choice == "" {
			choice = "all"
		}
		if cloudProvider != "" {
			exportCloud(choice)
		} else {
			exportGeneric(choice)
		}
	}

	save = strings.ToLower(strings.TrimSpace(save))
	format = strings.ToLower(strings.TrimSpace(format))
	if save != "" || format != "" {
		if save == "yes" || save == "y" {
			execute(format)
		} else if save != "" {
			fmt.Println("[+] Results not saved.")
		}
		return
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nDo you want to save results? (yes/no): ")
	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(strings.ToLower(resp))
	if resp == "yes" || resp == "y" {
		prompt := "Choose format (csv/html/all): "
		if cloudProvider != "" {
			prompt = "Choose format (csv/html/all) [all includes text+csv+html+json]: "
		}
		fmt.Print(prompt)
		fmtChoice, _ := reader.ReadString('\n')
		execute(fmtChoice)
	} else {
		fmt.Println("[+] Results not saved.")
	}
}

type awsProfileInfo struct {
	Name   string
	Region string
}

type gcpConfigInfo struct {
	Name    string
	Project string
	Zone    string
}

func resolveAWSProfileRegion(reader *bufio.Reader, cfg cloud.AWSConfig) cloud.AWSConfig {
	if strings.TrimSpace(cfg.AccessKeyID) != "" && strings.TrimSpace(cfg.SecretAccessKey) != "" {
		if strings.TrimSpace(cfg.Profile) == "" {
			cfg.Profile = "default"
		}
		if strings.TrimSpace(cfg.Region) == "" {
			fmt.Print("AWS region [us-east-1]: ")
			val, _ := reader.ReadString('\n')
			val = strings.TrimSpace(val)
			if val == "" {
				val = "us-east-1"
			}
			cfg.Region = val
		}
		return cfg
	}

	profiles := detectAWSProfiles()
	var selected *awsProfileInfo
	if name := strings.TrimSpace(cfg.Profile); name != "" {
		for i := range profiles {
			if profiles[i].Name == name {
				selected = &profiles[i]
				break
			}
		}
	}

	if selected == nil {
		if len(profiles) == 1 {
			selected = &profiles[0]
			fmt.Printf("[+] Using detected AWS profile %s\n", selected.Name)
		} else if len(profiles) > 1 {
			fmt.Println("[+] Available AWS profiles:")
			for i, p := range profiles {
				label := p.Name
				if p.Region != "" {
					label = fmt.Sprintf("%s (region %s)", p.Name, p.Region)
				}
				fmt.Printf("    [%d] %s\n", i+1, label)
			}
			fmt.Printf("Select profile [1-%d] (default 1): ", len(profiles))
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			idx := 0
			if choice != "" {
				if val, err := strconv.Atoi(choice); err == nil && val > 0 && val <= len(profiles) {
					idx = val - 1
				}
			}
			selected = &profiles[idx]
		} else {
			fmt.Print("AWS profile [default]: ")
			val, _ := reader.ReadString('\n')
			val = strings.TrimSpace(val)
			if val == "" {
				val = "default"
			}
			cfg.Profile = val
			if strings.TrimSpace(cfg.Region) == "" {
				fmt.Print("AWS region [us-east-1]: ")
				reg, _ := reader.ReadString('\n')
				reg = strings.TrimSpace(reg)
				if reg == "" {
					reg = "us-east-1"
				}
				cfg.Region = reg
			}
			return cfg
		}
	}

	cfg.Profile = selected.Name
	if strings.TrimSpace(cfg.Region) == "" {
		if selected.Region != "" {
			fmt.Printf("[+] Using region %s from profile %s\n", selected.Region, selected.Name)
			cfg.Region = selected.Region
		} else {
			fmt.Print("AWS region [us-east-1]: ")
			reg, _ := reader.ReadString('\n')
			reg = strings.TrimSpace(reg)
			if reg == "" {
				reg = "us-east-1"
			}
			cfg.Region = reg
		}
	}

	return cfg
}

func detectAWSProfiles() []awsProfileInfo {
	profiles := make(map[string]*awsProfileInfo)
	addProfile := func(name string) *awsProfileInfo {
		if existing, ok := profiles[name]; ok {
			return existing
		}
		info := &awsProfileInfo{Name: name}
		profiles[name] = info
		return info
	}

	home, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(home, ".aws", "config")
		parseAWSConfigFile(configPath, addProfile, true)
		credPath := filepath.Join(home, ".aws", "credentials")
		parseAWSConfigFile(credPath, addProfile, false)
	}

	list := make([]awsProfileInfo, 0, len(profiles))
	for _, info := range profiles {
		list = append(list, *info)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

func parseAWSConfigFile(path string, add func(string) *awsProfileInfo, expectProfileKeyword bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	current := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := strings.TrimSpace(line[1 : len(line)-1])
			if expectProfileKeyword && strings.HasPrefix(section, "profile ") {
				section = strings.TrimSpace(section[len("profile "):])
			}
			current = section
			if current != "" {
				add(current)
			}
			continue
		}
		if current == "" {
			continue
		}
		if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if strings.EqualFold(key, "region") {
				add(current).Region = val
			}
		}
	}
}

func resolveGCPConfig(reader *bufio.Reader, project, zone, cred string) (cloud.GCPConfig, error) {
	proj := strings.TrimSpace(project)
	zn := strings.TrimSpace(zone)
	cred = strings.TrimSpace(cred)

	if proj == "" {
		proj = strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_PROJECT"))
	}
	if proj == "" {
		proj = strings.TrimSpace(os.Getenv("GCLOUD_PROJECT"))
	}

	configs := detectGCPConfigs()
	var selected *gcpConfigInfo
	if proj != "" {
		for i := range configs {
			if configs[i].Project == proj || configs[i].Name == proj {
				selected = &configs[i]
				if zn == "" && configs[i].Zone != "" {
					zn = configs[i].Zone
				}
				break
			}
		}
	}

	reader = ensureReader(reader)

	if selected == nil {
		if len(configs) == 1 {
			selected = &configs[0]
			if proj == "" {
				proj = configs[0].Project
			}
			if zn == "" {
				zn = configs[0].Zone
			}
			if proj != "" {
				fmt.Printf("[+] Using detected GCP project %s\n", proj)
			}
			if zn != "" {
				fmt.Printf("[+] Using detected GCP zone %s\n", zn)
			}
		} else if len(configs) > 1 && proj == "" {
			fmt.Println("[+] Available gcloud configurations:")
			for i, cfg := range configs {
				label := cfg.Name
				meta := []string{}
				if cfg.Project != "" {
					meta = append(meta, fmt.Sprintf("project %s", cfg.Project))
				}
				if cfg.Zone != "" {
					meta = append(meta, fmt.Sprintf("zone %s", cfg.Zone))
				}
				if len(meta) > 0 {
					label = fmt.Sprintf("%s (%s)", label, strings.Join(meta, ", "))
				}
				fmt.Printf("    [%d] %s\n", i+1, label)
			}
			fmt.Printf("Select configuration [1-%d] (default 1): ", len(configs))
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			idx := 0
			if choice != "" {
				if val, err := strconv.Atoi(choice); err == nil && val > 0 && val <= len(configs) {
					idx = val - 1
				}
			}
			selected = &configs[idx]
			if proj == "" {
				proj = selected.Project
			}
			if zn == "" {
				zn = selected.Zone
			}
		}
	}

	if proj == "" {
		fmt.Print("GCP project ID: ")
		val, _ := reader.ReadString('\n')
		proj = strings.TrimSpace(val)
	}
	if proj == "" {
		return cloud.GCPConfig{}, fmt.Errorf("GCP project ID is required")
	}

	if zn == "" {
		if selected != nil && selected.Zone != "" {
			zn = selected.Zone
		} else {
			fmt.Print("GCP zone (e.g., us-central1-a): ")
			val, _ := reader.ReadString('\n')
			zn = strings.TrimSpace(val)
		}
	}
	if zn == "" {
		return cloud.GCPConfig{}, fmt.Errorf("GCP zone is required")
	}

	return cloud.GCPConfig{Project: proj, Zone: zn, CredentialsFile: cred}, nil
}

func detectGCPConfigs() []gcpConfigInfo {
	configs := []gcpConfigInfo{}
	home, err := os.UserHomeDir()
	if err != nil {
		return configs
	}
	dir := filepath.Join(home, ".config", "gcloud", "configurations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return configs
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "config_") {
			continue
		}
		info := gcpConfigInfo{Name: strings.TrimPrefix(name, "config_")}
		parseGCloudConfigFile(filepath.Join(dir, name), &info)
		configs = append(configs, info)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Name < configs[j].Name })
	return configs
}

func parseGCloudConfigFile(path string, info *gcpConfigInfo) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	section := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch strings.ToLower(section) {
		case "core":
			if strings.EqualFold(key, "project") {
				info.Project = val
			}
		case "compute":
			if strings.EqualFold(key, "zone") {
				info.Zone = val
			}
		}
	}
}

func ensureReader(r *bufio.Reader) *bufio.Reader {
	if r != nil {
		return r
	}
	return bufio.NewReader(os.Stdin)
}

func resolveAzureConfig(ctx context.Context, reader *bufio.Reader, subscription, tenant, clientID, clientSecret string) (cloud.AzureConfig, error) {
	tenant = strings.TrimSpace(tenant)
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)

	var credential azcore.TokenCredential
	var err error
	if tenant != "" && clientID != "" && clientSecret != "" {
		credential, err = azidentity.NewClientSecretCredential(tenant, clientID, clientSecret, nil)
		if err != nil {
			return cloud.AzureConfig{}, fmt.Errorf("build Azure credential: %w", err)
		}
	} else {
		credential, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			fmt.Println("[!] Azure credentials not detected. Please provide service principal details.")
			if tenant == "" {
				fmt.Print("Azure tenant ID: ")
				tenant, _ = reader.ReadString('\n')
				tenant = strings.TrimSpace(tenant)
			}
			if clientID == "" {
				fmt.Print("Azure client ID: ")
				clientID, _ = reader.ReadString('\n')
				clientID = strings.TrimSpace(clientID)
			}
			if clientSecret == "" {
				fmt.Print("Azure client secret: ")
				clientSecret, _ = reader.ReadString('\n')
				clientSecret = strings.TrimSpace(clientSecret)
			}
			if tenant == "" || clientID == "" || clientSecret == "" {
				return cloud.AzureConfig{}, fmt.Errorf("Azure credentials are required")
			}
			credential, err = azidentity.NewClientSecretCredential(tenant, clientID, clientSecret, nil)
			if err != nil {
				return cloud.AzureConfig{}, fmt.Errorf("build Azure credential: %w", err)
			}
		}
	}

	subID := strings.TrimSpace(subscription)
	if subID == "" {
		subClient, err := armsubscriptions.NewClient(credential, nil)
		if err == nil {
			pager := subClient.NewListPager(nil)
			type subEntry struct {
				name string
				id   string
			}
			subs := make([]subEntry, 0, 4)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					fmt.Printf("[!] Failed to enumerate Azure subscriptions: %v\n", err)
					break
				}
				for _, s := range page.Value {
					if s == nil || s.SubscriptionID == nil {
						continue
					}
					entry := subEntry{id: *s.SubscriptionID}
					if s.DisplayName != nil {
						entry.name = *s.DisplayName
					}
					subs = append(subs, entry)
				}
			}
			if len(subs) == 1 {
				subID = subs[0].id
				fmt.Printf("[+] Using detected subscription %s\n", subID)
			} else if len(subs) > 1 {
				fmt.Println("[+] Multiple Azure subscriptions detected:")
				for i, s := range subs {
					label := s.name
					if label == "" {
						label = s.id
					}
					fmt.Printf("    [%d] %s (%s)\n", i+1, label, s.id)
				}
				fmt.Printf("Select subscription [1-%d] (default 1): ", len(subs))
				choice, _ := reader.ReadString('\n')
				choice = strings.TrimSpace(choice)
				idx := 0
				if choice != "" {
					if val, err := strconv.Atoi(choice); err == nil && val > 0 && val <= len(subs) {
						idx = val - 1
					}
				}
				subID = subs[idx].id
			}
		}
		if subID == "" {
			fmt.Print("Azure subscription ID: ")
			manual, _ := reader.ReadString('\n')
			subID = strings.TrimSpace(manual)
		}
	}
	if subID == "" {
		return cloud.AzureConfig{}, fmt.Errorf("Azure subscription ID is required")
	}

	return cloud.AzureConfig{Subscription: subID, Credential: credential}, nil
}

func elapsed(start time.Time) {
	fmt.Printf("[+] Total execution time: %.2f seconds\n", time.Since(start).Seconds())
}

// runInteractive provides a simple terminal menu for selecting discovery modes
func runInteractive(logDir string) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println()
		fmt.Println("Discovr asset scan Mode")
		fmt.Println("Select one option from list:")
		fmt.Println("  1) Active network scan")
		fmt.Println("  2) Passive discovery")
		fmt.Println("  3) Active Directory")
		fmt.Println("  4) Cloud: AWS")
		fmt.Println("  5) Cloud: Azure")
		fmt.Println("  6) Cloud: GCP")
		fmt.Println("  7) Exit")
		fmt.Print("Enter choice [1-7]: ")
		choiceStr, _ := reader.ReadString('\n')
		choiceStr = strings.TrimSpace(choiceStr)
		if choiceStr == "" {
			fmt.Println("[!] No option selected. Please try again.")
			continue
		}
		choice, err := strconv.Atoi(choiceStr)
		if err != nil {
			fmt.Println("[!] Invalid input. Please enter a number from 1-7.")
			continue
		}

		var (
			feature       string
			timestamp     string
			assets        []types.Asset
			total         int
			start         time.Time
			cloudProvider string
			cloudReport   *cloudreport.Report
		)

		switch choice {
		case 1:
			feature = "network"
			li, err := core.SetupLogger(feature, logDir)
			if err != nil {
				log.Fatalf("[!] Logger setup failed: %v", err)
			}
			timestamp = li.Timestamp

			fmt.Print("Auto-detect local subnet? (y/N): ")
			autodStr, _ := reader.ReadString('\n')
			autodStr = strings.TrimSpace(strings.ToLower(autodStr))
			var subnet string
			if autodStr == "y" || autodStr == "yes" {
				s, err := util.DetectLocalSubnet()
				if err != nil {
					log.Fatalf("[!] Failed to auto-detect local subnet: %v", err)
				}
				subnet = s
				fmt.Printf("[+] Auto-detected local subnet: %s\n", subnet)
			} else {
				fmt.Print("Enter CIDR to scan (e.g., 192.168.1.0/24): ")
				subnet, _ = reader.ReadString('\n')
				subnet = strings.TrimSpace(subnet)
				if subnet == "" {
					fmt.Println("[!] No subnet provided; returning to menu.")
					continue
				}
			}

			fmt.Println("Choose ports:")
			fmt.Println("  1) Quick (22,80,443,3389)")
			fmt.Println("  2) Medium (common infra ports)")
			fmt.Println("  3) Top 1000 (Nmap top ports)")
			fmt.Println("  4) Custom (comma-separated)")
			fmt.Print("Enter choice [1-4]: ")
			pChoiceStr, _ := reader.ReadString('\n')
			pChoiceStr = strings.TrimSpace(pChoiceStr)
			pChoice, _ := strconv.Atoi(pChoiceStr)
			portsStr := ""
			switch pChoice {
			case 1:
				portsStr = intsToCSV(portlists.Quick)
			case 2:
				portsStr = intsToCSV(portlists.Medium)
			case 3:
				portsStr = intsToCSV(portlists.NMAP_TOP_1000)
			default:
				fmt.Print("Ports to scan (e.g., 22,80,443): ")
				raw, _ := reader.ReadString('\n')
				portsStr = strings.TrimSpace(raw)
			}

			fmt.Print("Parallel workers [1]: ")
			parStr, _ := reader.ReadString('\n')
			parStr = strings.TrimSpace(parStr)
			parallel := 1
			if parStr != "" {
				if v, err := strconv.Atoi(parStr); err == nil && v > 0 {
					parallel = v
				}
			}

			if !util.IsAdmin() {
				fmt.Print("Use elevated privileges for better OS detection? (y/N): ")
				resp, _ := reader.ReadString('\n')
				resp = strings.TrimSpace(strings.ToLower(resp))
				if resp == "y" || resp == "yes" {
					if err := util.RelaunchWithSudo(); err != nil {
						log.Fatalf("[!] Elevation failed: %v", err)
					}
					return
				}
			}

			start = time.Now()
			as, tot, err := network.RunNetworkDiscovery(subnet, portsStr, parallel)
			if err != nil {
				log.Fatalf("[!] Network scan failed: %v", err)
			}
			assets = enrich(as)
			total = tot
			core.PrintResults(assets, total, "active assets")
			elapsed(start)

		case 2:
			feature = "passive"
			li, err := core.SetupLogger(feature, logDir)
			if err != nil {
				log.Fatalf("[!] Logger setup failed: %v", err)
			}
			timestamp = li.Timestamp

			fmt.Print("Interface (leave blank to choose): ")
			ifaceStr, _ := reader.ReadString('\n')
			ifaceStr = strings.TrimSpace(ifaceStr)
			if ifaceStr == "" {
				devs, err := passive.ListInterfaces()
				if err != nil || len(devs) == 0 {
					fmt.Println("[!] No interfaces available; returning to menu.")
					continue
				}
				for i, d := range devs {
					desc := d.Description
					if desc == "" {
						desc = "(no description)"
					}
					fmt.Printf("  %d) %s %s\n", i+1, d.Name, desc)
				}
				fmt.Print("Choose interface by number: ")
				ifaceChoice, _ := reader.ReadString('\n')
				ifaceChoice = strings.TrimSpace(ifaceChoice)
				idx, err := strconv.Atoi(ifaceChoice)
				if err != nil || idx <= 0 || idx > len(devs) {
					fmt.Println("[!] Invalid choice; returning to menu.")
					continue
				}
				ifaceStr = devs[idx-1].Name
			}

			fmt.Print("Timeout seconds [180]: ")
			timeoutStr, _ := reader.ReadString('\n')
			timeoutStr = strings.TrimSpace(timeoutStr)
			timeout := 180
			if timeoutStr != "" {
				if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
					timeout = t
				}
			}

			if !util.IsAdmin() {
				fmt.Print("Passive discovery may require sudo. Elevate now? (y/N): ")
				resp, _ := reader.ReadString('\n')
				resp = strings.TrimSpace(strings.ToLower(resp))
				if resp == "y" || resp == "yes" {
					if err := util.RelaunchWithSudo(); err != nil {
						log.Fatalf("[!] Elevation failed: %v", err)
					}
					return
				}
			}

			start = time.Now()
			as, tot, err := passive.Discover(passive.Config{Iface: ifaceStr, Timeout: time.Duration(timeout) * time.Second})
			if err != nil {
				log.Fatalf("[!] Passive discovery failed: %v", err)
			}
			assets = enrich(as)
			total = tot
			core.PrintResults(assets, total, "passive assets")
			elapsed(start)

		case 3:
			feature = "ad"
			li, err := core.SetupLogger(feature, logDir)
			if err != nil {
				log.Fatalf("[!] Logger setup failed: %v", err)
			}
			timestamp = li.Timestamp
			fmt.Print("AD username (user@domain or DOMAIN\\\\user): ")
			u, _ := reader.ReadString('\n')
			u = strings.TrimSpace(u)
			if u == "" {
				fmt.Println("[!] Username is required; returning to menu.")
				continue
			}
			fmt.Print("AD password: ")
			p, _ := reader.ReadString('\n')
			p = strings.TrimSpace(p)
			if p == "" {
				fmt.Println("[!] Password is required; returning to menu.")
				continue
			}
			fmt.Print("AD domain (optional, auto-detect if blank): ")
			d, _ := reader.ReadString('\n')
			d = strings.TrimSpace(d)
			resolved, err := ad.ResolveDomain(d, u)
			if err != nil {
				fmt.Printf("[!] Could not determine AD domain: %v\n", err)
				continue
			}
			if d == "" {
				fmt.Printf("[+] Using detected Active Directory domain: %s\n", resolved)
			}
			start = time.Now()
			as, err := ad.Discover(ad.Config{Domain: resolved, Username: u, Password: p})
			if err != nil {
				log.Fatalf("[!] Active Directory discovery failed: %v", err)
			}
			assets = enrich(as)
			total = len(assets)
			core.PrintResults(assets, total, "AD assets")
			elapsed(start)

		case 4:
			feature = "cloud"
			li, err := core.SetupLogger(feature, logDir)
			if err != nil {
				log.Fatalf("[!] Logger setup failed: %v", err)
			}
			timestamp = li.Timestamp
			ctx := context.Background()
			start = time.Now()
			awsCfg := resolveAWSProfileRegion(reader, cloud.AWSConfig{})
			as, err := cloud.DiscoverAWS(ctx, awsCfg)
			if err != nil {
				log.Fatalf("[!] AWS discovery failed: %v", err)
			}
			assets = enrich(as)
			cloudProvider = "aws"
			rpt := cloudreport.Generate(cloudProvider, assets)
			cloudreport.RenderConsole(rpt)
			cloudReport = &rpt
			total = len(assets)
			fmt.Printf("\n[+] %d AWS assets discovered.\n", total)
			elapsed(start)

		case 5:
			feature = "cloud"
			li, err := core.SetupLogger(feature, logDir)
			if err != nil {
				log.Fatalf("[!] Logger setup failed: %v", err)
			}
			timestamp = li.Timestamp
			ctx := context.Background()
			start = time.Now()
			cfgAzure, err := resolveAzureConfig(ctx, reader, "", "", "", "")
			if err != nil {
				fmt.Printf("[!] Azure discovery cancelled: %v\n", err)
				continue
			}
			fmt.Printf("[+] Discovering AZURE assets in subscription %s...\n", cfgAzure.Subscription)
			as, err := cloud.DiscoverAzure(ctx, cfgAzure)
			if err != nil {
				log.Fatalf("[!] Azure discovery failed: %v", err)
			}
			assets = enrich(as)
			cloudProvider = "azure"
			rpt := cloudreport.Generate(cloudProvider, assets)
			cloudreport.RenderConsole(rpt)
			cloudReport = &rpt
			total = len(assets)
			fmt.Printf("\n[+] %d Azure assets discovered.\n", total)
			elapsed(start)

		case 6:
			feature = "cloud"
			li, err := core.SetupLogger(feature, logDir)
			if err != nil {
				log.Fatalf("[!] Logger setup failed: %v", err)
			}
			timestamp = li.Timestamp
			ctx := context.Background()
			start = time.Now()
			cfgGCP, err := resolveGCPConfig(reader, "", "", "")
			if err != nil {
				fmt.Printf("[!] GCP discovery cancelled: %v\n", err)
				continue
			}
			fmt.Printf("[+] Discovering GCP assets in project %s, zone %s\n", cfgGCP.Project, cfgGCP.Zone)
			as, err := cloud.DiscoverGCP(ctx, cfgGCP)
			if err != nil {
				log.Fatalf("[!] GCP discovery failed: %v", err)
			}
			assets = enrich(as)
			cloudProvider = "gcp"
			rpt := cloudreport.Generate(cloudProvider, assets)
			cloudreport.RenderConsole(rpt)
			cloudReport = &rpt
			total = len(assets)
			fmt.Printf("\n[+] %d GCP assets discovered.\n", total)
			elapsed(start)

		case 7:
			fmt.Println("[+] Exiting Discovr interactive mode. Bye!")
			return

		default:
			fmt.Println("[!] Invalid choice. Please select a number between 1 and 7.")
			continue
		}

		if feature != "" && timestamp != "" {
			fmt.Printf(" Logs saved at Documents/discovr_reports/logs/discovr_%s_log_%s.log\n", feature, timestamp)
		}
		handleExport(assets, feature, timestamp, "", "", cloudProvider, cloudReport)
	}
}

// intsToCSV converts a slice of ints to a comma-separated string
func intsToCSV(nums []int) string {
	if len(nums) == 0 {
		return ""
	}
	b := strings.Builder{}
	for i, n := range nums {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(n))
	}
	return b.String()
}
