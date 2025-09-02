package main

import (
    "fmt"
    "flag"
    "net"
    "strings"
    "time"
    "sync"
    "log"
    "discovr/portlists"
    "discovr/export"
)

// Ports are sourced from portlists package

// Struct for command-line arguments
type Config struct {
	Target     string
	QuickScan  bool
	OutputFile string
	HTMLFile   string
}

// Guess the OS based on open ports
func guessOS(openPorts []int) string {
	p := make(map[int]bool)
	for _, port := range openPorts {
		p[port] = true
	}
	if p[135] || p[445] || p[3389] {
		return "Windows (heuristic)"
	}
	if p[22] {
		return "Linux/Unix-like (heuristic)"
	}
	if p[80] || p[443] {
		return "Unknown (web)"
	}
	return "Unknown"
}

// Probe a TCP connection on a given host and port
func tcpProbe(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Scan a single host for open ports
func scanHost(host string, ports []int, timeout time.Duration) (map[string]interface{}, error) {
	var openPorts []int
	for _, port := range ports {
		if tcpProbe(host, port, timeout) {
			openPorts = append(openPorts, port)
		}
	}
	if len(openPorts) == 0 {
		return nil, nil
	}
    hostNames, _ := net.LookupAddr(host)
    hostname := ""
    if len(hostNames) > 0 {
        // take the first PTR record and trim trailing dot if present
        hostname = strings.TrimSuffix(hostNames[0], ".")
    }
    return map[string]interface{}{
        "ip":         host,
        "hostname":   hostname,
        "open_ports": strings.Join(intToStr(openPorts), ","),
        "os_guess":   guessOS(openPorts),
    }, nil
}

// Convert int array to string array
func intToStr(ints []int) []string {
	strs := make([]string, len(ints))
	for i, v := range ints {
		strs[i] = fmt.Sprintf("%d", v)
	}
	return strs
}

// Generate a list of IP addresses from a CIDR range
func cidrRange(cidr string) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal("Invalid CIDR format:", err)
	}

	var ipAddresses []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); increment(ip) {
		ipAddresses = append(ipAddresses, ip.String())
	}
	return ipAddresses
}

// Increment an IP address
func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// Run the scan on the given CIDR range
func runScan(cidr string, ports []int, concurrency int, timeout time.Duration) ([]map[string]interface{}, time.Duration) {
	// Generate IPs from the CIDR range
	var results []map[string]interface{}
	var targets []string
	for _, ip := range cidrRange(cidr) {
		targets = append(targets, ip)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	start := time.Now()

	for _, target := range targets {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			res, _ := scanHost(ip, ports, timeout)
			if res != nil {
				results = append(results, res)
			}
			<-sem
		}(target)
	}

	wg.Wait()
	elapsed := time.Since(start)

	return results, elapsed
}

// Write the scan results to a CSV file
// CSV/HTML export moved to export package


// Parse command-line arguments
func parseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.Target, "target", "192.168.1.0/24", "Target IP range (CIDR notation)")
	flag.BoolVar(&cfg.QuickScan, "quick-scan", false, "Enable quick scan (fewer ports)")
	flag.StringVar(&cfg.OutputFile, "out", "outgo/report.csv", "Output CSV file")
	flag.StringVar(&cfg.HTMLFile, "html", "outgo/report.html", "Output HTML file")
	flag.Parse()
	return cfg
}

func main() {
	// Parse command-line arguments
	cfg := parseFlags()

    // Select ports from portlists
    var ports []int
    if cfg.QuickScan {
        ports = portlists.Quick
    } else {
        ports = portlists.NMAP_TOP_1000
    }

	// Set a timeout for TCP connections
	timeout := 1 * time.Second

	// Run the scan
	results, elapsed := runScan(cfg.Target, ports, 256, timeout)

    // Write results
    export.WriteCSV(results, cfg.OutputFile)
    export.WriteHTML(results, cfg.HTMLFile)

	// Print the scan summary
	fmt.Printf("[+] Hosts scanned: %d\n", len(results))
	fmt.Printf("[+] Discovered: %d\n", len(results))
	fmt.Printf("[+] Exported to: %s and %s\n", cfg.OutputFile, cfg.HTMLFile)
	fmt.Printf("[+] Done in %.2fs\n", elapsed.Seconds())
}
