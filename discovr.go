package main

import (
	"encoding/csv"
	"fmt"
	"flag"
	"net"
	"os"
	"strings"
	"time"
	"sync"
	"log"
	"path/filepath"
	"html/template"
)

// Define the default ports to scan
var DEFAULT_PORTS = []int{22, 80, 135, 443, 445, 3389}

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
	hostName, _ := net.LookupAddr(host)
	return map[string]interface{}{
		"ip":         host,
		"hostname":   hostName,
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
func writeCSV(rows []map[string]interface{}, outCSV string) {
	// Ensure the directory exists or create it
	dir := filepath.Dir(outCSV)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	// Create the CSV file
	file, err := os.Create(outCSV)
	if err != nil {
		fmt.Println("Error creating CSV file:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write the headers
	writer.Write([]string{"IP", "Hostname", "Open Ports", "OS Guess"})
	// Write the data rows
	for _, row := range rows {
		writer.Write([]string{
			row["ip"].(string),
			row["hostname"].(string),
			row["open_ports"].(string),
			row["os_guess"].(string),
		})
	}
}

// Write the scan results to an HTML file with search functionality
func writeHTML(rows []map[string]interface{}, outHTML string) {
	// Ensure the directory exists or create it
	dir := filepath.Dir(outHTML)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	// Define the HTML template with a search/filter feature
	tmpl, err := template.New("report").Parse(`
	<!doctype html>
	<html>
	<head>
		<title>Discovr Scan Report</title>
		<style>
			body { font-family: Arial, sans-serif; }
			table { width: 100%; border-collapse: collapse; margin-top: 20px; }
			th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
			th { background-color: #f2f2f2; }
			#q { margin: 8px 0; padding: 8px; width: 100%; }
		</style>
	</head>
	<body>
		<h1>Discovr Scan Report</h1>
		<input id="q" placeholder="Filter results..." />
		<table>
			<tr><th>IP</th><th>Hostname</th><th>Open Ports</th><th>OS Guess</th></tr>
			{{range .}}
				<tr>
					<td>{{.ip}}</td>
					<td>{{.hostname}}</td>
					<td>{{.open_ports}}</td>
					<td>{{.os_guess}}</td>
				</tr>
			{{end}}
		</table>
		<script>
			const q = document.getElementById('q');
			const rows = [...document.querySelectorAll('table tbody tr')];
			q.addEventListener('input', () => {
				const s = q.value.toLowerCase();
				rows.forEach(row => {
					row.style.display = row.textContent.toLowerCase().includes(s) ? '' : 'none';
				});
			});
		</script>
	</body>
	</html>`)

	if err != nil {
		fmt.Println("Error parsing HTML template:", err)
		return
	}

	// Create the HTML file
	file, err := os.Create(outHTML)
	if err != nil {
		fmt.Println("Error creating HTML file:", err)
		return
	}
	defer file.Close()

	// Execute the template and write to the file
	err = tmpl.Execute(file, rows)
	if err != nil {
		fmt.Println("Error executing HTML template:", err)
	}
}


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

	// Default ports to scan
	var ports []int
	if cfg.QuickScan {
		ports = []int{22, 80, 443} // Limited set of ports for quick scan
	} else {
		ports = DEFAULT_PORTS // Full port set
	}

	// Set a timeout for TCP connections
	timeout := 1 * time.Second

	// Run the scan
	results, elapsed := runScan(cfg.Target, ports, 256, timeout)

	// Write results to CSV
	writeCSV(results, cfg.OutputFile)

	// Write results to HTML
	writeHTML(results, cfg.HTMLFile)

	// Print the scan summary
	fmt.Printf("[+] Hosts scanned: %d\n", len(results))
	fmt.Printf("[+] Discovered: %d\n", len(results))
	fmt.Printf("[+] Exported to: %s and %s\n", cfg.OutputFile, cfg.HTMLFile)
	fmt.Printf("[+] Done in %.2fs\n", elapsed.Seconds())
}
