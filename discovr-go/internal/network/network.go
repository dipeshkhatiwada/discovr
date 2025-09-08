package network

import (
    "encoding/xml"
    "fmt"
    "net"
    "os/exec"
    "strings"
    "time"

    "discovr/internal/types"
)

// Nmap XML structures (partial)
type nmapRun struct {
    XMLName xml.Name `xml:"nmaprun"`
    Hosts   []nmapHost `xml:"host"`
}
type nmapHost struct {
    Status    nmapStatus    `xml:"status"`
    Addresses []nmapAddr    `xml:"address"`
    Hostnames nmapHostnames `xml:"hostnames"`
    OS        nmapOS        `xml:"os"`
    Ports     nmapPorts     `xml:"ports"`
}
type nmapStatus struct { State string `xml:"state,attr"` }
type nmapAddr struct { Addr string `xml:"addr,attr"`; AddrType string `xml:"addrtype,attr"` }
type nmapHostnames struct { Names []nmapHostname `xml:"hostname"` }
type nmapHostname struct { Name string `xml:"name,attr"` }
type nmapOS struct { OSMatches []nmapOSMatch `xml:"osmatch"` }
type nmapOSMatch struct {
    Name     string `xml:"name,attr"`
    Accuracy string `xml:"accuracy,attr"`
}
type nmapPorts struct { Ports []nmapPort `xml:"port"` }
type nmapPort struct {
    PortID string `xml:"portid,attr"`
    State  nmapPortState `xml:"state"`
}
type nmapPortState struct { State string `xml:"state,attr"` }

func RunNetworkDiscovery(cidr, ports string, parallel int) ([]types.Asset, int, error) {
    // Prefer nmap if available, otherwise fallback to basic scanning
    if _, err := exec.LookPath("nmap"); err == nil {
        // Try with OS detection (may require privileges)
        assets, total, err := runNmap(cidr, ports, true)
        if err == nil {
            return assets, total, nil
        }
        fmt.Printf("[!] nmap with OS detection failed (%v). Falling back to no-OS scan...\n", err)
        // Fallback: no OS detection, TCP connect scan (-sT) which doesn't require root
        assets, total, err2 := runNmap(cidr, ports, false)
        if err2 == nil {
            return assets, total, nil
        }
        fmt.Printf("[!] nmap without OS detection also failed (%v). Falling back to basic TCP scan...\n", err2)
        return runBasicScan(cidr, ports, parallel)
    }
    return runBasicScan(cidr, ports, parallel)
}

func runNmap(cidr, ports string, tryOS bool) ([]types.Asset, int, error) {
    args := []string{"-T4", "-oX", "-"}
    if tryOS {
        args = append([]string{"-O"}, args...)
    } else {
        args = append([]string{"-sT"}, args...)
    }
    if strings.TrimSpace(ports) != "" {
        args = append([]string{"-p", ports}, args...)
    }
    args = append(args, cidr)
    cmd := exec.Command("nmap", args...)
    out, err := cmd.CombinedOutput()
    if err != nil { return nil, 0, fmt.Errorf("nmap failed: %v; %s", err, strings.TrimSpace(string(out))) }
    var nr nmapRun
    if err := xml.Unmarshal(out, &nr); err != nil { return nil, 0, fmt.Errorf("parse nmap xml: %w", err) }
    assets := make([]types.Asset, 0, len(nr.Hosts))
    upCount := 0
    for _, h := range nr.Hosts {
        if h.Status.State != "up" { continue }
        upCount++
        hostname := "Unknown"
        if len(h.Hostnames.Names) > 0 && h.Hostnames.Names[0].Name != "" {
            hostname = h.Hostnames.Names[0].Name
        }
        // Determine correct IP (prefer IPv4, then IPv6; avoid MAC)
        ipStr := ""
        for _, a := range h.Addresses { if a.AddrType == "ipv4" { ipStr = a.Addr; break } }
        if ipStr == "" {
            for _, a := range h.Addresses { if a.AddrType == "ipv6" { ipStr = a.Addr; break } }
        }
        if ipStr == "" && len(h.Addresses) > 0 {
            // Fallback to first address if type missing
            ipStr = h.Addresses[0].Addr
        }
        osName := "Unknown"
        if len(h.OS.OSMatches) > 0 {
            osName = h.OS.OSMatches[0].Name
        }
        openPorts := []string{}
        for _, p := range h.Ports.Ports {
            if p.State.State == "open" {
                openPorts = append(openPorts, p.PortID)
            }
        }
        // Guess OS if unknown
        if osName == "Unknown" && len(openPorts) > 0 {
            if contains(openPorts, "445") || contains(openPorts, "3389") { osName = "Windows (guessed)" }
            if contains(openPorts, "22") && osName == "Unknown" { osName = "Linux/Unix (guessed)" }
        }
        // Reverse DNS if hostname unknown and we have an IP
        if hostname == "Unknown" && ipStr != "" {
            if names, _ := net.LookupAddr(ipStr); len(names) > 0 {
                // names typically have trailing dot
                hostname = strings.TrimSuffix(names[0], ".")
            }
        }
        assets = append(assets, types.Asset{
            IP: ipStr,
            Hostname: hostname,
            OS: osName,
            Ports: strings.Join(openPorts, ","),
        })
    }
    total, _ := countIPsInCIDR(cidr)
    return assets, total, nil
}

func runBasicScan(cidr, ports string, parallel int) ([]types.Asset, int, error) {
    // Very basic TCP connect scan as a fallback
    ipNet, err := parseCIDR(cidr)
    if err != nil { return nil, 0, err }
    var portList []string
    if strings.TrimSpace(ports) != "" { portList = splitPorts(ports) } else { portList = []string{"22","80","443","135","139","445","3389"} }

    ips := expand(ipNet)
    jobs := make(chan string)
    results := make(chan *types.Asset)
    if parallel < 1 { parallel = 1 }
    for i := 0; i < parallel; i++ {
        go func() {
            for ip := range jobs {
                open := []string{}
                for _, p := range portList {
                    conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, p), 500*time.Millisecond)
                    if err == nil {
                        _ = conn.Close()
                        open = append(open, p)
                    }
                }
                if len(open) > 0 {
                    osGuess := "Unknown"
                    if contains(open, "445") || contains(open, "3389") { osGuess = "Windows (guessed)" }
                    if contains(open, "22") && osGuess == "Unknown" { osGuess = "Linux/Unix (guessed)" }
                    host := "Unknown"
                    if names, _ := net.LookupAddr(ip); len(names) > 0 { host = strings.TrimSuffix(names[0], ".") }
                    a := types.Asset{IP: ip, Hostname: host, OS: osGuess, Ports: strings.Join(open, ",")}
                    results <- &a
                } else {
                    results <- nil
                }
            }
        }()
    }
    go func() { for _, ip := range ips { jobs <- ip } ; close(jobs) }()

    assets := make([]types.Asset, 0)
    for i := 0; i < len(ips); i++ {
        if a := <-results; a != nil { assets = append(assets, *a) }
    }
    return assets, len(ips), nil
}

func contains(s []string, v string) bool { for _, x := range s { if x==v { return true } } ; return false }

func parseCIDR(c string) (*net.IPNet, error) {
    _, n, err := net.ParseCIDR(c)
    if err != nil { return nil, fmt.Errorf("invalid network range: %w", err) }
    return n, nil
}

func splitPorts(s string) []string {
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts { p = strings.TrimSpace(p); if p != "" { out = append(out, p) } }
    return out
}

func expand(n *net.IPNet) []string {
    var ips []string
    for ip := n.IP.Mask(n.Mask); n.Contains(ip); inc(ip) {
        ips = append(ips, ip.String())
    }
    // Drop network and broadcast if present
    if len(ips) >= 2 { return ips[1:len(ips)-1] }
    return ips
}

func inc(ip net.IP) {
    for j := len(ip)-1; j>=0; j-- { ip[j]++ ; if ip[j] != 0 { break } }
}

func countIPsInCIDR(cidr string) (int, error) {
    _, n, err := net.ParseCIDR(cidr)
    if err != nil { return 0, err }
    ones, bits := n.Mask.Size()
    return 1 << (bits-ones), nil
}
