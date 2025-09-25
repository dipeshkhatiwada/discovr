package risk

import "strings"

func Assess(osName, ports, tag string) string {
    o := strings.ToLower(osName)
    p := strings.ToLower(ports)
    
    riskyPorts := []string{"3389", "23", "445", "21"}
    mediumPorts := []string{"80", "443", "3306"}

    for _, old := range []string{"windows xp", "windows vista", "windows 7", "server 2003", "server 2008"} {
        if strings.Contains(o, old) { return "Critical" }
    }
    if tag == "[IoT]" || tag == "[Printer]" { return "High" }

    if tag == "[Mobile]" || tag == "[Tablet]" {
        for _, rp := range riskyPorts { if strings.Contains(p, rp) { return "High" } }
        return "Medium"
    }

    if tag == "[Workstation]" {
        if strings.Contains(o, "windows 7") || strings.Contains(o, "vista") { return "Critical" }
        if strings.Contains(o, "windows 10") { return "Medium" }
        if strings.Contains(o, "windows 11") || strings.Contains(o, "macos") || strings.Contains(o, "darwin") { return "Low" }
        for _, rp := range riskyPorts { if strings.Contains(p, rp) { return "High" } }
    }

    if tag == "[Server]" {
        if strings.Contains(o, "server 2008") || strings.Contains(o, "server 2003") { return "Critical" }
        for _, rp := range riskyPorts { if strings.Contains(p, rp) { return "High" } }
        return "Medium"
    }

    if tag == "[Network]" {
        for _, rp := range riskyPorts { if strings.Contains(p, rp) { return "High" } }
        return "Medium"
    }

    if tag == "[WebHost]" {
        for _, mp := range mediumPorts { if strings.Contains(p, mp) { return "Medium" } }
    }

    if o == "unknown" || tag == "[Unknown]" { return "Medium" }
    return "Low"
}

