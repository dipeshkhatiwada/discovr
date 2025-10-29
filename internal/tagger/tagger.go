package tagger

import "strings"

type AssetLike interface {
    GetHostname() string
    GetOS() string
    GetPorts() string
    SetTag(string)
}

func AssignTag(hostname, osName, ports string) string {
    h := strings.ToLower(hostname)
    o := strings.ToLower(osName)
    p := strings.ToLower(ports)

    if strings.Contains(h, "iphone") || strings.Contains(h, "android") || strings.Contains(h, "pixel") || strings.Contains(h, "galaxy") {
        return "[Mobile]"
    }
    if strings.Contains(o, "ios") && !strings.Contains(o, "macos") { return "[Mobile]" }
    if strings.Contains(o, "android") { return "[Mobile]" }

    if strings.Contains(h, "ipad") || strings.Contains(h, "tablet") { return "[Tablet]" }
    if strings.Contains(o, "ipad") || strings.Contains(o, "ipad os") { return "[Tablet]" }

    if strings.Contains(o, "macos") || strings.Contains(o, "os x") || (strings.Contains(o, "darwin") && !strings.Contains(o, "ios")) {
        return "[Workstation]"
    }
    if strings.Contains(o, "windows 10") || strings.Contains(o, "windows 11") { return "[Workstation]" }

    if strings.Contains(o, "server") || strings.Contains(o, "linux") { return "[Server]" }

    if strings.Contains(h, "printer") { return "[Printer]" }

    if strings.Contains(h, "camera") || strings.Contains(h, "iot") || strings.Contains(h, "chromecast") { return "[IoT]" }

    if strings.Contains(h, "router") || strings.Contains(h, "switch") || strings.Contains(h, "firewall") { return "[Network]" }

    if strings.Contains(p, "80") || strings.Contains(p, "443") { return "[WebHost]" }

    return "[Unknown]"
}

