package ad

import (
    "fmt"
    "net"
    "strings"

    ldap "github.com/go-ldap/ldap/v3"

    "discovr/internal/types"
)

type Config struct {
    Domain   string
    Username string
    Password string
}

func Discover(cfg Config) ([]types.Asset, error) {
    // Connect to LDAP on default port 389
    url := fmt.Sprintf("ldap://%s:389", cfg.Domain)
    conn, err := ldap.DialURL(url)
    if err != nil { return nil, fmt.Errorf("ldap connect: %w", err) }
    defer conn.Close()
    if err := conn.Bind(cfg.Username, cfg.Password); err != nil {
        return nil, fmt.Errorf("ldap bind failed: %w", err)
    }
    base := domainToBase(cfg.Domain)
    req := ldap.NewSearchRequest(
        base,
        ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
        "(objectClass=computer)",
        []string{"cn","dNSHostName","operatingSystem","operatingSystemVersion"},
        nil,
    )
    res, err := conn.Search(req)
    if err != nil { return nil, fmt.Errorf("ldap search: %w", err) }
    assets := make([]types.Asset, 0, len(res.Entries))
    for _, e := range res.Entries {
        fqdn := firstNonEmpty(e.GetAttributeValue("dNSHostName"), e.GetAttributeValue("cn"))
        osName := firstNonEmpty(e.GetAttributeValue("operatingSystem"), "Unknown")
        osVer := e.GetAttributeValue("operatingSystemVersion")
        if osVer != "" { osName = strings.TrimSpace(osName+" "+osVer) }
        ip := "N/A"
        if ips, _ := net.LookupIP(fqdn); len(ips) > 0 { ip = ips[0].String() }
        assets = append(assets, types.Asset{IP: ip, Hostname: fqdn, OS: osName, Ports: "N/A"})
    }
    return assets, nil
}

func domainToBase(domain string) string {
    parts := strings.Split(domain, ".")
    for i := range parts { parts[i] = "DC="+parts[i] }
    return strings.Join(parts, ",")
}

func firstNonEmpty(a, b string) string { if a != "" { return a } ; return b }

