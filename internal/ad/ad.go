package ad

import (
	"fmt"
	"net"
	"os"
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
	domain := normalizeDomain(cfg.Domain)
	if domain == "" {
		return nil, fmt.Errorf("active directory domain is required")
	}
	bindUser := formatBindUsername(cfg.Username, domain)
	if bindUser == "" {
		return nil, fmt.Errorf("active directory username is required")
	}

	// Connect to LDAP on default port 389
	url := fmt.Sprintf("ldap://%s:389", domain)
	conn, err := ldap.DialURL(url)
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()
	if err := conn.Bind(bindUser, cfg.Password); err != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}
	base := domainToBase(domain)
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=computer)",
		[]string{"cn", "dNSHostName", "operatingSystem", "operatingSystemVersion"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	assets := make([]types.Asset, 0, len(res.Entries))
	for _, e := range res.Entries {
		fqdn := firstNonEmpty(e.GetAttributeValue("dNSHostName"), e.GetAttributeValue("cn"))
		osName := firstNonEmpty(e.GetAttributeValue("operatingSystem"), "Unknown")
		osVer := e.GetAttributeValue("operatingSystemVersion")
		if osVer != "" {
			osName = strings.TrimSpace(osName + " " + osVer)
		}
		ip := "N/A"
		if ips, _ := net.LookupIP(fqdn); len(ips) > 0 {
			ip = ips[0].String()
		}
		assets = append(assets, types.Asset{IP: ip, Hostname: fqdn, OS: osName, Ports: "N/A"})
	}
	return assets, nil
}

func domainToBase(domain string) string {
	parts := strings.Split(domain, ".")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		filtered = append(filtered, "DC="+p)
	}
	return strings.Join(filtered, ",")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ResolveDomain determines the Active Directory domain using the explicit
// argument if provided, otherwise inspecting the username and common
// environment variables. It normalizes the result to a dotted, lower-case
// domain without trailing dots.
func ResolveDomain(domain, username string) (string, error) {
	resolved, err := resolveDomain(domain, username, os.LookupEnv)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

type envLookup func(string) (string, bool)

var domainEnvKeys = []string{"DISCOVR_AD_DOMAIN", "USERDNSDOMAIN", "USERDOMAIN"}

func resolveDomain(domain, username string, lookup envLookup) (string, error) {
	if d := normalizeDomain(domain); d != "" {
		return d, nil
	}
	if d := extractDomainFromUsername(username); d != "" {
		return d, nil
	}
	for _, key := range domainEnvKeys {
		if val, ok := lookup(key); ok {
			if trimmed := normalizeDomain(val); trimmed != "" {
				return trimmed, nil
			}
		}
	}
	return "", fmt.Errorf("unable to determine Active Directory domain; provide --domain")
}

func extractDomainFromUsername(username string) string {
	username = strings.TrimSpace(username)
	if username == "" {
		return ""
	}
	if at := strings.Index(username, "@"); at >= 0 && at < len(username)-1 {
		return normalizeDomain(username[at+1:])
	}
	if slash := strings.Index(username, "\\"); slash > 0 {
		return normalizeDomain(username[:slash])
	}
	return ""
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	for strings.HasSuffix(domain, ".") {
		domain = strings.TrimSuffix(domain, ".")
	}
	domain = strings.ToLower(domain)
	return domain
}

func formatBindUsername(username, domain string) string {
	username = strings.TrimSpace(username)
	if username == "" {
		return ""
	}
	if strings.Contains(username, "@") || strings.Contains(username, "\\") {
		return username
	}
	if domain == "" {
		return username
	}
	return fmt.Sprintf("%s@%s", username, domain)
}
