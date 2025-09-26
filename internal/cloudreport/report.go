package cloudreport

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"discovr/internal/types"
)

type Report struct {
	Provider string
	Summary  []SummaryRow
	Tables   []Table
}

type SummaryRow struct {
	Label string
	Count int
}

type Table struct {
	Title  string
	Header []string
	Rows   [][]string
}

func Generate(provider string, assets []types.Asset) Report {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "aws":
		return buildAWSReport(assets)
	case "azure":
		return buildAzureReport(assets)
	case "gcp":
		return buildGCPReport(assets)
	default:
		return buildGenericReport(provider, assets)
	}
}

func Save(provider, timestamp string, rpt Report) (string, error) {
	file := renderTextReport(rpt)
	provider = rpt.Provider
	if strings.TrimSpace(timestamp) == "" {
		timestamp = time.Now().Format("20060102_150405")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	base := filepath.Join(home, "Documents", "discovr_reports", "cloud")
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("ensure report dir: %w", err)
	}
	filename := fmt.Sprintf("discovr_%s_report_%s.txt", strings.ToLower(provider), timestamp)
	path := filepath.Join(base, filename)
	if err := os.WriteFile(path, []byte(file), 0o644); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}
	return path, nil
}

func buildAWSReport(assets []types.Asset) Report {
	sections := map[string][]types.Asset{
		"IAM Resources":   nil,
		"Networking":      nil,
		"Compute":         nil,
		"Storage":         nil,
		"Other Resources": nil,
	}
	for _, asset := range assets {
		cat := classifyAWS(asset)
		sections[cat] = append(sections[cat], asset)
	}
	order := []string{"IAM Resources", "Networking", "Compute", "Storage", "Other Resources"}
	tables := make([]Table, 0, len(order))
	summaries := make([]SummaryRow, 0, len(order))
	for _, key := range order {
		rows := formatAWSRows(key, sections[key])
		if len(rows) == 0 {
			continue
		}
		tables = append(tables, Table{
			Title:  key,
			Header: []string{"Type", "Name", "Details"},
			Rows:   rows,
		})
		summaries = append(summaries, SummaryRow{Label: key, Count: len(rows)})
	}
	return Report{Provider: "AWS", Summary: summaries, Tables: tables}
}

func buildAzureReport(assets []types.Asset) Report {
	sections := map[string][]types.Asset{
		"Resource Groups":         nil,
		"Virtual Machines":        nil,
		"Network Security Groups": nil,
		"Virtual Networks":        nil,
		"Other Resources":         nil,
	}
	for _, asset := range assets {
		cat := classifyAzure(asset)
		sections[cat] = append(sections[cat], asset)
	}
	order := []string{"Resource Groups", "Virtual Machines", "Network Security Groups", "Virtual Networks", "Other Resources"}
	tables := make([]Table, 0, len(order))
	summaries := make([]SummaryRow, 0, len(order))
	for _, key := range order {
		rows := formatAzureRows(key, sections[key])
		if len(rows) == 0 {
			continue
		}
		tables = append(tables, Table{
			Title:  key,
			Header: []string{"Name", "Details"},
			Rows:   rows,
		})
		summaries = append(summaries, SummaryRow{Label: key, Count: len(rows)})
	}
	return Report{Provider: "Azure", Summary: summaries, Tables: tables}
}

func buildGCPReport(assets []types.Asset) Report {
	sections := map[string][]types.Asset{
		"Compute":          nil,
		"Storage":          nil,
		"Networking":       nil,
		"Firewall Rules":   nil,
		"Forwarding Rules": nil,
		"Other Resources":  nil,
	}
	for _, asset := range assets {
		cat := classifyGCP(asset)
		sections[cat] = append(sections[cat], asset)
	}
	order := []string{"Compute", "Storage", "Networking", "Firewall Rules", "Forwarding Rules", "Other Resources"}
	tables := make([]Table, 0, len(order))
	summaries := make([]SummaryRow, 0, len(order))
	for _, key := range order {
		rows := formatGCPRows(key, sections[key])
		if len(rows) == 0 {
			continue
		}
		tables = append(tables, Table{
			Title:  key,
			Header: []string{"Type", "Name", "Details"},
			Rows:   rows,
		})
		summaries = append(summaries, SummaryRow{Label: key, Count: len(rows)})
	}
	return Report{Provider: "GCP", Summary: summaries, Tables: tables}
}

func buildGenericReport(provider string, assets []types.Asset) Report {
	rows := make([][]string, len(assets))
	for i, asset := range assets {
		rows[i] = []string{asset.Hostname, asset.OS, asset.Ports}
	}
	return Report{
		Provider: strings.ToUpper(provider),
		Summary:  []SummaryRow{{Label: "Assets", Count: len(assets)}},
		Tables: []Table{
			{Title: "Assets", Header: []string{"Hostname", "Info", "Ports"}, Rows: rows},
		},
	}
}

func classifyAWS(asset types.Asset) string {
	host := asset.Hostname
	switch {
	case strings.HasPrefix(host, "IAM User"), strings.HasPrefix(host, "IAM Role"):
		return "IAM Resources"
	case strings.HasPrefix(host, "AWS SecurityGroup"):
		return "Networking"
	case strings.HasPrefix(host, "AWS EBS"):
		return "Storage"
	case strings.HasPrefix(host, "AWS"):
		return "Other Resources"
	default:
		return "Compute"
	}
}

func formatAWSRows(section string, assets []types.Asset) [][]string {
	sortAssets(assets)
	rows := [][]string{}
	for _, asset := range assets {
		switch section {
		case "IAM Resources":
			rows = append(rows, []string{strings.Split(asset.Hostname, " ")[1], asset.Hostname, asset.OS})
		case "Networking":
			rows = append(rows, []string{"Security Group", asset.Hostname, fmt.Sprintf("Ports %s", asset.Ports)})
		case "Storage":
			rows = append(rows, []string{"EBS Volume", asset.Hostname, asset.OS})
		case "Other Resources":
			rows = append(rows, []string{"Resource", asset.Hostname, asset.OS})
		default:
			rows = append(rows, []string{"Instance", asset.Hostname, asset.OS})
		}
	}
	return rows
}

func classifyAzure(asset types.Asset) string {
	host := asset.Hostname
	switch {
	case strings.HasPrefix(host, "Azure RG"):
		return "Resource Groups"
	case strings.HasPrefix(host, "Azure NSG"):
		return "Network Security Groups"
	case strings.HasPrefix(host, "Azure VNet"):
		return "Virtual Networks"
	case strings.HasPrefix(host, "Azure"):
		return "Other Resources"
	default:
		return "Virtual Machines"
	}
}

func formatAzureRows(section string, assets []types.Asset) [][]string {
	sortAssets(assets)
	rows := make([][]string, 0, len(assets))
	for _, asset := range assets {
		rows = append(rows, []string{asset.Hostname, asset.OS})
	}
	return rows
}

func classifyGCP(asset types.Asset) string {
	host := asset.Hostname
	switch {
	case strings.HasPrefix(host, "Disk "):
		return "Storage"
	case strings.HasPrefix(host, "Image "):
		return "Storage"
	case strings.HasPrefix(host, "VPC "):
		return "Networking"
	case strings.HasPrefix(host, "Firewall "):
		return "Firewall Rules"
	case strings.HasPrefix(host, "Forwarding "):
		return "Forwarding Rules"
	case strings.HasPrefix(host, "Address "), strings.HasPrefix(host, "Global Address "):
		return "Networking"
	default:
		return "Compute"
	}
}

func formatGCPRows(section string, assets []types.Asset) [][]string {
	sortAssets(assets)
	rows := make([][]string, 0, len(assets))
	for _, asset := range assets {
		rows = append(rows, []string{section, asset.Hostname, asset.OS})
	}
	return rows
}

func sortAssets(assets []types.Asset) {
	sort.Slice(assets, func(i, j int) bool {
		return strings.ToLower(assets[i].Hostname) < strings.ToLower(assets[j].Hostname)
	})
}

func renderTextReport(r Report) string {
	var b strings.Builder
	title := fmt.Sprintf("%s Cloud Asset Report", r.Provider)
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("=", len(title)))
	b.WriteString("\n\nSummary\n-------\n")
	total := 0
	for _, row := range r.Summary {
		b.WriteString(fmt.Sprintf("%s: %d\n", row.Label, row.Count))
		total += row.Count
	}
	b.WriteString(fmt.Sprintf("Total: %d\n", total))
	for _, table := range r.Tables {
		b.WriteString("\n")
		b.WriteString(table.Title)
		b.WriteString("\n")
		b.WriteString(strings.Repeat("-", len(table.Title)))
		b.WriteString("\n")
		b.WriteString(renderTable(table.Header, table.Rows))
		b.WriteString("\n")
	}
	return b.String()
}

func renderTable(header []string, rows [][]string) string {
	if len(header) == 0 {
		return ""
	}
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, col := range row {
			if len(col) > widths[i] {
				widths[i] = len(col)
			}
		}
	}
	var b strings.Builder
	writeRow(&b, header, widths)
	b.WriteString(strings.Repeat("-", totalWidth(widths)))
	b.WriteString("\n")
	for _, row := range rows {
		writeRow(&b, row, widths)
	}
	return b.String()
}

func writeRow(b *strings.Builder, cols []string, widths []int) {
	for i, col := range cols {
		format := fmt.Sprintf("%%-%ds  ", widths[i])
		if i == len(cols)-1 {
			format = fmt.Sprintf("%%-%ds", widths[i])
		}
		b.WriteString(fmt.Sprintf(format, col))
	}
	b.WriteString("\n")
}

func totalWidth(widths []int) int {
	total := 0
	for i, w := range widths {
		total += w
		if i != len(widths)-1 {
			total += 2
		}
	}
	return total
}
