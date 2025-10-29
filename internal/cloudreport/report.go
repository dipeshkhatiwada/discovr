package cloudreport

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Report struct {
	Provider stringgit 
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
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get current dir: %w", err)
	}
	base := filepath.Join(dir, "discovr_reports", "cloud")
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

func SaveHTML(provider, timestamp string, rpt Report) (string, error) {
	html, err := renderHTMLReport(rpt)
	if err != nil {
		return "", fmt.Errorf("build html report: %w", err)
	}
	if strings.TrimSpace(timestamp) == "" {
		timestamp = time.Now().Format("20060102_150405")
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get current dir: %w", err)
	}
	base := filepath.Join(dir, "discovr_reports", "html")

	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", fmt.Errorf("ensure html dir: %w", err)
	}
	filename := fmt.Sprintf("discovr_%s_report_%s.html", strings.ToLower(rpt.Provider), timestamp)
	path := filepath.Join(base, filename)
	if err := os.WriteFile(path, []byte(html), 0o644); err != nil {
		return "", fmt.Errorf("write html report: %w", err)
	}
	return path, nil
}

func ExportCSVs(provider, timestamp string, rpt Report) ([]string, error) {
	if strings.TrimSpace(timestamp) == "" {
		timestamp = time.Now().Format("20060102_150405")
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get current dir: %w", err)
	}
	csvBase := filepath.Join(dir, "discovr_reports", "csv")
	if err := os.MkdirAll(csvBase, 0o755); err != nil {
		return nil, fmt.Errorf("ensure csv dir: %w", err)
	}
	folder := fmt.Sprintf("%s_%s", strings.ToLower(rpt.Provider), timestamp)
	target := filepath.Join(csvBase, folder)
	if err := os.MkdirAll(target, 0o755); err != nil {
		return nil, fmt.Errorf("ensure provider csv dir: %w", err)
	}
	paths := make([]string, 0, len(rpt.Tables)+1)
	summaryPath := filepath.Join(target, fmt.Sprintf("%s_summary_%s.csv", strings.ToLower(rpt.Provider), timestamp))
	if err := writeCSV(summaryPath, []string{"Section", "Count"}, summaryRows(rpt.Summary)); err != nil {
		return nil, err
	}
	paths = append(paths, summaryPath)
	for _, table := range rpt.Tables {
		slug := sanitize(table.Title)
		filename := fmt.Sprintf("%s_%s_%s.csv", strings.ToLower(rpt.Provider), slug, timestamp)
		path := filepath.Join(target, filename)
		if err := writeCSV(path, table.Header, table.Rows); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
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
			name := strings.TrimPrefix(asset.Hostname, "IAM ")
			rows = append(rows, []string{name, asset.Hostname, asset.OS})
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

func writeCSV(path string, header []string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv: %w", err)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, row := range rows {
		if err := w.Write(row); err != nil {
			return fmt.Errorf("write csv row: %w", err)
		}
	}
	w.Flush()
	return w.Error()
}

func summaryRows(rows []SummaryRow) [][]string {
	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, []string{r.Label, fmt.Sprintf("%d", r.Count)})
	}
	return out
}

func sanitize(name string) string {
	lower := strings.ToLower(name)
	replacer := strings.NewReplacer(" ", "_", "/", "_", "-", "_", "(", "_", ")", "", "__", "_")
	cleaned := replacer.Replace(lower)
	for strings.Contains(cleaned, "__") {
		cleaned = strings.ReplaceAll(cleaned, "__", "_")
	}
	return strings.Trim(cleaned, "_")
}

func renderHTMLReport(r Report) (string, error) {
	var b strings.Builder

	// Basic HTML header
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	title := fmt.Sprintf("%s Cloud Asset Report", r.Provider)
	b.WriteString(fmt.Sprintf("<title>%s</title>\n", title))
	b.WriteString(`
<style>
body {
	font-family: Arial, sans-serif;
	margin: 40px;
	background-color: #f9f9f9;
	color: #333;
}
h1 {
	text-align: center;
}
h2 {
	margin-top: 40px;
	border-bottom: 2px solid #0078d4;
	padding-bottom: 5px;
	color: #0078d4;
}
table {
	width: 100%;
	border-collapse: collapse;
	margin-top: 10px;
	margin-bottom: 30px;
	background: #fff;
}
th, td {
	border: 1px solid #ddd;
	padding: 8px 10px;
	text-align: left;
}
th {
	background-color: #0078d4;
	color: white;
}
tr:nth-child(even) {
	background-color: #f2f2f2;
}
.summary-table {
	width: 50%;
	margin: 0 auto 40px auto;
}
.summary-table th {
	background-color: #555;
}
.footer {
	margin-top: 50px;
	text-align: center;
	font-size: 0.9em;
	color: #888;
}
</style>
</head>
<body>
`)
	// Report Title
	b.WriteString(fmt.Sprintf("<h1>%s</h1>\n", title))
	b.WriteString(fmt.Sprintf("<p><strong>Generated:</strong> %s</p>\n", time.Now().Format("Jan 02, 2006 15:04:05")))

	// Summary section
	b.WriteString("<h2>Summary</h2>\n")
	b.WriteString("<table class=\"summary-table\">\n<thead><tr><th>Section</th><th>Count</th></tr></thead>\n<tbody>\n")

	total := 0
	for _, row := range r.Summary {
		b.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>\n", row.Label, row.Count))
		total += row.Count
	}
	b.WriteString(fmt.Sprintf("<tr><th>Total</th><th>%d</th></tr>\n", total))
	b.WriteString("</tbody></table>\n")

	// Each table (section)
	for _, table := range r.Tables {
		b.WriteString(fmt.Sprintf("<h2>%s</h2>\n", table.Title))
		b.WriteString("<table>\n<thead><tr>")
		for _, h := range table.Header {
			b.WriteString(fmt.Sprintf("<th>%s</th>", h))
		}
		b.WriteString("</tr></thead>\n<tbody>\n")

		for _, row := range table.Rows {
			b.WriteString("<tr>")
			for _, col := range row {
				b.WriteString(fmt.Sprintf("<td>%s</td>", htmlEscape(col)))
			}
			b.WriteString("</tr>\n")
		}

		b.WriteString("</tbody></table>\n")
	}

	b.WriteString(fmt.Sprintf("<div class=\"footer\">Generated by Discovr — %s</div>\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString("</body></html>")

	return b.String(), nil
}
func htmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}
