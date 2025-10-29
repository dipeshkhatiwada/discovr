package core

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"discovr/export"
	"discovr/internal/types"
)

func SaveResults(assets []types.Asset, formats []string, feature, timestamp string) error {
	dir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get current dir: %w", err)
	}
	base := filepath.Join(dir, "discovr_reports")
	csvDir := filepath.Join(base, "csv")
	jsonDir := filepath.Join(base, "json")
	htmlDir := filepath.Join(base, "html")
	if err := os.MkdirAll(csvDir, 0o755); err != nil {
		return fmt.Errorf("make csv dir: %w", err)
	}
	if err := os.MkdirAll(jsonDir, 0o755); err != nil {
		return fmt.Errorf("make json dir: %w", err)
	}
	if err := os.MkdirAll(htmlDir, 0o755); err != nil {
		return fmt.Errorf("make html dir: %w", err)
	}

	// Normalize output-friendly fields
	normalized := make([]types.Asset, 0, len(assets))
	for _, a := range assets {
		a.Ports = strings.TrimSpace(a.Ports)
		if a.Ports == "" {
			a.Ports = "None"
		}
		a.Ports = compressRepeatedTokens(a.Ports)

		a.NmapSummary = strings.TrimSpace(a.NmapSummary)
		if a.NmapSummary == "" {
			a.NmapSummary = "None"
		}
		normalized = append(normalized, a)
	}

	for _, f := range formats {
		switch strings.ToLower(f) {
		case "csv":
			csvPath := filepath.Join(csvDir, fmt.Sprintf("discovr_%s_%s.csv", feature, timestamp))
			if err := saveCSV(csvPath, normalized); err != nil {
				return err
			}
			fmt.Printf("[+] CSV saved: %s\n", csvPath)
		case "json":
			jsonPath := filepath.Join(jsonDir, fmt.Sprintf("discovr_%s_%s.json", feature, timestamp))
			if err := saveJSON(jsonPath, normalized); err != nil {
				return err
			}
			fmt.Printf("[+] JSON saved: %s\n", jsonPath)
		case "html":
			htmlPath := filepath.Join(htmlDir, fmt.Sprintf("discovr_%s_%s.html", feature, timestamp))
			if err := saveHTML(htmlPath, normalized); err != nil {
				return err
			}
			fmt.Printf("[+] HTML saved: %s\n", htmlPath)
		}
	}
	return nil
}

func saveCSV(path string, assets []types.Asset) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	w.Write([]string{"IP", "Hostname", "OS", "Ports", "Nmap Summary", "Tag", "Risk"})
	for _, a := range assets {
		if err := w.Write([]string{a.IP, a.Hostname, a.OS, a.Ports, a.NmapSummary, a.Tag, a.Risk}); err != nil {
			return err
		}
	}
	return w.Error()
}

func saveJSON(path string, assets []types.Asset) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "    ")
	return enc.Encode(assets)
}

func saveHTML(path string, assets []types.Asset) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	rows := make([]map[string]interface{}, len(assets))
	for i, a := range assets {
		rows[i] = map[string]interface{}{
			"ip":           a.IP,
			"hostname":     a.Hostname,
			"open_ports":   a.Ports,
			"nmap_summary": a.NmapSummary,
			"os_guess":     a.OS,
		}
	}
	return export.WriteHTML(rows, path)
}

func compressRepeatedTokens(input string) string {
	if input == "" {
		return input
	}
	if !strings.Contains(input, ",") {
		return input
	}
	parts := strings.Split(input, ",")
	counts := make(map[string]int, len(parts))
	order := make([]string, 0, len(parts))
	for _, raw := range parts {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		if _, ok := counts[token]; !ok {
			order = append(order, token)
		}
		counts[token]++
	}
	if len(order) == 0 {
		return input
	}
	allSingle := true
	for _, token := range order {
		if counts[token] > 1 {
			allSingle = false
			break
		}
	}
	if allSingle {
		return strings.Join(order, ",")
	}
	result := make([]string, 0, len(order))
	for _, token := range order {
		if counts[token] > 1 {
			result = append(result, fmt.Sprintf("%s (x%d)", token, counts[token]))
		} else {
			result = append(result, token)
		}
	}
	return strings.Join(result, ",")
}
