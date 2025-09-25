package core

import (
    "encoding/csv"
    "encoding/json"
    "fmt"
    "html/template"
    "os"
    "path/filepath"
    "strings"

    "discovr/internal/types"
)

func SaveResults(assets []types.Asset, formats []string, feature, timestamp string) error {
    home, err := os.UserHomeDir()
    if err != nil {
        return fmt.Errorf("get home dir: %w", err)
    }
    base := filepath.Join(home, "Documents", "discovr_reports")
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

    // Normalize ports to comma-separated string
    normalized := make([]types.Asset, 0, len(assets))
    for _, a := range assets {
        a.Ports = strings.TrimSpace(a.Ports)
        if a.Ports == "" {
            a.Ports = "None"
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
    if err != nil { return err }
    defer f.Close()
    w := csv.NewWriter(f)
    defer w.Flush()
    w.Write([]string{"IP", "Hostname", "OS", "Ports", "Tag", "Risk"})
    for _, a := range assets {
        if err := w.Write([]string{a.IP, a.Hostname, a.OS, a.Ports, a.Tag, a.Risk}); err != nil { return err }
    }
    return w.Error()
}

func saveJSON(path string, assets []types.Asset) error {
    f, err := os.Create(path)
    if err != nil { return err }
    defer f.Close()
    enc := json.NewEncoder(f)
    enc.SetIndent("", "    ")
    return enc.Encode(assets)
}

func saveHTML(path string, assets []types.Asset) error {
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { return err }
    const tpl = `<!doctype html>
<html>
<head>
    <meta charset="utf-8" />
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
        <thead>
            <tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open Ports</th><th>Tag</th><th>Risk</th></tr>
        </thead>
        <tbody>
        {{range .}}
            <tr>
                <td>{{.IP}}</td>
                <td>{{.Hostname}}</td>
                <td>{{.OS}}</td>
                <td>{{.Ports}}</td>
                <td>{{.Tag}}</td>
                <td>{{.Risk}}</td>
            </tr>
        {{end}}
        </tbody>
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
</html>`
    t, err := template.New("report").Parse(tpl)
    if err != nil { return err }
    f, err := os.Create(path)
    if err != nil { return err }
    defer f.Close()
    return t.Execute(f, assets)
}
