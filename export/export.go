package export

import (
    "encoding/csv"
    "fmt"
    "html/template"
    "os"
    "path/filepath"
)

// WriteCSV writes scan results to a CSV file, creating directories if needed.
func WriteCSV(rows []map[string]interface{}, outCSV string) {
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

// WriteHTML writes scan results to an HTML file with a simple client-side filter.
func WriteHTML(rows []map[string]interface{}, outHTML string) {
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

