package cloudreport

import (
	"fmt"
	"strings"
)

// RenderConsole prints the provider-specific report to stdout and returns the
// number of asset rows rendered across all sections.
func RenderConsole(r Report) int {
	provider := strings.ToUpper(strings.TrimSpace(r.Provider))
	title := fmt.Sprintf("%s Cloud Asset Report", provider)
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("=", len(title)))

	total := 0
	for _, table := range r.Tables {
		if len(table.Rows) == 0 {
			continue
		}
		fmt.Printf("\n%s\n", table.Title)
		renderASCIITable(table.Header, table.Rows)
		total += len(table.Rows)
	}

	if len(r.Summary) > 0 {
		fmt.Println("\nSummary")
		renderASCIITable([]string{"Section", "Count"}, summaryRows(r.Summary))
	}

	return total
}

func renderASCIITable(header []string, rows [][]string) {
	if len(header) == 0 {
		return
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

	hline := func() {
		fmt.Print("+")
		for _, w := range widths {
			fmt.Print(strings.Repeat("-", w+2))
			fmt.Print("+")
		}
		fmt.Println()
	}

	renderRow := func(cols []string) {
		fmt.Print("|")
		for i, col := range cols {
			fmt.Printf(" %-*s |", widths[i], col)
		}
		fmt.Println()
	}

	hline()
	renderRow(header)
	hline()
	for _, row := range rows {
		renderRow(row)
	}
	hline()
}
