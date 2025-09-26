package core

import (
    "fmt"
    "strings"

    "discovr/internal/types"
)

func PrintResults(assets []types.Asset, totalHosts int, context string) {
    if len(assets) == 0 {
        fmt.Println("\n[!] No assets discovered.")
        return
    }
    // Build a simple ASCII table
    headers := []string{"IP", "Hostname", "OS", "Ports", "Tag", "Risk"}
    rows := make([][]string, 0, len(assets))
    for _, a := range assets {
        rows = append(rows, []string{a.IP, a.Hostname, a.OS, a.Ports, a.Tag, a.Risk})
    }
    fmt.Println("\nDiscovered Assets (final report):")
    printTable(headers, rows)
    fmt.Printf("\n[+] %d %s discovered out of %d scanned hosts.\n", len(assets), context, totalHosts)
}

func printTable(headers []string, rows [][]string) {
    // determine column widths
    widths := make([]int, len(headers))
    for i, h := range headers { widths[i] = len(h) }
    for _, r := range rows {
        for i := range r {
            if l := len(r[i]); l > widths[i] { widths[i] = l }
        }
    }
    // helper
    hline := func() {
        fmt.Print("+")
        for _, w := range widths { fmt.Print(strings.Repeat("-", w+2)); fmt.Print("+") }
        fmt.Println()
    }
    rowprint := func(cols []string) {
        fmt.Print("|")
        for i, c := range cols { fmt.Printf(" %-*s |", widths[i], c) }
        fmt.Println()
    }
    // render
    hline(); rowprint(headers); hline()
    for _, r := range rows { rowprint(r) }
    hline()
}

