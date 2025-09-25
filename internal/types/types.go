package types

type Asset struct {
    IP       string `json:"IP"`
    Hostname string `json:"Hostname"`
    OS       string `json:"OS"`
    Ports    string `json:"Ports"`
    Tag      string `json:"Tag,omitempty"`
    Risk     string `json:"Risk,omitempty"`
}

