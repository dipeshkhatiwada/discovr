package types

type Asset struct {
	IP          string `json:"IP"`
	Hostname    string `json:"Hostname"`
	OS          string `json:"OS"`
	Ports       string `json:"Ports"`
	NmapSummary string `json:"NmapSummary,omitempty"`
	Tag         string `json:"Tag,omitempty"`
	Risk        string `json:"Risk,omitempty"`
}
