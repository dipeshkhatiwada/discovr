package cloud

import (
    "context"
    "fmt"

    "discovr/internal/types"
)

// GCPConfig mirrors the real config, available even without the gcp build tag.
type GCPConfig struct {
    Project string
    Zone    string
}

// DiscoverGCP is a stub used when building without the `gcp` build tag.
func DiscoverGCP(ctx context.Context, cfg GCPConfig) ([]types.Asset, error) {
    return nil, fmt.Errorf("GCP support not built. Rebuild with -tags gcp (and ensure modules are fetched)")
}

