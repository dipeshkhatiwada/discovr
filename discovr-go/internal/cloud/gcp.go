//go:build gcp
// +build gcp

package cloud

import (
	"context"
	"fmt"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"discovr/internal/types"
)

type GCPConfig struct {
	Project string
	Zone    string
}

func DiscoverGCP(ctx context.Context, cfg GCPConfig) ([]types.Asset, error) {
	c, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp client: %w", err)
	}
	defer c.Close()
	req := &computepb.ListInstancesRequest{Project: cfg.Project, Zone: cfg.Zone}
	it := c.List(ctx, req)
	assets := []types.Asset{}
	for {
		inst, err := it.Next()
		if err != nil {
			if err.Error() == "no more items in iterator" {
				break
			}
			return nil, err
		}
		hostname := inst.GetName()
		osName := "Unknown"
		// Try label "os" if present
		if inst.Labels != nil {
			if v, ok := inst.Labels["os"]; ok {
				osName = v
			}
		}
		ip := "N/A"
		if len(inst.NetworkInterfaces) > 0 {
			ni := inst.NetworkInterfaces[0]
			if ni.NetworkIP != nil {
				ip = ni.GetNetworkIP()
			}
			if len(ni.AccessConfigs) > 0 && ni.AccessConfigs[0].NatIP != nil {
				ip = ni.AccessConfigs[0].GetNatIP()
			}
		}
		assets = append(assets, types.Asset{IP: ip, Hostname: hostname, OS: osName, Ports: "N/A"})
	}
	return assets, nil
}
