//go:build gcp
// +build gcp

package cloud

import (
	"context"
	"fmt"
	"sort"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"discovr/internal/types"
)

type GCPConfig struct {
	Project         string
	Zone            string
	CredentialsFile string
}

func DiscoverGCP(ctx context.Context, cfg GCPConfig) ([]types.Asset, error) {
	clientOpts := []option.ClientOption{}
	if path := strings.TrimSpace(cfg.CredentialsFile); path != "" {
		clientOpts = append(clientOpts, option.WithCredentialsFile(path))
	}

	assets := make([]types.Asset, 0, 128)

	instClient, err := compute.NewInstancesRESTClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcp instances client: %w", err)
	}
	defer instClient.Close()
	if instAssets, err := gcpDiscoverInstances(ctx, instClient, cfg); err != nil {
		fmt.Printf("[!] Failed to list GCP instances: %v\n", err)
	} else {
		assets = append(assets, instAssets...)
	}

	diskClient, err := compute.NewDisksRESTClient(ctx, clientOpts...)
	if err != nil {
		fmt.Printf("[!] Failed to initialize GCP disks client: %v\n", err)
	} else {
		defer diskClient.Close()
		if diskAssets, err := gcpDiscoverDisks(ctx, diskClient, cfg); err != nil {
			fmt.Printf("[!] Failed to list GCP disks: %v\n", err)
		} else {
			assets = append(assets, diskAssets...)
		}
	}

	imageClient, err := compute.NewImagesRESTClient(ctx, clientOpts...)
	if err != nil {
		fmt.Printf("[!] Failed to initialize GCP images client: %v\n", err)
	} else {
		defer imageClient.Close()
		if imageAssets, err := gcpDiscoverImages(ctx, imageClient, cfg.Project); err != nil {
			fmt.Printf("[!] Failed to list GCP images: %v\n", err)
		} else {
			assets = append(assets, imageAssets...)
		}
	}

	networkClient, err := compute.NewNetworksRESTClient(ctx, clientOpts...)
	if err != nil {
		fmt.Printf("[!] Failed to initialize GCP networks client: %v\n", err)
	} else {
		defer networkClient.Close()
		if networkAssets, err := gcpDiscoverNetworks(ctx, networkClient, cfg.Project); err != nil {
			fmt.Printf("[!] Failed to list GCP networks: %v\n", err)
		} else {
			assets = append(assets, networkAssets...)
		}
	}

	firewallClient, err := compute.NewFirewallsRESTClient(ctx, clientOpts...)
	if err != nil {
		fmt.Printf("[!] Failed to initialize GCP firewalls client: %v\n", err)
	} else {
		defer firewallClient.Close()
		if fwAssets, err := gcpDiscoverFirewalls(ctx, firewallClient, cfg.Project); err != nil {
			fmt.Printf("[!] Failed to list GCP firewalls: %v\n", err)
		} else {
			assets = append(assets, fwAssets...)
		}
	}

	regionClient, err := compute.NewAddressesRESTClient(ctx, clientOpts...)
	if err != nil {
		fmt.Printf("[!] Failed to initialize GCP addresses client: %v\n", err)
	}
	globalAddrClient, err2 := compute.NewGlobalAddressesRESTClient(ctx, clientOpts...)
	if err2 != nil {
		fmt.Printf("[!] Failed to initialize GCP global addresses client: %v\n", err2)
	}
	if regionClient != nil {
		defer regionClient.Close()
	}
	if globalAddrClient != nil {
		defer globalAddrClient.Close()
	}
	if regionClient != nil || globalAddrClient != nil {
		if addrAssets, err := gcpDiscoverAddresses(ctx, regionClient, globalAddrClient, cfg); err != nil {
			fmt.Printf("[!] Failed to list GCP addresses: %v\n", err)
		} else {
			assets = append(assets, addrAssets...)
		}
	}

	frClient, err := compute.NewForwardingRulesRESTClient(ctx, clientOpts...)
	if err != nil {
		fmt.Printf("[!] Failed to initialize GCP forwarding rules client: %v\n", err)
	}
	globalFrClient, err2 := compute.NewGlobalForwardingRulesRESTClient(ctx, clientOpts...)
	if err2 != nil {
		fmt.Printf("[!] Failed to initialize GCP global forwarding rules client: %v\n", err2)
	}
	if frClient != nil {
		defer frClient.Close()
	}
	if globalFrClient != nil {
		defer globalFrClient.Close()
	}
	if frClient != nil || globalFrClient != nil {
		if frAssets, err := gcpDiscoverForwardingRules(ctx, frClient, globalFrClient, cfg); err != nil {
			fmt.Printf("[!] Failed to list GCP forwarding rules: %v\n", err)
		} else {
			assets = append(assets, frAssets...)
		}
	}

	return assets, nil
}

func gcpDiscoverInstances(ctx context.Context, client *compute.InstancesClient, cfg GCPConfig) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	req := &computepb.ListInstancesRequest{Project: cfg.Project, Zone: cfg.Zone}
	it := client.List(ctx, req)
	for {
		inst, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list instances: %w", err)
		}
		hostname := inst.GetName()
		osName := "Unknown"
		if labels := inst.GetLabels(); labels != nil {
			if v, ok := labels["os"]; ok && strings.TrimSpace(v) != "" {
				osName = v
			}
		}
		ip := "N/A"
		if len(inst.GetNetworkInterfaces()) > 0 {
			ni := inst.GetNetworkInterfaces()[0]
			if ni.GetNetworkIP() != "" {
				ip = ni.GetNetworkIP()
			}
			if len(ni.GetAccessConfigs()) > 0 && ni.GetAccessConfigs()[0].GetNatIP() != "" {
				ip = ni.GetAccessConfigs()[0].GetNatIP()
			}
		}
		status := strings.ToLower(inst.GetStatus())
		machineType := gcpLastSegment(inst.GetMachineType())
		osField := fmt.Sprintf("%s | Status:%s | Type:%s", osName, emptyFallback(status, "unknown"), emptyFallback(machineType, "unknown"))
		assets = append(assets, types.Asset{IP: ip, Hostname: hostname, OS: osField, Ports: "N/A"})
	}
	return assets, nil
}

func gcpDiscoverDisks(ctx context.Context, client *compute.DisksClient, cfg GCPConfig) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	req := &computepb.ListDisksRequest{Project: cfg.Project, Zone: cfg.Zone}
	it := client.List(ctx, req)
	for {
		disk, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list disks: %w", err)
		}
		users := make([]string, 0, len(disk.GetUsers()))
		for _, u := range disk.GetUsers() {
			users = append(users, gcpLastSegment(u))
		}
		osField := fmt.Sprintf("Size:%dGB | Type:%s | Status:%s", disk.GetSizeGb(), gcpLastSegment(disk.GetType()), emptyFallback(strings.ToLower(disk.GetStatus()), "unknown"))
		ports := "N/A"
		if len(users) > 0 {
			sort.Strings(users)
			ports = "Users:" + strings.Join(users, ",")
		}
		assets = append(assets, types.Asset{IP: "N/A", Hostname: fmt.Sprintf("Disk %s", disk.GetName()), OS: osField, Ports: ports})
	}
	return assets, nil
}

func gcpDiscoverImages(ctx context.Context, client *compute.ImagesClient, project string) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 64)
	req := &computepb.ListImagesRequest{Project: project}
	it := client.List(ctx, req)
	for {
		img, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list images: %w", err)
		}
		osField := fmt.Sprintf("Status:%s | Size:%dGB | Family:%s", emptyFallback(strings.ToLower(img.GetStatus()), "unknown"), img.GetDiskSizeGb(), emptyFallback(img.GetFamily(), ""))
		assets = append(assets, types.Asset{IP: "N/A", Hostname: fmt.Sprintf("Image %s", img.GetName()), OS: osField, Ports: "N/A"})
	}
	return assets, nil
}

func gcpDiscoverNetworks(ctx context.Context, client *compute.NetworksClient, project string) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 16)
	req := &computepb.ListNetworksRequest{Project: project}
	it := client.List(ctx, req)
	for {
		network, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list networks: %w", err)
		}
		subnets := uniqueSegments(network.GetSubnetworks())
		mode := "unknown"
		if rc := network.GetRoutingConfig(); rc != nil && rc.GetRoutingMode() != "" {
			mode = strings.ToLower(rc.GetRoutingMode())
		}
		osField := fmt.Sprintf("AutoSubnet:%t | Routing:%s", network.GetAutoCreateSubnetworks(), mode)
		assets = append(assets, types.Asset{IP: "N/A", Hostname: fmt.Sprintf("VPC %s", network.GetName()), OS: osField, Ports: joinOrNA(subnets)})
	}
	return assets, nil
}

func gcpDiscoverFirewalls(ctx context.Context, client *compute.FirewallsClient, project string) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	req := &computepb.ListFirewallsRequest{Project: project}
	it := client.List(ctx, req)
	for {
		fw, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("list firewalls: %w", err)
		}
		allowed := summarizeFirewallAllows(fw.GetAllowed(), "allow")
		denied := summarizeFirewallDenies(fw.GetDenied(), "deny")
		ports := "N/A"
		descriptors := append(allowed, denied...)
		if len(descriptors) > 0 {
			ports = strings.Join(descriptors, ";")
		}
		osField := fmt.Sprintf("Direction:%s | Priority:%d", strings.ToLower(fw.GetDirection()), fw.GetPriority())
		assets = append(assets, types.Asset{
			IP:       "N/A",
			Hostname: fmt.Sprintf("Firewall %s", fw.GetName()),
			OS:       osField,
			Ports:    ports,
		})
	}
	return assets, nil
}

func gcpDiscoverAddresses(ctx context.Context, regional *compute.AddressesClient, global *compute.GlobalAddressesClient, cfg GCPConfig) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	region := gcpRegionFromZone(cfg.Zone)
	if regional != nil {
		req := &computepb.ListAddressesRequest{Project: cfg.Project, Region: region}
		it := regional.List(ctx, req)
		for {
			addr, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("list regional addresses: %w", err)
			}
			assets = append(assets, types.Asset{
				IP:       addr.GetAddress(),
				Hostname: fmt.Sprintf("Address %s", addr.GetName()),
				OS:       fmt.Sprintf("Type:%s | Status:%s", strings.ToLower(addr.GetAddressType()), strings.ToLower(addr.GetStatus())),
				Ports:    fmt.Sprintf("Region:%s", emptyFallback(region, "unknown")),
			})
		}
	}
	if global != nil {
		req := &computepb.ListGlobalAddressesRequest{Project: cfg.Project}
		it := global.List(ctx, req)
		for {
			addr, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("list global addresses: %w", err)
			}
			assets = append(assets, types.Asset{
				IP:       addr.GetAddress(),
				Hostname: fmt.Sprintf("Global Address %s", addr.GetName()),
				OS:       fmt.Sprintf("Type:%s | Status:%s", strings.ToLower(addr.GetAddressType()), strings.ToLower(addr.GetStatus())),
				Ports:    "Global",
			})
		}
	}
	return assets, nil
}

func gcpDiscoverForwardingRules(ctx context.Context, regional *compute.ForwardingRulesClient, global *compute.GlobalForwardingRulesClient, cfg GCPConfig) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	region := gcpRegionFromZone(cfg.Zone)
	if regional != nil {
		req := &computepb.ListForwardingRulesRequest{Project: cfg.Project, Region: region}
		it := regional.List(ctx, req)
		for {
			rule, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("list regional forwarding rules: %w", err)
			}
			assets = append(assets, gcpForwardingAsset(rule, "Regional", region))
		}
	}
	if global != nil {
		req := &computepb.ListGlobalForwardingRulesRequest{Project: cfg.Project}
		it := global.List(ctx, req)
		for {
			rule, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("list global forwarding rules: %w", err)
			}
			assets = append(assets, gcpForwardingAsset(rule, "Global", ""))
		}
	}
	return assets, nil
}

func gcpForwardingAsset(rule *computepb.ForwardingRule, scope, region string) types.Asset {
	ports := "N/A"
	if rule.GetPortRange() != "" {
		ports = rule.GetPortRange()
	}
	scheme := strings.ToLower(rule.GetLoadBalancingScheme())
	if scheme == "" {
		scheme = "unspecified"
	}
	osField := fmt.Sprintf("Scope:%s | Scheme:%s", scope, scheme)
	if rule.GetNetwork() != "" {
		osField = fmt.Sprintf("%s | Network:%s", osField, gcpLastSegment(rule.GetNetwork()))
	}
	if rule.GetTarget() != "" {
		osField = fmt.Sprintf("%s | Target:%s", osField, gcpLastSegment(rule.GetTarget()))
	}
	if region != "" {
		osField = fmt.Sprintf("%s | Region:%s", osField, region)
	}
	return types.Asset{
		IP:       emptyFallback(rule.GetIPAddress(), "N/A"),
		Hostname: fmt.Sprintf("Forwarding %s", rule.GetName()),
		OS:       osField,
		Ports:    ports,
	}
}

func summarizeFirewallAllows(items []*computepb.Allowed, prefix string) []string {
	entries := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		proto := strings.ToLower(item.GetIPProtocol())
		ports := item.GetPorts()
		if len(ports) == 0 {
			entries = append(entries, fmt.Sprintf("%s %s:*", prefix, proto))
			continue
		}
		sort.Strings(ports)
		entries = append(entries, fmt.Sprintf("%s %s:%s", prefix, proto, strings.Join(ports, ",")))
	}
	return entries
}

func uniqueSegments(entries []string) []string {
	if len(entries) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(entries))
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		seg := gcpLastSegment(entry)
		if seg == "" {
			continue
		}
		if _, ok := seen[seg]; ok {
			continue
		}
		seen[seg] = struct{}{}
		out = append(out, seg)
	}
	return out
}

func summarizeFirewallDenies(items []*computepb.Denied, prefix string) []string {
	entries := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		proto := strings.ToLower(item.GetIPProtocol())
		ports := item.GetPorts()
		if len(ports) == 0 {
			entries = append(entries, fmt.Sprintf("%s %s:*", prefix, proto))
			continue
		}
		sort.Strings(ports)
		entries = append(entries, fmt.Sprintf("%s %s:%s", prefix, proto, strings.Join(ports, ",")))
	}
	return entries
}

func gcpLastSegment(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	return parts[len(parts)-1]
}

func gcpRegionFromZone(zone string) string {
	if zone == "" {
		return ""
	}
	parts := strings.Split(zone, "-")
	if len(parts) < 2 {
		return zone
	}
	return strings.Join(parts[:len(parts)-1], "-")
}
