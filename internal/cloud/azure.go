package cloud

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	armresources "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"discovr/internal/types"
)

type AzureConfig struct {
	Subscription string
	Credential   azcore.TokenCredential
}

type azureNSGSummary struct {
	id            string
	name          string
	resourceGroup string
	location      string
	inboundPorts  []string
	outboundPorts []string
	ruleCountIn   int
	ruleCountOut  int
}

func DiscoverAzure(ctx context.Context, cfg AzureConfig) ([]types.Asset, error) {
	cred := cfg.Credential
	if cred == nil {
		var err error
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azure credential: %w", err)
		}
	}

	rgClient, err := armresources.NewResourceGroupsClient(cfg.Subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("resource group client: %w", err)
	}
	vmClient, err := armcompute.NewVirtualMachinesClient(cfg.Subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("vm client: %w", err)
	}
	nicClient, err := armnetwork.NewInterfacesClient(cfg.Subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("nic client: %w", err)
	}
	pipClient, err := armnetwork.NewPublicIPAddressesClient(cfg.Subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("pip client: %w", err)
	}
	vnetClient, err := armnetwork.NewVirtualNetworksClient(cfg.Subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("vnet client: %w", err)
	}
	nsgClient, err := armnetwork.NewSecurityGroupsClient(cfg.Subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("nsg client: %w", err)
	}

	assets := make([]types.Asset, 0, 128)

	if rgAssets, err := collectAzureResourceGroups(ctx, rgClient); err != nil {
		fmt.Printf("[!] Failed to list Azure resource groups: %v\n", err)
	} else {
		assets = append(assets, rgAssets...)
	}

	nsgSummaries, nsgAssets := collectAzureNSGs(ctx, nsgClient)
	if len(nsgAssets) > 0 {
		assets = append(assets, nsgAssets...)
	}

	if vmAssets, err := collectAzureVMs(ctx, vmClient, nicClient, pipClient, nsgSummaries); err != nil {
		fmt.Printf("[!] Failed to discover Azure virtual machines: %v\n", err)
	} else {
		assets = append(assets, vmAssets...)
	}

	if vnetAssets, err := collectAzureVNets(ctx, vnetClient); err != nil {
		fmt.Printf("[!] Failed to list Azure virtual networks: %v\n", err)
	} else {
		assets = append(assets, vnetAssets...)
	}

	return assets, nil
}

func collectAzureResourceGroups(ctx context.Context, client *armresources.ResourceGroupsClient) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list resource groups: %w", err)
		}
		for _, rg := range page.Value {
			name := safeStr(rg.Name)
			location := safeStr(rg.Location)
			tags := formatAzureTags(rg.Tags)
			osField := fmt.Sprintf("Location:%s", emptyFallback(location, "Unknown"))
			if tags != "" {
				osField = fmt.Sprintf("%s | Tags:%s", osField, tags)
			}
			assets = append(assets, types.Asset{
				IP:       "N/A",
				Hostname: fmt.Sprintf("Azure RG %s", emptyFallback(name, "(unnamed)")),
				OS:       osField,
				Ports:    "N/A",
			})
		}
	}
	return assets, nil
}

func collectAzureNSGs(ctx context.Context, client *armnetwork.SecurityGroupsClient) (map[string]azureNSGSummary, []types.Asset) {
	summaries := make(map[string]azureNSGSummary)
	assets := make([]types.Asset, 0, 32)
	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			fmt.Printf("[!] Failed to enumerate Azure NSGs: %v\n", err)
			break
		}
		for _, nsg := range page.Value {
			id := safeStr(nsg.ID)
			name := safeStr(nsg.Name)
			rg := resourceGroupFromID(id)
			inbound, outbound := extractNSGPorts(nsg.Properties)
			inboundStr := joinOrNA(inbound)
			outboundStr := joinOrNA(outbound)
			summaries[id] = azureNSGSummary{
				id:            id,
				name:          name,
				resourceGroup: rg,
				location:      safeStr(nsg.Location),
				inboundPorts:  inbound,
				outboundPorts: outbound,
				ruleCountIn:   len(inbound),
				ruleCountOut:  len(outbound),
			}
			osField := fmt.Sprintf("Location:%s | Rules in:%d out:%d", safeStr(nsg.Location), len(inbound), len(outbound))
			ports := inboundStr
			if ports == "N/A" {
				ports = outboundStr
			}
			assets = append(assets, types.Asset{
				IP:       "N/A",
				Hostname: fmt.Sprintf("Azure NSG %s", emptyFallback(name, rg)),
				OS:       osField,
				Ports:    ports,
			})
		}
	}
	return summaries, assets
}

func collectAzureVMs(ctx context.Context, vmClient *armcompute.VirtualMachinesClient, nicClient *armnetwork.InterfacesClient, pipClient *armnetwork.PublicIPAddressesClient, nsgCache map[string]azureNSGSummary) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 64)
	pager := vmClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list vms: %w", err)
		}
		for _, vm := range page.Value {
			rg := resourceGroupFromID(safeStr(vm.ID))
			name := safeStr(vm.Name)
			osType := "Unknown"
			if vm.Properties != nil && vm.Properties.StorageProfile != nil && vm.Properties.StorageProfile.OSDisk != nil && vm.Properties.StorageProfile.OSDisk.OSType != nil {
				osType = string(*vm.Properties.StorageProfile.OSDisk.OSType)
			}

			powerState := "Unknown"
			agentInfo := "Agent:unknown"
			if iv, err := vmClient.InstanceView(ctx, rg, name, nil); err == nil {
				view := iv.VirtualMachineInstanceView
				powerState = extractAzurePowerState(view.Statuses)
				agentInfo = summarizeAgent(view.VMAgent)
			}

			primaryIP, ports := resolveNICDetails(ctx, vm.Properties, nicClient, pipClient, nsgCache)
			osField := fmt.Sprintf("%s | Power:%s | %s", osType, powerState, agentInfo)
			assets = append(assets, types.Asset{
				IP:       emptyFallback(primaryIP, "N/A"),
				Hostname: emptyFallback(name, "Azure-VM"),
				OS:       osField,
				Ports:    joinOrNA(ports),
			})
		}
	}
	return assets, nil
}

func resolveNICDetails(ctx context.Context, props *armcompute.VirtualMachineProperties, nicClient *armnetwork.InterfacesClient, pipClient *armnetwork.PublicIPAddressesClient, nsgCache map[string]azureNSGSummary) (string, []string) {
	if props == nil || props.NetworkProfile == nil || len(props.NetworkProfile.NetworkInterfaces) == 0 {
		return "", nil
	}
	nicID := safeStr(props.NetworkProfile.NetworkInterfaces[0].ID)
	nicRG := resourceGroupFromID(nicID)
	nicName := resourceNameFromID(nicID)
	resp, err := nicClient.Get(ctx, nicRG, nicName, nil)
	if err != nil || resp.Interface.Properties == nil {
		if err != nil {
			fmt.Printf("[!] Failed to inspect NIC %s: %v\n", nicName, err)
		}
		return "", nil
	}

	propsNIC := resp.Interface.Properties
	privateIP := ""
	publicIP := ""
	if len(propsNIC.IPConfigurations) > 0 {
		ipConf := propsNIC.IPConfigurations[0]
		if ipConf.Properties != nil {
			if ipConf.Properties.PrivateIPAddress != nil {
				privateIP = *ipConf.Properties.PrivateIPAddress
			}
			if ipConf.Properties.PublicIPAddress != nil && ipConf.Properties.PublicIPAddress.ID != nil {
				pipID := *ipConf.Properties.PublicIPAddress.ID
				pipRG := resourceGroupFromID(pipID)
				pipName := resourceNameFromID(pipID)
				pipResp, err := pipClient.Get(ctx, pipRG, pipName, nil)
				if err == nil && pipResp.PublicIPAddress.Properties != nil && pipResp.PublicIPAddress.Properties.IPAddress != nil {
					publicIP = *pipResp.PublicIPAddress.Properties.IPAddress
				}
			}
		}
	}

	ports := make([]string, 0)
	if propsNIC.NetworkSecurityGroup != nil && propsNIC.NetworkSecurityGroup.ID != nil {
		if summary, ok := nsgCache[*propsNIC.NetworkSecurityGroup.ID]; ok {
			ports = append(ports, summary.inboundPorts...)
		}
	}
	ports = uniqueStrings(ports)
	return firstNonEmpty(publicIP, privateIP), ports
}

func collectAzureVNets(ctx context.Context, vnetClient *armnetwork.VirtualNetworksClient) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	pager := vnetClient.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list virtual networks: %w", err)
		}
		for _, vnet := range page.Value {
			name := safeStr(vnet.Name)
			rg := resourceGroupFromID(safeStr(vnet.ID))
			location := safeStr(vnet.Location)
			addressSpace := ""
			if vnet.Properties != nil && vnet.Properties.AddressSpace != nil {
				addressSpace = strings.Join(derefStrings(vnet.Properties.AddressSpace.AddressPrefixes), ",")
			}
			subnets := []string{}
			if vnet.Properties != nil && vnet.Properties.Subnets != nil {
				for _, subnet := range vnet.Properties.Subnets {
					if subnet != nil && subnet.Name != nil {
						subnets = append(subnets, *subnet.Name)
					}
				}
			}
			assets = append(assets, types.Asset{
				IP:       "N/A",
				Hostname: fmt.Sprintf("Azure VNet %s", emptyFallback(name, rg)),
				OS:       fmt.Sprintf("Location:%s | Address:%s", emptyFallback(location, "Unknown"), emptyFallback(addressSpace, "Unknown")),
				Ports:    joinOrNA(subnets),
			})
		}
	}
	return assets, nil
}

func extractNSGPorts(props *armnetwork.SecurityGroupPropertiesFormat) ([]string, []string) {
	inbound := make([]string, 0)
	outbound := make([]string, 0)
	if props == nil {
		return inbound, outbound
	}
	for _, rule := range props.SecurityRules {
		if rule == nil || rule.Properties == nil {
			continue
		}
		rp := rule.Properties
		ports := flattenPortRanges(rp.DestinationPortRange, rp.DestinationPortRanges)
		switch {
		case rp.Direction != nil && *rp.Direction == armnetwork.SecurityRuleDirectionInbound && rp.Access != nil && *rp.Access == armnetwork.SecurityRuleAccessAllow:
			inbound = append(inbound, ports...)
		case rp.Direction != nil && *rp.Direction == armnetwork.SecurityRuleDirectionOutbound && rp.Access != nil && *rp.Access == armnetwork.SecurityRuleAccessAllow:
			outbound = append(outbound, ports...)
		}
	}
	return uniqueStrings(inbound), uniqueStrings(outbound)
}

func flattenPortRanges(single *string, many []*string) []string {
	ports := make([]string, 0)
	if single != nil && *single != "" {
		ports = append(ports, strings.TrimSpace(*single))
	}
	for _, p := range many {
		if p != nil && *p != "" {
			ports = append(ports, strings.TrimSpace(*p))
		}
	}
	if len(ports) == 0 {
		ports = append(ports, "*")
	}
	return ports
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if v == "*" {
			v = "Any"
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func derefStrings(in []*string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == nil {
			continue
		}
		s := strings.TrimSpace(*v)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func extractAzurePowerState(statuses []*armcompute.InstanceViewStatus) string {
	for _, st := range statuses {
		if st == nil || st.Code == nil {
			continue
		}
		code := *st.Code
		if strings.HasPrefix(strings.ToLower(code), "powerstate/") {
			return strings.TrimPrefix(strings.ToLower(code), "powerstate/")
		}
	}
	return "unknown"
}

func summarizeAgent(agent *armcompute.VirtualMachineAgentInstanceView) string {
	if agent == nil {
		return "Agent:none"
	}
	version := "unknown"
	if agent.VMAgentVersion != nil && *agent.VMAgentVersion != "" {
		version = *agent.VMAgentVersion
	}
	status := "incompatible"
	if len(agent.Statuses) > 0 {
		for _, st := range agent.Statuses {
			if st != nil && st.DisplayStatus != nil {
				status = strings.ToLower(*st.DisplayStatus)
				break
			}
		}
	}
	return fmt.Sprintf("Agent:%s (%s)", status, version)
}

func safeStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func resourceGroupFromID(id string) string {
	parts := strings.Split(id, "/")
	for i := range parts {
		if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func resourceNameFromID(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func formatAzureTags(tags map[string]*string) string {
	if len(tags) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(tags))
	for k, v := range tags {
		if v == nil || *v == "" {
			pairs = append(pairs, k)
		} else {
			pairs = append(pairs, fmt.Sprintf("%s=%s", k, *v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ";")
}
