package cloud

import (
    "context"
    "fmt"
    "strings"

    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
    armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"

    "discovr/internal/types"
)

type AzureConfig struct {
    Subscription string
}

func DiscoverAzure(ctx context.Context, cfg AzureConfig) ([]types.Asset, error) {
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil { return nil, fmt.Errorf("azure credential: %w", err) }
    vmClient, err := armcompute.NewVirtualMachinesClient(cfg.Subscription, cred, nil)
    if err != nil { return nil, fmt.Errorf("vm client: %w", err) }
    nicClient, err := armnetwork.NewInterfacesClient(cfg.Subscription, cred, nil)
    if err != nil { return nil, fmt.Errorf("nic client: %w", err) }
    pipClient, err := armnetwork.NewPublicIPAddressesClient(cfg.Subscription, cred, nil)
    if err != nil { return nil, fmt.Errorf("pip client: %w", err) }

    pager := vmClient.NewListAllPager(nil)
    assets := []types.Asset{}
    for pager.More() {
        page, err := pager.NextPage(ctx)
        if err != nil { return nil, fmt.Errorf("list vms: %w", err) }
        for _, vm := range page.Value {
            name := safeStr(vm.Name)
            osType := "Unknown"
            if vm.Properties != nil && vm.Properties.StorageProfile != nil && vm.Properties.StorageProfile.OSDisk != nil && vm.Properties.StorageProfile.OSDisk.OSType != nil {
                osType = string(*vm.Properties.StorageProfile.OSDisk.OSType)
            }
            privIP, pubIP := "N/A", "N/A"
            if vm.Properties != nil && vm.Properties.NetworkProfile != nil && len(vm.Properties.NetworkProfile.NetworkInterfaces) > 0 {
                nicID := safeStr(vm.Properties.NetworkProfile.NetworkInterfaces[0].ID)
                rg := resourceGroupFromID(nicID)
                nicName := resourceNameFromID(nicID)
                nic, err := nicClient.Get(ctx, rg, nicName, nil)
                if err == nil && nic.Properties != nil && len(nic.Properties.IPConfigurations) > 0 {
                    ipconf := nic.Properties.IPConfigurations[0]
                    if ipconf.Properties != nil && ipconf.Properties.PrivateIPAddress != nil {
                        privIP = *ipconf.Properties.PrivateIPAddress
                    }
                    if ipconf.Properties != nil && ipconf.Properties.PublicIPAddress != nil && ipconf.Properties.PublicIPAddress.ID != nil {
                        pipID := *ipconf.Properties.PublicIPAddress.ID
                        pipName := resourceNameFromID(pipID)
                        pipRG := resourceGroupFromID(pipID)
                        pip, err := pipClient.Get(ctx, pipRG, pipName, nil)
                        if err == nil && pip.Properties != nil && pip.Properties.IPAddress != nil {
                            pubIP = *pip.Properties.IPAddress
                        }
                    }
                }
            }
            ip := firstNonEmpty(pubIP, privIP)
            assets = append(assets, types.Asset{IP: ip, Hostname: name, OS: osType, Ports: "N/A"})
        }
    }
    return assets, nil
}

func safeStr(p *string) string { if p==nil { return "" }; return *p }

func resourceGroupFromID(id string) string {
    // format: /subscriptions/<sub>/resourceGroups/<rg>/providers/...
    parts := strings.Split(id, "/")
    for i := range parts { if strings.EqualFold(parts[i], "resourceGroups") && i+1 < len(parts) { return parts[i+1] } }
    return ""
}

func resourceNameFromID(id string) string {
    parts := strings.Split(id, "/")
    if len(parts) == 0 { return "" }
    return parts[len(parts)-1]
}

