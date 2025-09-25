package passive

import (
    "fmt"
    "log"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"

    "discovr/internal/types"
)

func ListInterfaces() ([]pcap.Interface, error) { return pcap.FindAllDevs() }

type Config struct {
    Iface   string
    Timeout time.Duration
}

func Discover(cfg Config) ([]types.Asset, int, error) {
    if cfg.Timeout <= 0 { cfg.Timeout = 180 * time.Second }
    h, err := pcap.OpenLive(cfg.Iface, 65535, true, pcap.BlockForever)
    if err != nil { return nil, 0, fmt.Errorf("pcap open: %w", err) }
    defer h.Close()
    // Capture ARP, DNS(UDP 53), DHCP(67/68), mDNS(5353)
    _ = h.SetBPFFilter("arp or udp port 53 or (udp port 67 or 68) or udp port 5353")
    src := gopacket.NewPacketSource(h, h.LinkType())
    assets := map[string]types.Asset{}
    stop := time.After(cfg.Timeout)
    for {
        select {
        case pkt := <-src.Packets():
            processPacket(pkt, assets)
        case <-stop:
            return mapToSlice(assets), len(assets), nil
        }
    }
}

func processPacket(packet gopacket.Packet, assets map[string]types.Asset) {
    var ip, host string
    if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
        arp := arpLayer.(*layers.ARP)
        if len(arp.SourceProtAddress) == 4 {
            ip = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
            host = fmt.Sprintf("MAC-%x", arp.SourceHwAddress)
        }
    } else if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
        dns := dnsLayer.(*layers.DNS)
        if len(dns.Questions) > 0 && len(dns.Questions[0].Name) > 0 {
            host = string(dns.Questions[0].Name)
        }
    } else if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
        dhcp := dhcpLayer.(*layers.DHCPv4)
        if dhcp.YourClientIP != nil { ip = dhcp.YourClientIP.String() }
        host = fmt.Sprintf("DHCP-%x", dhcp.ClientHWAddr)
    }
    if host == "" && packet.TransportLayer() != nil {
        if udp, ok := packet.TransportLayer().(*layers.UDP); ok && udp.DstPort == 5353 {
            if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
                dns := dnsLayer.(*layers.DNS)
                if len(dns.Questions) > 0 && len(dns.Questions[0].Name) > 0 {
                    host = string(dns.Questions[0].Name)
                } else {
                    host = "mDNS-device"
                }
            }
        }
    }
    if ip != "" || host != "" {
        key := ip
        if key == "" { key = host }
        if _, ok := assets[key]; !ok {
            a := types.Asset{IP: ip}
            if a.IP == "" { a.IP = "N/A" }
            if host == "" { host = "Unknown" }
            a.Hostname = host
            a.OS = "Unknown"
            a.Ports = "N/A"
            log.Printf("    [+] Passive Discovery Found: %s (%s)", a.IP, a.Hostname)
            assets[key] = a
        }
    }
}

func mapToSlice(m map[string]types.Asset) []types.Asset {
    out := make([]types.Asset, 0, len(m))
    for _, v := range m { out = append(out, v) }
    return out
}

