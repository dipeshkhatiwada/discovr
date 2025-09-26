package util

import (
    "fmt"
    "net"
)

func DetectLocalSubnet() (string, error) {
    ifs, err := net.Interfaces()
    if err != nil { return "", err }
    for _, iface := range ifs {
        if (iface.Flags & net.FlagUp) == 0 { continue }
        if (iface.Flags & net.FlagLoopback) != 0 { continue }
        addrs, _ := iface.Addrs()
        for _, a := range addrs {
            if ipnet, ok := a.(*net.IPNet); ok {
                if ip4 := ipnet.IP.To4(); ip4 != nil {
                    // Construct CIDR from IPNet
                    ones, _ := ipnet.Mask.Size()
                    return fmt.Sprintf("%s/%d", ip4.String(), ones), nil
                }
            }
        }
    }
    return "", fmt.Errorf("auto-detect failed")
}

