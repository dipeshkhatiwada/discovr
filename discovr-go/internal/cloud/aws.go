package cloud

import (
    "context"
    "fmt"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/ec2"

    "discovr/internal/types"
)

type AWSConfig struct {
    Profile string
    Region  string
}

func DiscoverAWS(ctx context.Context, cfg AWSConfig) ([]types.Asset, error) {
    l := []func(*config.LoadOptions) error{}
    if cfg.Profile != "" { l = append(l, config.WithSharedConfigProfile(cfg.Profile)) }
    if cfg.Region != "" { l = append(l, config.WithRegion(cfg.Region)) }
    c, err := config.LoadDefaultConfig(ctx, l...)
    if err != nil { return nil, fmt.Errorf("load aws config: %w", err) }
    ec2c := ec2.NewFromConfig(c)
    out, err := ec2c.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
    if err != nil { return nil, fmt.Errorf("describe instances: %w", err) }
    assets := []types.Asset{}
    for _, res := range out.Reservations {
        for _, inst := range res.Instances {
            var name string
            for _, t := range inst.Tags { if aws.ToString(t.Key) == "Name" { name = aws.ToString(t.Value); break } }
            if name == "" { name = aws.ToString(inst.InstanceId) }
            osName := aws.ToString(inst.PlatformDetails)
            if osName == "" { osName = "Unknown" }
            ip := firstNonEmpty(aws.ToString(inst.PublicIpAddress), aws.ToString(inst.PrivateIpAddress))
            if ip == "" { ip = "N/A" }
            assets = append(assets, types.Asset{IP: ip, Hostname: name, OS: osName, Ports: "N/A"})
        }
    }
    return assets, nil
}

func firstNonEmpty(a,b string) string { if a!="" {return a}; return b }

