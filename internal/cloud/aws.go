package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"discovr/internal/types"
)

type AWSConfig struct {
	Profile         string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type securityGroupSummary struct {
	id            string
	name          string
	inboundPorts  string
	outboundPorts string
	inboundRules  int
	outboundRules int
	description   string
	vpcID         string
}

func DiscoverAWS(ctx context.Context, cfg AWSConfig) ([]types.Asset, error) {
	loaders := []func(*config.LoadOptions) error{}
	if cfg.Profile != "" {
		loaders = append(loaders, config.WithSharedConfigProfile(cfg.Profile))
	}
	if strings.TrimSpace(cfg.Region) != "" {
		loaders = append(loaders, config.WithRegion(strings.TrimSpace(cfg.Region)))
	}
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		loaders = append(loaders, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			strings.TrimSpace(cfg.AccessKeyID),
			strings.TrimSpace(cfg.SecretAccessKey),
			strings.TrimSpace(cfg.SessionToken),
		)))
	}

	awsCfg, err := config.LoadDefaultConfig(ctx, loaders...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	region := resolveAWSRegion(cfg.Region, awsCfg.Region)
	if region == "" {
		region = "us-east-1"
	}
	// Update region on the shared config so that service clients inherit it.
	awsCfg.Region = region

	if _, err := awsCfg.Credentials.Retrieve(ctx); err != nil {
		return nil, fmt.Errorf("retrieve aws credentials: %w", err)
	}

	ec2Client := ec2.NewFromConfig(awsCfg)

	assets := make([]types.Asset, 0, 64)
	sgCache, sgAssets := fetchSecurityGroups(ctx, ec2Client)
	if len(sgAssets) > 0 {
		assets = append(assets, sgAssets...)
	}

	if instanceAssets, err := discoverEC2Instances(ctx, ec2Client, sgCache); err != nil {
		fmt.Printf("[!] Failed to discover AWS instances: %v\n", err)
	} else {
		assets = append(assets, instanceAssets...)
	}

	if volumeAssets, err := discoverEBSVolumes(ctx, ec2Client, region); err != nil {
		fmt.Printf("[!] Failed to discover AWS EBS volumes: %v\n", err)
	} else {
		assets = append(assets, volumeAssets...)
	}
	if iamAssets, err := discoverIAM(ctx, awsCfg); err != nil {
		fmt.Printf("[!] Failed to discover AWS IAM identities: %v\n", err)
	} else {
		assets = append(assets, iamAssets...)
	}
	return assets, nil
}

func resolveAWSRegion(requested, fromConfig string) string {
	candidate := strings.TrimSpace(requested)
	if candidate == "" {
		candidate = strings.TrimSpace(fromConfig)
	}
	if candidate == "" {
		return ""
	}
	return normalizeAWSRegion(candidate)
}

func normalizeAWSRegion(region string) string {
	region = strings.TrimSpace(region)
	if len(region) >= 2 {
		last := region[len(region)-1]
		second := region[len(region)-2]
		if last >= 'a' && last <= 'z' && second >= '0' && second <= '9' && strings.Contains(region, "-") {
			return region[:len(region)-1]
		}
	}
	return region
}

func fetchSecurityGroups(ctx context.Context, client *ec2.Client) (map[string]securityGroupSummary, []types.Asset) {
	cache := make(map[string]securityGroupSummary)
	assets := make([]types.Asset, 0, 32)
	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			fmt.Printf("[!] Failed to enumerate AWS security groups: %v\n", err)
			break
		}
		for _, sg := range page.SecurityGroups {
			inbound := permissionsToPorts(sg.IpPermissions)
			outbound := permissionsToPorts(sg.IpPermissionsEgress)
			inboundStr := joinOrNA(inbound)
			outboundStr := joinOrNA(outbound)
			summary := securityGroupSummary{
				id:            aws.ToString(sg.GroupId),
				name:          aws.ToString(sg.GroupName),
				inboundPorts:  inboundStr,
				outboundPorts: outboundStr,
				inboundRules:  len(sg.IpPermissions),
				outboundRules: len(sg.IpPermissionsEgress),
				description:   aws.ToString(sg.Description),
				vpcID:         aws.ToString(sg.VpcId),
			}
			cache[summary.id] = summary

			osInfo := fmt.Sprintf("Rules in:%d out:%d | VPC:%s", summary.inboundRules, summary.outboundRules, emptyFallback(summary.vpcID, "Unknown"))
			ports := inboundStr
			if ports == "N/A" {
				ports = outboundStr
			}
			assets = append(assets, types.Asset{
				IP:       "N/A",
				Hostname: fmt.Sprintf("AWS SecurityGroup %s", emptyFallback(summary.name, summary.id)),
				OS:       osInfo,
				Ports:    ports,
			})
		}
	}
	return cache, assets
}

func discoverEC2Instances(ctx context.Context, client *ec2.Client, sgCache map[string]securityGroupSummary) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 64)
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe instances: %w", err)
		}
		for _, res := range page.Reservations {
			for _, inst := range res.Instances {
				state := string(inst.State.Name)
				if state == "terminated" || state == "shutting-down" {
					continue
				}
				hostname := extractInstanceHostname(inst)
				osName := extractInstanceOS(inst)
				ip := firstNonEmpty(aws.ToString(inst.PublicIpAddress), aws.ToString(inst.PrivateIpAddress))
				if ip == "" {
					ip = "N/A"
				}
				groupPorts := collectGroupPorts(inst.SecurityGroups, sgCache)
				ports := joinOrNA(groupPorts)
				if ports == "N/A" {
					ports = "Unknown"
				}
				osField := osName
				if inst.InstanceType != "" {
					osField = fmt.Sprintf("%s | %s", osField, inst.InstanceType)
				}
				if state != "" {
					osField = fmt.Sprintf("%s | state:%s", osField, state)
				}
				assets = append(assets, types.Asset{
					IP:       ip,
					Hostname: hostname,
					OS:       osField,
					Ports:    ports,
				})
			}
		}
	}
	return assets, nil
}

func discoverEBSVolumes(ctx context.Context, client *ec2.Client, region string) ([]types.Asset, error) {
	assets := make([]types.Asset, 0, 32)
	paginator := ec2.NewDescribeVolumesPaginator(client, &ec2.DescribeVolumesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("describe volumes: %w", err)
		}
		for _, vol := range page.Volumes {
			attachments := make([]string, 0, len(vol.Attachments))
			for _, att := range vol.Attachments {
				if att.InstanceId != nil {
					attachments = append(attachments, aws.ToString(att.InstanceId))
				}
			}
			attachStr := "None"
			if len(attachments) > 0 {
				sort.Strings(attachments)
				attachStr = strings.Join(attachments, ",")
			}
			osField := fmt.Sprintf("State:%s | Size:%d GiB", vol.State, vol.Size)
			if vol.VolumeType != "" {
				osField = fmt.Sprintf("%s | Type:%s", osField, vol.VolumeType)
			}
			assets = append(assets, types.Asset{
				IP:       "N/A",
				Hostname: fmt.Sprintf("AWS EBS %s", aws.ToString(vol.VolumeId)),
				OS:       osField,
				Ports:    fmt.Sprintf("Attached:%s", attachStr),
			})
		}
	}
	return assets, nil
}

func discoverIAM(ctx context.Context, cfg aws.Config) ([]types.Asset, error) {
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieve credentials: %w", err)
	}
	httpClient := http.DefaultClient
	if cfg.HTTPClient != nil {
		if hc, ok := cfg.HTTPClient.(*http.Client); ok && hc != nil {
			httpClient = hc
		}
	}
	service := iamQueryService{
		Endpoint:    "https://iam.amazonaws.com",
		Region:      "us-east-1",
		Service:     "iam",
		Credentials: creds,
		Client:      httpClient,
	}
	users, err := service.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := service.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	assets := make([]types.Asset, 0, len(users)+len(roles))
	for _, user := range users {
		assets = append(assets, types.Asset{
			IP:       "N/A",
			Hostname: fmt.Sprintf("IAM User %s", user.UserName),
			OS:       fmt.Sprintf("Created:%s", user.CreateDate),
			Ports:    "N/A",
		})
	}
	for _, role := range roles {
		assets = append(assets, types.Asset{
			IP:       "N/A",
			Hostname: fmt.Sprintf("IAM Role %s", role.RoleName),
			OS:       fmt.Sprintf("Path:%s", role.Path),
			Ports:    "N/A",
		})
	}
	return assets, nil
}

type iamQueryService struct {
	Endpoint    string
	Region      string
	Service     string
	Credentials aws.Credentials
	Client      *http.Client
}

type iamUser struct {
	UserName   string `xml:"UserName"`
	CreateDate string `xml:"CreateDate"`
}

type iamRole struct {
	RoleName string `xml:"RoleName"`
	Path     string `xml:"Path"`
}

type listUsersResponse struct {
	Result struct {
		Users struct {
			Members []iamUser `xml:"member"`
		} `xml:"Users"`
		IsTruncated string `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
	} `xml:"ListUsersResult"`
}

type listRolesResponse struct {
	Result struct {
		Roles struct {
			Members []iamRole `xml:"member"`
		} `xml:"Roles"`
		IsTruncated string `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
	} `xml:"ListRolesResult"`
}

func (s iamQueryService) ListUsers(ctx context.Context) ([]iamUser, error) {
	params := map[string]string{
		"MaxItems": "1000",
	}
	users := []iamUser{}
	marker := ""
	for {
		if marker != "" {
			params["Marker"] = marker
		} else {
			delete(params, "Marker")
		}
		var resp listUsersResponse
		if err := s.doRequest(ctx, "ListUsers", params, &resp); err != nil {
			return nil, err
		}
		users = append(users, resp.Result.Users.Members...)
		if strings.EqualFold(resp.Result.IsTruncated, "true") {
			marker = resp.Result.Marker
		} else {
			break
		}
	}
	return users, nil
}

func (s iamQueryService) ListRoles(ctx context.Context) ([]iamRole, error) {
	params := map[string]string{
		"MaxItems": "1000",
	}
	roles := []iamRole{}
	marker := ""
	for {
		if marker != "" {
			params["Marker"] = marker
		} else {
			delete(params, "Marker")
		}
		var resp listRolesResponse
		if err := s.doRequest(ctx, "ListRoles", params, &resp); err != nil {
			return nil, err
		}
		roles = append(roles, resp.Result.Roles.Members...)
		if strings.EqualFold(resp.Result.IsTruncated, "true") {
			marker = resp.Result.Marker
		} else {
			break
		}
	}
	return roles, nil
}

func (s iamQueryService) doRequest(ctx context.Context, action string, params map[string]string, out interface{}) error {
	query := map[string]string{
		"Action":  action,
		"Version": "2010-05-08",
	}
	for k, v := range params {
		query[k] = v
	}
	u, err := url.Parse(s.Endpoint)
	if err != nil {
		return fmt.Errorf("parse endpoint: %w", err)
	}
	qs := canonicalQuery(query)
	fullURL := fmt.Sprintf("%s://%s%s?%s", u.Scheme, u.Host, canonicalURI(u.Path), qs)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	date := time.Now().UTC()
	hash := sha256.Sum256([]byte{})
	payloadHash := hex.EncodeToString(hash[:])
	if err := signAWSRequest(req, s.Service, s.Region, s.Credentials, date, payloadHash, qs); err != nil {
		return err
	}
	res, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("iam request failed: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("iam error: %s", strings.TrimSpace(string(body)))
	}
	if err := xml.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func signAWSRequest(req *http.Request, service, region string, creds aws.Credentials, ts time.Time, payloadHash, canonicalQS string) error {
	if !creds.HasKeys() {
		return fmt.Errorf("missing AWS credentials for signing")
	}
	amzDate := ts.Format("20060102T150405Z")
	shortDate := ts.Format("20060102")
	req.Header.Set("host", req.URL.Host)
	req.Header.Set("x-amz-date", amzDate)
	canonicalHeaders := fmt.Sprintf("host:%s\n", req.URL.Host)
	canonicalHeaders += fmt.Sprintf("x-amz-date:%s\n", amzDate)
	signedHeaders := "host;x-amz-date"
	if creds.SessionToken != "" {
		req.Header.Set("x-amz-security-token", creds.SessionToken)
		canonicalHeaders += fmt.Sprintf("x-amz-security-token:%s\n", creds.SessionToken)
		signedHeaders = "host;x-amz-date;x-amz-security-token"
	}
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		canonicalQS,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	hash := sha256.Sum256([]byte(canonicalRequest))
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", shortDate, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hex.EncodeToString(hash[:]),
	}, "\n")
	signingKey := awsSigningKey(creds.SecretAccessKey, shortDate, region, service)
	signature := hmacSHA256Hex(signingKey, stringToSign)
	auth := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", creds.AccessKeyID, credentialScope, signedHeaders, signature)
	req.Header.Set("Authorization", auth)
	return nil
}

func canonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", awsURLEncode(k, false), awsURLEncode(params[k], false)))
	}
	return strings.Join(parts, "&")
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func awsURLEncode(in string, encodeSlash bool) string {
	encoded := url.QueryEscape(in)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	if !encodeSlash {
		encoded = strings.ReplaceAll(encoded, "%2F", "/")
	}
	return encoded
}

func awsSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hmacSHA256Hex(key []byte, data string) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}
func extractInstanceHostname(inst ec2types.Instance) string {
	for _, tag := range inst.Tags {
		if strings.EqualFold(aws.ToString(tag.Key), "name") && aws.ToString(tag.Value) != "" {
			return aws.ToString(tag.Value)
		}
	}
	if inst.InstanceId != nil {
		return aws.ToString(inst.InstanceId)
	}
	return "unknown-instance"
}

func extractInstanceOS(inst ec2types.Instance) string {
	if inst.PlatformDetails != nil && aws.ToString(inst.PlatformDetails) != "" {
		return aws.ToString(inst.PlatformDetails)
	}
	if inst.Platform != "" {
		if strings.EqualFold(string(inst.Platform), "windows") {
			return "Windows"
		}
		return string(inst.Platform)
	}
	if inst.ImageId != nil && aws.ToString(inst.ImageId) != "" {
		return aws.ToString(inst.ImageId)
	}
	return "Unknown"
}

func collectGroupPorts(groups []ec2types.GroupIdentifier, cache map[string]securityGroupSummary) []string {
	ports := make(map[string]struct{})
	for _, g := range groups {
		if summary, ok := cache[aws.ToString(g.GroupId)]; ok {
			for _, port := range strings.Split(summary.inboundPorts, ",") {
				port = strings.TrimSpace(port)
				if port == "" || port == "N/A" {
					continue
				}
				ports[port] = struct{}{}
			}
		}
	}
	if len(ports) == 0 {
		return nil
	}
	out := make([]string, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i] == "Any" {
			return true
		}
		if out[j] == "Any" {
			return false
		}
		return out[i] < out[j]
	})
	return out
}

func permissionsToPorts(perms []ec2types.IpPermission) []string {
	ports := make(map[string]struct{})
	for _, perm := range perms {
		proto := aws.ToString(perm.IpProtocol)
		if proto == "-1" {
			ports["Any"] = struct{}{}
			continue
		}
		from := perm.FromPort
		to := perm.ToPort
		if from == nil && to == nil {
			continue
		}
		fromVal := aws.ToInt32(from)
		toVal := aws.ToInt32(to)
		switch {
		case to == nil || fromVal == toVal:
			ports[fmt.Sprintf("%d", fromVal)] = struct{}{}
		default:
			ports[fmt.Sprintf("%d-%d", fromVal, toVal)] = struct{}{}
		}
	}
	if len(ports) == 0 {
		return nil
	}
	out := make([]string, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i] == "Any" {
			return true
		}
		if out[j] == "Any" {
			return false
		}
		return out[i] < out[j]
	})
	return out
}

func joinOrNA(values []string) string {
	if len(values) == 0 {
		return "N/A"
	}
	filtered := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			filtered = append(filtered, v)
		}
	}
	if len(filtered) == 0 {
		return "N/A"
	}
	return strings.Join(filtered, ",")
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
