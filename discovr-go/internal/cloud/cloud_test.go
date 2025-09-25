package cloud

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func TestNormalizeAWSRegion(t *testing.T) {
	tests := map[string]string{
		"us-east-1a":     "us-east-1",
		"eu-west-1b":     "eu-west-1",
		"ap-southeast-2": "ap-southeast-2",
		"":               "",
	}
	for input, expected := range tests {
		got := normalizeAWSRegion(input)
		if got != expected {
			t.Fatalf("normalizeAWSRegion(%q) = %q, expected %q", input, got, expected)
		}
	}
}

func TestPermissionsToPorts(t *testing.T) {
	perms := []ec2types.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
		},
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(80),
			ToPort:     aws.Int32(443),
		},
		{
			IpProtocol: aws.String("-1"),
		},
	}
	ports := permissionsToPorts(perms)
	expected := []string{"Any", "22", "80-443"}
	if len(ports) != len(expected) {
		t.Fatalf("expected %d ports, got %d", len(expected), len(ports))
	}
	for i, exp := range expected {
		if ports[i] != exp {
			t.Fatalf("ports[%d] = %q, expected %q", i, ports[i], exp)
		}
	}
}

func TestResourceGroupFromID(t *testing.T) {
	id := "/subscriptions/123/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/vm1"
	if got := resourceGroupFromID(id); got != "myRG" {
		t.Fatalf("resourceGroupFromID returned %q", got)
	}
}

func TestUniqueStrings(t *testing.T) {
	in := []string{"80", "", "*", "443", "80"}
	out := uniqueStrings(in)
	expected := map[string]struct{}{"80": {}, "443": {}, "Any": {}}
	if len(out) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(out))
	}
	for _, val := range out {
		if _, ok := expected[val]; !ok {
			t.Fatalf("unexpected value %q in uniqueStrings output", val)
		}
		delete(expected, val)
	}
	if len(expected) != 0 {
		t.Fatalf("missing expected values: %v", expected)
	}
}

func TestCanonicalQuery(t *testing.T) {
	params := map[string]string{
		"Version": "2010-05-08",
		"Action":  "ListUsers",
		"Marker":  "foo bar",
	}
	got := canonicalQuery(params)
	expected := "Action=ListUsers&Marker=foo%20bar&Version=2010-05-08"
	if got != expected {
		t.Fatalf("canonicalQuery mismatch: got %q expected %q", got, expected)
	}
}

func TestAWSURLEncode(t *testing.T) {
	if got := awsURLEncode("a b/~", false); got != "a%20b/~" {
		t.Fatalf("awsURLEncode unexpected encoding: %q", got)
	}
}
