//go:build gcp
// +build gcp

package cloud

import (
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestGCPLastSegment(t *testing.T) {
	in := "projects/demo/global/networks/default"
	if got := gcpLastSegment(in); got != "default" {
		t.Fatalf("gcpLastSegment returned %q", got)
	}
}

func TestGCPRegionFromZone(t *testing.T) {
	if got := gcpRegionFromZone("us-central1-a"); got != "us-central1" {
		t.Fatalf("expected us-central1, got %q", got)
	}
	if got := gcpRegionFromZone("customzone"); got != "customzone" {
		t.Fatalf("expected customzone, got %q", got)
	}
}

func TestSummarizeFirewallAllows(t *testing.T) {
	items := []*computepb.Allowed{
		{IPProtocol: aws.String("tcp"), Ports: []string{"80", "443"}},
		{IPProtocol: aws.String("udp"), Ports: nil},
	}
	entries := summarizeFirewallAllows(items, "allow")
	expected := []string{"allow tcp:443,80", "allow udp:*"}
	if len(entries) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(entries))
	}
	for i, exp := range expected {
		if entries[i] != exp {
			t.Fatalf("entries[%d] = %q, expected %q", i, entries[i], exp)
		}
	}
}

func TestSummarizeFirewallDenies(t *testing.T) {
	items := []*computepb.Denied{
		{IPProtocol: aws.String("icmp"), Ports: []string{}},
		{IPProtocol: aws.String("tcp"), Ports: []string{"22"}},
	}
	entries := summarizeFirewallDenies(items, "deny")
	expected := []string{"deny icmp:*", "deny tcp:22"}
	if len(entries) != len(expected) {
		t.Fatalf("expected %d entries, got %d", len(expected), len(entries))
	}
	for i, exp := range expected {
		if entries[i] != exp {
			t.Fatalf("entries[%d] = %q, expected %q", i, entries[i], exp)
		}
	}
}
