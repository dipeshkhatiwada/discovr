//go:build gcp
// +build gcp

package cloud

import "testing"

func TestSummarizeSubnets(t *testing.T) {
	input := []string{
		"projects/demo/regions/us-east1/subnetworks/default",
		"projects/demo/regions/us-west1/subnetworks/default",
		"projects/demo/regions/us-central1/subnetworks/default",
	}
	got := summarizeSubnets(input)
	want := "default [us-central1|us-east1|us-west1] (3 subnets)"
	if got != want {
		t.Fatalf("summarizeSubnets() = %q, want %q", got, want)
	}
}
