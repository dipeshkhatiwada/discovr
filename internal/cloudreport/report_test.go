package cloudreport

import (
	"strings"
	"testing"

	"discovr/internal/types"
)

func TestRenderTextReportIncludesSummary(t *testing.T) {
	assets := []types.Asset{{Hostname: "IAM User test", OS: "Created:today"}}
	rpt := buildAWSReport(assets)
	out := renderTextReport(rpt)
	if !strings.Contains(out, "IAM Resources") {
		t.Fatalf("expected IAM Resources in report")
	}
	if !strings.Contains(out, "Summary") {
		t.Fatalf("expected summary in report")
	}
}
