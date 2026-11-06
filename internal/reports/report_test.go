package reports

import (
	"strings"
	"testing"
	"time"

	"vuln-research/internal/domain"
)

func TestGenerateMarkdownReport(t *testing.T) {
	rep := &ResearchReport{
		JobID:              "job-uuid-1",
		RepositoryRef:      "github.com/example/defi-vault",
		RepositoryRevision: "commit-abc1234",
		JobStatus:          domain.JobStatusConfirmed,
		GeneratedAt:        time.Now().UTC(),
		Summary: ReportSummary{
			TotalCandidates: 2,
			TotalHypotheses: 2,
			Confirmed:       1,
			Refuted:         1,
		},
		ConfirmedFindings: []FindingDetail{
			{
				HypothesisID: "hyp-uuid-1",
				Title:        "Reentrancy on withdraw function",
				Status:       domain.HypothesisConfirmed,
				Weakness:     domain.Weakness{CWE: "CWE-841", Category: "reentrancy"},
				AffectedLocations: []domain.AffectedLocation{
					{Path: "src/vault.sol", Symbol: "withdraw", LineStart: 20, LineEnd: 35},
				},
				SecurityInvariant: "Vault assets must not drop below liabilities",
				Impact:            "Liquidity drainage",
				Validations: []*domain.ValidationResult{
					{
						TestCommandID: "forge test --mt testExploit",
						Outcome:       domain.ValidationOutcomeReproduced,
						ExitCode:      1,
						Notes:         "Reentrancy assertion triggered",
					},
				},
			},
		},
		RefutedFindings: []FindingDetail{
			{
				HypothesisID: "hyp-uuid-2",
				Title:        "Unchecked return value",
				Status:       domain.HypothesisRefuted,
				Weakness:     domain.Weakness{CWE: "CWE-252", Category: "error_handling"},
				Counterarguments: []string{
					"SafeERC20 wrapper reverts on boolean false",
				},
			},
		},
	}

	md := rep.GenerateMarkdownReport()
	if !strings.Contains(md, "Reentrancy on withdraw function") {
		t.Errorf("expected confirmed title in markdown, got: %s", md)
	}
	if !strings.Contains(md, "SafeERC20 wrapper reverts on boolean false") {
		t.Errorf("expected counterargument in refuted section, got: %s", md)
	}
	if !strings.Contains(md, "forge test --mt testExploit") {
		t.Errorf("expected test command in validation evidence, got: %s", md)
	}

	jsonBytes, err := rep.GenerateJSONReport()
	if err != nil {
		t.Fatalf("failed to generate JSON report: %v", err)
	}
	if !strings.Contains(string(jsonBytes), "hyp-uuid-1") {
		t.Errorf("expected JSON to contain hypothesis id")
	}
}
