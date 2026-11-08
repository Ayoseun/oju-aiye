package reports

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vuln-research/internal/domain"
)

// ReportSummary aggregates finding counts by verification status.
type ReportSummary struct {
	TotalCandidates int `json:"total_candidates"`
	TotalHypotheses int `json:"total_hypotheses"`
	Confirmed       int `json:"confirmed"`
	Refuted         int `json:"refuted"`
	Inconclusive    int `json:"inconclusive"`
}

// FindingDetail provides full provenance and evidence trail for an individual hypothesis.
type FindingDetail struct {
	HypothesisID      string                     `json:"hypothesis_id"`
	Title             string                     `json:"title"`
	Status            domain.HypothesisStatus    `json:"status"`
	Weakness          domain.Weakness            `json:"weakness"`
	AffectedLocations []domain.AffectedLocation  `json:"affected_locations"`
	SecurityInvariant string                     `json:"security_invariant"`
	Impact            string                     `json:"impact"`
	ExpectedFailure   string                     `json:"expected_failure"`
	FailureSignature  string                     `json:"failure_signature"`
	ValidationPlan    []string                   `json:"validation_plan"`
	Counterarguments  []string                   `json:"counterarguments"`
	Reviews           []*domain.ReviewResult     `json:"reviews"`
	Validations       []*domain.ValidationResult `json:"validations"`
}

// ResearchReport represents the structured report object.
type ResearchReport struct {
	JobID                string           `json:"job_id"`
	RepositoryRef        string           `json:"repository_ref"`
	RepositoryRevision   string           `json:"repository_revision"`
	JobStatus            domain.JobStatus `json:"job_status"`
	GeneratedAt          time.Time        `json:"generated_at"`
	Summary              ReportSummary    `json:"summary"`
	ConfirmedFindings    []FindingDetail  `json:"confirmed_findings"`
	RefutedFindings      []FindingDetail  `json:"refuted_findings"`
	InconclusiveFindings []FindingDetail  `json:"inconclusive_findings"`
}

// GenerateMarkdownReport formats the research findings as an auditable Markdown document.
func (r *ResearchReport) GenerateMarkdownReport() string {
	var sb strings.Builder

	sb.WriteString("# Automated Vulnerability Research Report\n\n")
	sb.WriteString(fmt.Sprintf("**Job ID:** `%s`  \n", r.JobID))
	sb.WriteString(fmt.Sprintf("**Repository:** `%s` (`%s`)  \n", r.RepositoryRef, r.RepositoryRevision))
	sb.WriteString(fmt.Sprintf("**Status:** `%s`  \n", r.JobStatus))
	sb.WriteString(fmt.Sprintf("**Generated At:** %s  \n\n", r.GeneratedAt.Format(time.RFC3339)))

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("| Metric | Count |\n| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| Total Candidates Discovered | %d |\n", r.Summary.TotalCandidates))
	sb.WriteString(fmt.Sprintf("| Hypotheses Formulated | %d |\n", r.Summary.TotalHypotheses))
	sb.WriteString(fmt.Sprintf("| **Confirmed Vulnerabilities** | **%d** |\n", r.Summary.Confirmed))
	sb.WriteString(fmt.Sprintf("| Refuted Hypotheses | %d |\n", r.Summary.Refuted))
	sb.WriteString(fmt.Sprintf("| Inconclusive Leads | %d |\n\n", r.Summary.Inconclusive))

	// Confirmed Findings
	sb.WriteString("## Confirmed Vulnerabilities\n\n")
	if len(r.ConfirmedFindings) == 0 {
		sb.WriteString("No vulnerabilities were reproducibly confirmed in this run.\n\n")
	} else {
		for i, f := range r.ConfirmedFindings {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
			sb.WriteString(fmt.Sprintf("- **Weakness:** %s (%s)\n", f.Weakness.CWE, f.Weakness.Category))
			sb.WriteString(fmt.Sprintf("- **Status:** `%s`\n", f.Status))
			sb.WriteString(fmt.Sprintf("- **Impact:** %s\n", f.Impact))
			sb.WriteString(fmt.Sprintf("- **Security Invariant:** %s\n\n", f.SecurityInvariant))

			sb.WriteString("#### Affected Code Locations:\n")
			for _, loc := range f.AffectedLocations {
				sb.WriteString(fmt.Sprintf("- `%s:%d-%d` (symbol: `%s`)\n", loc.Path, loc.LineStart, loc.LineEnd, loc.Symbol))
			}
			sb.WriteString("\n")

			if len(f.Validations) > 0 {
				sb.WriteString("#### Validation Evidence:\n")
				for _, v := range f.Validations {
					sb.WriteString(fmt.Sprintf("- **Outcome:** `%s` (Exit Code: %d)\n", v.Outcome, v.ExitCode))
					sb.WriteString(fmt.Sprintf("- **Command:** `%s`\n", v.TestCommandID))
					sb.WriteString(fmt.Sprintf("- **Notes:** %s\n", v.Notes))
					if v.StdoutArtifact != "" {
						sb.WriteString(fmt.Sprintf("- **Stdout Artifact:** `%s`\n", v.StdoutArtifact))
					}
					if v.StderrArtifact != "" {
						sb.WriteString(fmt.Sprintf("- **Stderr Artifact:** `%s`\n", v.StderrArtifact))
					}
				}
				sb.WriteString("\n")
			}
		}
	}

	// Refuted Findings
	if len(r.RefutedFindings) > 0 {
		sb.WriteString("## Refuted Hypotheses (Disproven or Mitigated)\n\n")
		for i, f := range r.RefutedFindings {
			sb.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, f.Title))
			sb.WriteString(fmt.Sprintf("- **Weakness:** %s\n", f.Weakness.CWE))
			if len(f.Counterarguments) > 0 {
				sb.WriteString("- **Mitigations & Counterarguments:**\n")
				for _, ca := range f.Counterarguments {
					sb.WriteString(fmt.Sprintf("  - %s\n", ca))
				}
			}
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// GenerateJSONReport serializes the structured report.
func (r *ResearchReport) GenerateJSONReport() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
