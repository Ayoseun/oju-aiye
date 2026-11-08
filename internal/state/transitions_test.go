package state

import (
	"testing"

	"github.com/google/uuid"
	"vuln-research/internal/domain"
)

func TestValidateJobTransition(t *testing.T) {
	tests := []struct {
		name    string
		from    domain.JobStatus
		to      domain.JobStatus
		wantErr bool
	}{
		{"queued to preparing", domain.JobStatusQueued, domain.JobStatusPreparingTarget, false},
		{"preparing to inventorying", domain.JobStatusPreparingTarget, domain.JobStatusInventorying, false},
		{"inventorying to discovering", domain.JobStatusInventorying, domain.JobStatusDiscovering, false},
		{"discovering to analyzing", domain.JobStatusDiscovering, domain.JobStatusAnalyzing, false},
		{"analyzing to reviewing", domain.JobStatusAnalyzing, domain.JobStatusReviewing, false},
		{"reviewing to ready_for_validation", domain.JobStatusReviewing, domain.JobStatusReadyForValidation, false},
		{"reviewing to needs_more_evidence", domain.JobStatusReviewing, domain.JobStatusNeedsMoreEvidence, false},
		{"needs_more_evidence to analyzing", domain.JobStatusNeedsMoreEvidence, domain.JobStatusAnalyzing, false},
		{"ready_for_validation to validating", domain.JobStatusReadyForValidation, domain.JobStatusValidating, false},
		{"validating to confirmed", domain.JobStatusValidating, domain.JobStatusConfirmed, false},
		{"validating to refuted", domain.JobStatusValidating, domain.JobStatusRefuted, false},
		{"validating to inconclusive", domain.JobStatusValidating, domain.JobStatusInconclusive, false},
		{"validating to needs_more_evidence", domain.JobStatusValidating, domain.JobStatusNeedsMoreEvidence, false},
		// A job that finds nothing, or cannot resolve its hypotheses, must be able to end inconclusive
		{"discovering to inconclusive (scout found nothing)", domain.JobStatusDiscovering, domain.JobStatusInconclusive, false},
		{"reviewing to inconclusive (nothing resolvable)", domain.JobStatusReviewing, domain.JobStatusInconclusive, false},
		{"reviewing to refuted (all rejected)", domain.JobStatusReviewing, domain.JobStatusRefuted, false},
		// ...but never straight to a positive result without validation
		{"discovering to confirmed (illegal)", domain.JobStatusDiscovering, domain.JobStatusConfirmed, true},
		{"reviewing to confirmed (illegal, must validate first)", domain.JobStatusReviewing, domain.JobStatusConfirmed, true},
		{"analyzing to refuted (illegal, must be reviewed first)", domain.JobStatusAnalyzing, domain.JobStatusRefuted, true},
		// Cancellation & failure
		{"queued to cancelled", domain.JobStatusQueued, domain.JobStatusCancelled, false},
		{"analyzing to failed", domain.JobStatusAnalyzing, domain.JobStatusFailed, false},
		// Illegal transitions
		{"queued directly to confirmed (illegal)", domain.JobStatusQueued, domain.JobStatusConfirmed, true},
		{"confirmed to analyzing (illegal terminal escape)", domain.JobStatusConfirmed, domain.JobStatusAnalyzing, true},
		{"refuted to validating (illegal terminal escape)", domain.JobStatusRefuted, domain.JobStatusValidating, true},
		{"failed to queued (illegal terminal escape)", domain.JobStatusFailed, domain.JobStatusQueued, true},
		// Idempotent
		{"same state is no-op", domain.JobStatusAnalyzing, domain.JobStatusAnalyzing, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJobTransition(tt.from, tt.to)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJobTransition(%s -> %s) error = %v, wantErr = %v", tt.from, tt.to, err, tt.wantErr)
			}
		})
	}
}

func TestRecordTransitionAudit(t *testing.T) {
	jobID := uuid.New()
	rec, err := RecordTransition(jobID, "coordinator", domain.JobStatusQueued, domain.JobStatusPreparingTarget, "target uploaded")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.JobID != jobID || rec.FromState != domain.JobStatusQueued || rec.ToState != domain.JobStatusPreparingTarget {
		t.Errorf("unexpected record content: %+v", rec)
	}

	// Illegal transition audit fails
	_, err = RecordTransition(jobID, "coordinator", domain.JobStatusConfirmed, domain.JobStatusDiscovering, "attempt replay")
	if err == nil {
		t.Fatalf("expected error on illegal transition audit, got nil")
	}
}
