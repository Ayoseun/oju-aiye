package state

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/domain"
)

// TransitionRecord tracks the audit trail of any state transition.
type TransitionRecord struct {
	ID        uuid.UUID        `json:"id"`
	JobID     uuid.UUID        `json:"job_id"`
	Actor     string           `json:"actor"`
	FromState domain.JobStatus `json:"from_state"`
	ToState   domain.JobStatus `json:"to_state"`
	Reason    string           `json:"reason"`
	Timestamp time.Time        `json:"timestamp"`
}

// legalJobTransitions maps each JobStatus to its allowed target statuses.
var legalJobTransitions = map[domain.JobStatus]map[domain.JobStatus]bool{
	domain.JobStatusQueued: {
		domain.JobStatusPreparingTarget: true,
		domain.JobStatusCancelled:       true,
		domain.JobStatusFailed:          true,
	},
	domain.JobStatusPreparingTarget: {
		domain.JobStatusInventorying: true,
		domain.JobStatusCancelled:    true,
		domain.JobStatusFailed:       true,
	},
	domain.JobStatusInventorying: {
		domain.JobStatusDiscovering: true,
		domain.JobStatusCancelled:   true,
		domain.JobStatusFailed:      true,
	},
	domain.JobStatusDiscovering: {
		domain.JobStatusAnalyzing:    true,
		domain.JobStatusInconclusive: true, // the Scout found nothing to analyze
		domain.JobStatusCancelled:    true,
		domain.JobStatusFailed:       true,
	},
	domain.JobStatusAnalyzing: {
		domain.JobStatusReviewing: true,
		domain.JobStatusCancelled: true,
		domain.JobStatusFailed:    true,
	},
	domain.JobStatusReviewing: {
		domain.JobStatusInconclusive:       true, // nothing could be validated or resolved
		domain.JobStatusNeedsMoreEvidence:  true,
		domain.JobStatusReadyForValidation: true,
		domain.JobStatusRefuted:            true,
		domain.JobStatusCancelled:          true,
		domain.JobStatusFailed:             true,
	},
	domain.JobStatusNeedsMoreEvidence: {
		domain.JobStatusAnalyzing: true,
		domain.JobStatusCancelled: true,
		domain.JobStatusFailed:    true,
	},
	domain.JobStatusReadyForValidation: {
		domain.JobStatusValidating: true,
		domain.JobStatusCancelled:  true,
		domain.JobStatusFailed:     true,
	},
	domain.JobStatusValidating: {
		domain.JobStatusConfirmed:         true,
		domain.JobStatusRefuted:           true,
		domain.JobStatusInconclusive:      true,
		domain.JobStatusNeedsMoreEvidence: true,
		domain.JobStatusCancelled:         true,
		domain.JobStatusFailed:            true,
	},
	// Terminal states have no outbound transitions.
	domain.JobStatusConfirmed:    {},
	domain.JobStatusRefuted:      {},
	domain.JobStatusInconclusive: {},
	domain.JobStatusFailed:       {},
	domain.JobStatusCancelled:    {},
}

// ValidateJobTransition verifies if moving from currentState to nextState is permitted.
func ValidateJobTransition(current domain.JobStatus, next domain.JobStatus) error {
	if current == next {
		return nil
	}
	allowed, exists := legalJobTransitions[current]
	if !exists {
		return fmt.Errorf("unknown initial job status: %s", current)
	}
	if !allowed[next] {
		return fmt.Errorf("illegal job state transition from %s to %s", current, next)
	}
	return nil
}

// IsTerminal returns true if the job status cannot transition further.
func IsTerminal(status domain.JobStatus) bool {
	switch status {
	case domain.JobStatusConfirmed, domain.JobStatusRefuted, domain.JobStatusInconclusive, domain.JobStatusFailed, domain.JobStatusCancelled:
		return true
	default:
		return false
	}
}

// RecordTransition creates an immutable audit entry for a legal transition.
func RecordTransition(jobID uuid.UUID, actor string, from domain.JobStatus, to domain.JobStatus, reason string) (*TransitionRecord, error) {
	if err := ValidateJobTransition(from, to); err != nil {
		return nil, err
	}
	return &TransitionRecord{
		ID:        uuid.New(),
		JobID:     jobID,
		Actor:     actor,
		FromState: from,
		ToState:   to,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
	}, nil
}
