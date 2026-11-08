package coordinator_test

import (
	"context"
	"strings"
	"testing"

	"vuln-research/internal/domain"
)

const (
	vulnerable = "testdata/targets/traversal-vulnerable"
	patched    = "testdata/targets/traversal-patched"
)

// When the Reviewer asks for more evidence, the Investigator must get the feedback and revise
// the SAME hypothesis; once the Reviewer is satisfied, validation runs as usual.
func TestReviewerEvidenceRequestTriggersRevision(t *testing.T) {
	r := runPipeline(t, "testdata/scenarios/traversal-evidence-once", vulnerable)

	if r.job.Status != domain.JobStatusConfirmed {
		t.Fatalf("job = %s (%s), want confirmed", r.job.Status, r.job.ErrorSummary)
	}
	if len(r.hyps) != 1 {
		t.Fatalf("want one finding that evolves across rounds, got %d hypotheses", len(r.hyps))
	}
	h := r.hyps[0]
	if !strings.Contains(h.Title, "revised after review") {
		t.Fatalf("hypothesis was not updated with the revision, title = %q", h.Title)
	}
	if h.Status != domain.HypothesisConfirmed {
		t.Fatalf("hypothesis = %s, want confirmed", h.Status)
	}
	revs := r.reviews[h.HypothesisID]
	if len(revs) != 2 || revs[0].Decision != domain.ReviewRequestMoreEvidence || revs[1].Decision != domain.ReviewAcceptForValidation {
		t.Fatalf("want [request_more_evidence, accept_for_validation], got %+v", revs)
	}
	if got := []int{r.replay.Count("scout"), r.replay.Count("investigator"), r.replay.Count("reviewer")}; got[0] != 1 || got[1] != 2 || got[2] != 2 {
		t.Fatalf("calls scout/investigator/reviewer = %v, want [1 2 2]", got)
	}
	trs, _ := r.store.ListTransitions(context.Background(), r.job.ID)
	var path []string
	for _, tr := range trs {
		path = append(path, string(tr.ToState))
	}
	want := "preparing_target inventorying discovering analyzing reviewing needs_more_evidence analyzing reviewing ready_for_validation validating confirmed"
	if strings.Join(path, " ") != want {
		t.Fatalf("job path =\n  %s\nwant\n  %s", strings.Join(path, " "), want)
	}
}

// A Reviewer that is never satisfied must end in `inconclusive` after a bounded number of
// rounds. It must NOT be reported as refuted: nothing was ever tested.
func TestUnresolvedEvidenceIsInconclusiveNotRefuted(t *testing.T) {
	r := runPipeline(t, "testdata/scenarios/traversal-never-converges", vulnerable)

	if r.job.Status != domain.JobStatusInconclusive {
		t.Fatalf("job = %s (%s), want inconclusive", r.job.Status, r.job.ErrorSummary)
	}
	if len(r.hyps) != 1 || r.hyps[0].Status != domain.HypothesisNeedsMoreEvidence {
		t.Fatalf("want one hypothesis left in needs_more_evidence, got %+v", r.hyps)
	}
	if n := len(r.runs[r.hyps[0].HypothesisID]); n != 0 {
		t.Fatalf("nothing should have been validated, got %d runs", n)
	}
	// max_iterations_per_hypothesis is 4: one investigation + three revisions, each reviewed.
	if inv, rev := r.replay.Count("investigator"), r.replay.Count("reviewer"); inv != 4 || rev != 4 {
		t.Fatalf("investigator/reviewer calls = %d/%d, want 4/4 (bounded by max_iterations_per_hypothesis)", inv, rev)
	}
	if !strings.Contains(r.job.ErrorSummary+lastReason(t, r), "evidence") {
		t.Logf("note: final reason = %q", lastReason(t, r))
	}
}

// If the Scout finds nothing, the job must reach a terminal state. (It used to stay in
// `reviewing` forever because the final transition was illegal and its error was ignored.)
func TestNoCandidatesReachesTerminalState(t *testing.T) {
	r := runPipeline(t, "testdata/scenarios/traversal-no-candidates", vulnerable)
	if r.job.Status != domain.JobStatusInconclusive {
		t.Fatalf("job = %s, want inconclusive (a job must never be left in a running state)", r.job.Status)
	}
	if len(r.hyps) != 0 {
		t.Fatalf("want no hypotheses, got %d", len(r.hyps))
	}
}

// If every Investigator call fails, nothing was analyzed. The job must say so (failed),
// not report an all-clear.
func TestAgentFailuresAreNeverAnAllClear(t *testing.T) {
	t.Run("investigator fails for every candidate", func(t *testing.T) {
		r := runPipeline(t, "testdata/scenarios/traversal-investigator-garbage", vulnerable)
		if r.job.Status != domain.JobStatusFailed {
			t.Fatalf("job = %s (%s), want failed", r.job.Status, r.job.ErrorSummary)
		}
		if !strings.Contains(strings.ToLower(r.job.ErrorSummary), "investigator") {
			t.Fatalf("error should name the failing agent, got %q", r.job.ErrorSummary)
		}
	})
	t.Run("reviewer fails for every hypothesis", func(t *testing.T) {
		r := runPipeline(t, "testdata/scenarios/traversal-reviewer-garbage", vulnerable)
		if r.job.Status != domain.JobStatusInconclusive {
			t.Fatalf("job = %s (%s), want inconclusive, never refuted", r.job.Status, r.job.ErrorSummary)
		}
		if len(r.hyps) != 1 {
			t.Fatalf("want the unreviewed hypothesis kept visible, got %d", len(r.hyps))
		}
	})
}

// An explicit rejection by the Reviewer is a reasoned conclusion, so the job is refuted, but
// the reason must make clear that nothing was actually run.
func TestReviewerRejectionIsRefutedAndUntested(t *testing.T) {
	r := runPipeline(t, "testdata/scenarios/traversal-rejected", vulnerable)
	if r.job.Status != domain.JobStatusRefuted {
		t.Fatalf("job = %s, want refuted", r.job.Status)
	}
	if n := len(r.runs[r.hyps[0].HypothesisID]); n != 0 {
		t.Fatalf("a rejected hypothesis must not be validated, got %d runs", n)
	}
	if reason := lastReason(t, r); !strings.Contains(strings.ToLower(reason), "not tested") && !strings.Contains(strings.ToLower(reason), "none were tested") {
		t.Fatalf("reason should say nothing was tested, got %q", reason)
	}
}

// Sanity: a patched target with the normal scenario is still an honest "not reproduced".
func TestPatchedStillRefutedAfterValidation(t *testing.T) {
	r := runPipeline(t, "testdata/scenarios/traversal", patched)
	if r.job.Status != domain.JobStatusRefuted {
		t.Fatalf("job = %s, want refuted", r.job.Status)
	}
}

func lastReason(t *testing.T, r pipelineResult) string {
	t.Helper()
	trs, _ := r.store.ListTransitions(context.Background(), r.job.ID)
	if len(trs) == 0 {
		return ""
	}
	return trs[len(trs)-1].Reason
}
