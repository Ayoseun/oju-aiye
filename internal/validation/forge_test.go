package validation

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"vuln-research/internal/config"
)

// A Foundry proof of concept has to compile and run inside the sandbox. The compiler
// lives under the user's home directory, which the sandbox scrubs, so the runner links it
// in; without that the sandbox cannot even install one, and it has no network.
//
// The test is skipped when the Plether checkout is not present.
func TestForgeProofOfConceptRunsInTheSandbox(t *testing.T) {
	repo := "/Users/ayoseun/Documents/GitHub/Audit/vuln-research/targets/audit-comp-plether"
	if _, err := os.Stat(repo); err != nil {
		t.Skip("plether checkout not present")
	}

	runner := NewRunner(config.ValidationConfig{
		Enabled:           true,
		NetworkAccess:     "disabled",
		MaxRuntimeSeconds: 900,
	}, t.TempDir())

	plan := "cd packages/perps\n" +
		"cat > PoC.s.sol <<'POCEOF'\n" +
		"// SPDX-License-Identifier: MIT\n" +
		"pragma solidity ^0.8.35;\n" +
		"import \"forge-std/Script.sol\";\n" +
		"contract PoC is Script {\n" +
		"    function run() external pure {\n" +
		"        require(false, \"forge script: sandbox compiler works\");\n" +
		"    }\n" +
		"}\n" +
		"POCEOF\n" +
		"forge script PoC.s.sol --sig \"run()\"\n"

	res, err := runner.Execute(context.Background(), ExecutionRequest{
		HypothesisID:     uuid.New(),
		SourceDir:        repo,
		Command:          "sh",
		Args:             []string{"-c", plan},
		Timeout:          15 * time.Minute,
		FailureSignature: "forge script: sandbox compiler works",
	})
	if err != nil {
		t.Fatalf("execution error: %v", err)
	}
	t.Logf("outcome=%s exit=%d", res.Outcome, res.ExitCode)
	t.Logf("notes: %s", res.Notes)
	if res.Outcome != "reproduced" {
		t.Errorf("expected the script to run and revert with the signature")
	}
}
