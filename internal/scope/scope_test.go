package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadReadsIncludeExcludeAndKnownIssuesFile(t *testing.T) {
	dir := t.TempDir()
	known := filepath.Join(dir, "known.md")
	if err := os.WriteFile(known, []byte("- MED-7: stale price feed"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "scope.yaml")
	body := "include:\n  - packages/perps/src\nexclude:\n  - packages/perps/src/Lens.sol\nknown_issues_file: known.md\n"
	if err := os.WriteFile(manifest, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	sc, err := Load(manifest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sc.Include) != 1 || sc.Include[0] != "packages/perps/src" {
		t.Errorf("unexpected include list: %v", sc.Include)
	}
	if !sc.InScope("packages/perps/src/Vault.sol") {
		t.Error("expected Vault.sol to be in scope")
	}
	if sc.InScope("packages/perps/src/Lens.sol") {
		t.Error("expected Lens.sol to be excluded")
	}
	if sc.InScope("packages/shared/src/Shared.sol") {
		t.Error("expected a file outside the include list to be out of scope")
	}
	if sc.KnownIssues != "- MED-7: stale price feed" {
		t.Errorf("unexpected known issues: %q", sc.KnownIssues)
	}
}

func TestInScopeWithNoScopeAllowsEverything(t *testing.T) {
	var sc *Scope
	if !sc.InScope("anything/at/all.sol") {
		t.Error("a nil scope must not restrict anything")
	}
	if !sc.IsEmpty() {
		t.Error("a nil scope must be empty")
	}
}

func TestExcludedDirectoryPrefix(t *testing.T) {
	sc := &Scope{Exclude: []string{"packages/perps/out"}}
	if !sc.Excluded("packages/perps/out/Vault.json") {
		t.Error("expected a file under an excluded directory to be excluded")
	}
	if sc.Excluded("packages/perps/outer/Vault.json") {
		t.Error("a directory with a similar name must not be excluded")
	}
}

// A directory inside an included path is in scope, and so is the directory that holds it.
// Getting this wrong prunes the whole subtree and silently shrinks the audit surface.
func TestIncludesSubtreeCoversAncestorsAndDescendants(t *testing.T) {
	sc := &Scope{Include: []string{"packages/perps/src"}}

	for _, dir := range []string{"packages", "packages/perps", "packages/perps/src", "packages/perps/src/libraries"} {
		if !sc.IncludesSubtree(dir) {
			t.Errorf("expected %q to be walked", dir)
		}
	}
	for _, dir := range []string{"packages/shared", "packages/perps/test", "scripts"} {
		if sc.IncludesSubtree(dir) {
			t.Errorf("expected %q to be pruned", dir)
		}
	}
}
