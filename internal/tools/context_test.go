package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vuln-research/internal/scope"
)

// writeTree creates a small repository on disk for the context tests.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestScopedFilesAppliesIncludeAndExclude(t *testing.T) {
	root := writeTree(t, map[string]string{
		"packages/perps/src/Vault.sol":             "contract Vault {}",
		"packages/perps/src/VaultLens.sol":         "contract VaultLens {}",
		"packages/perps/test/Vault.t.sol":          "contract VaultTest {}",
		"packages/shared/src/Shared.sol":           "contract Shared {}",
		"lib/forge-std/src/Test.sol":               "contract Test {}",
		"packages/perps/out/Vault.json":            "{}",
		"packages/perps/cache/artifact.json":       "{}",
		"packages/perps/node_modules/dep/index.js": "module.exports={}",
	})

	sc := &scope.Scope{
		Include: []string{"packages/perps/src"},
		Exclude: []string{"packages/perps/src/VaultLens.sol"},
	}

	files, err := ScopedFiles(root, sc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"packages/perps/src/Vault.sol"}
	if len(files) != len(want) {
		t.Fatalf("expected %v, got %v", want, files)
	}
	for i := range want {
		if files[i] != want[i] {
			t.Errorf("expected %s, got %s", want[i], files[i])
		}
	}
}

func TestScopedFilesWithoutScopeReturnsEverythingInSource(t *testing.T) {
	root := writeTree(t, map[string]string{
		"src/A.sol":   "contract A {}",
		"lib/x/B.sol": "contract B {}",
	})

	files, err := ScopedFiles(root, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// lib/ is a dependency directory: it is not source the program wants audited.
	if len(files) != 1 || files[0] != "src/A.sol" {
		t.Errorf("expected only src/A.sol, got %v", files)
	}
}

func TestBuildChunksCoversEveryFile(t *testing.T) {
	files := map[string]string{
		"src/A.sol": strings.Repeat("a", 500),
		"src/B.sol": strings.Repeat("b", 500),
		"src/C.sol": strings.Repeat("c", 500),
	}
	root := writeTree(t, files)

	chunks, err := BuildChunks(root, []string{"src/A.sol", "src/B.sol", "src/C.sol"}, 700, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("expected the files to be split over several chunks, got %d", len(chunks))
	}

	seen := map[string]bool{}
	for _, ch := range chunks {
		if ch.Index < 1 || ch.Index > ch.Total {
			t.Errorf("chunk index %d out of range (total %d)", ch.Index, ch.Total)
		}
		if len(ch.Text) > 700+600 {
			t.Errorf("chunk is over the budget: %d bytes", len(ch.Text))
		}
		for _, f := range ch.Files {
			seen[f] = true
		}
	}
	if len(seen) != 3 {
		t.Errorf("expected every file in exactly one chunk, got %v", seen)
	}
}

func TestBuildChunksSplitsOneHugeFileRatherThanDroppingIt(t *testing.T) {
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, "line "+strings.Repeat("x", 40))
	}
	root := writeTree(t, map[string]string{"src/Huge.sol": strings.Join(lines, "\n")})

	chunks, err := BuildChunks(root, []string{"src/Huge.sol"}, 1000, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Every part of the file must appear somewhere: the biggest contracts are the
	// ones worth reading, so they must not be cut off.
	seenParts := 0
	for _, ch := range chunks {
		// A batch must never hold two pieces of the same file: a model reads that as
		// a duplication and deliberates instead of answering.
		count := 0
		for _, f := range ch.Files {
			if f == "src/Huge.sol" {
				count++
			}
		}
		if count > 1 {
			t.Errorf("batch %d holds %d pieces of the same file", ch.Index, count)
		}
		seenParts += count
	}
	if seenParts < 5 {
		t.Errorf("expected the file to be split into several parts, got %d", seenParts)
	}

	all := ""
	for _, ch := range chunks {
		all += ch.Text
	}
	if !strings.Contains(all, "part 1") || !strings.Contains(all, "part 2") {
		t.Error("expected the parts to be labelled")
	}
}

func TestResolveScopedPath(t *testing.T) {
	files := []string{"packages/perps/src/libraries/FooLib.sol", "packages/perps/src/Vault.sol"}

	cases := map[string]string{
		"packages/perps/src/Vault.sol":            "packages/perps/src/Vault.sol",
		"packages/perps/src/libraries/FooLib.sol": "packages/perps/src/libraries/FooLib.sol",
		"libraries/FooLib.sol":                    "packages/perps/src/libraries/FooLib.sol",
		"FooLib.sol":                              "packages/perps/src/libraries/FooLib.sol",
		"./packages/perps/src/Vault.sol":          "packages/perps/src/Vault.sol",
		"does/not/exist.sol":                      "",
	}
	for ref, want := range cases {
		if got := ResolveScopedPath(files, ref); got != want {
			t.Errorf("ResolveScopedPath(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestFileContextCentresOnTheCitedLines(t *testing.T) {
	var lines []string
	for i := 1; i <= 200; i++ {
		lines = append(lines, "line "+string(rune('A'+i%26)))
	}
	root := writeTree(t, map[string]string{"src/Big.sol": strings.Join(lines, "\n")})

	ctx := FileContext(root, "src/Big.sol", 100, 110, "", 4000)
	if !strings.Contains(ctx, "100 |") {
		t.Errorf("expected the cited range in the excerpt, got:\n%s", ctx[:200])
	}
	if strings.Contains(ctx, "  1 |") {
		t.Error("expected the excerpt to skip the far-away beginning of the file")
	}
}

func TestFileContextFallsBackToTheFileHeadWhenTheRangeIsUnusable(t *testing.T) {
	root := writeTree(t, map[string]string{"src/Big.sol": strings.Repeat("y", 5000)})

	ctx := FileContext(root, "src/Big.sol", 0, 0, "", 1000)
	if ctx == "" {
		t.Fatal("expected some context")
	}
	if !strings.Contains(ctx, "truncated") {
		t.Error("expected the excerpt to be marked as truncated")
	}
}

// The symbol is the reliable anchor: a model that cannot count lines cites a line that
// does not hold the function it means.
func TestFileContextForSymbolFindsTheDefinition(t *testing.T) {
	source := `package fileserve

import "os"

// Read returns the contents of name.
func Read(root, name string) ([]byte, error) {
	return os.ReadFile(name)
}

func Unrelated(a int) int {
	return a
}
`
	root := writeTree(t, map[string]string{"src/token.sol": source})

	// The cited line is wrong on purpose: the symbol is right.
	ctx := FileContextForSymbol(root, "src/token.sol", 2, 3, "Read", 4000)
	if !strings.Contains(ctx, "func Read(root, name string)") {
		t.Errorf("expected the definition of Read in the excerpt, got:\n%s", ctx)
	}
	if strings.Contains(ctx, "func Unrelated") {
		t.Error("expected the excerpt to stop at the end of the function")
	}
}

func TestFileContextForSymbolFallsBackToTheCitedRange(t *testing.T) {
	root := writeTree(t, map[string]string{"src/token.sol": "line one\nline two\nline three\n"})

	ctx := FileContextForSymbol(root, "src/token.sol", 2, 3, "NoSuchSymbol", 4000)
	if !strings.Contains(ctx, "line two") {
		t.Errorf("expected the cited range in the excerpt, got:\n%s", ctx)
	}
}
