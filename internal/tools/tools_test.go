package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafePath(t *testing.T) {
	tempDir := t.TempDir()

	validFile := filepath.Join(tempDir, "safe.go")
	_ = os.WriteFile(validFile, []byte("package main"), 0644)

	// Valid path
	resolved, err := SafePath(tempDir, "safe.go")
	if err != nil || resolved != validFile {
		t.Fatalf("expected safe resolution, got: %s (err: %v)", resolved, err)
	}

	// Path traversal attempts
	traversalPaths := []string{
		"../outside.go",
		"../../etc/passwd",
		"sub/../../secret",
	}

	for _, p := range traversalPaths {
		_, err := SafePath(tempDir, p)
		if err == nil {
			t.Errorf("expected path traversal violation for %s, got nil", p)
		}
	}
}

func TestReadSourceRange(t *testing.T) {
	tempDir := t.TempDir()
	sourcePath := filepath.Join(tempDir, "test.go")

	content := "line1\nline2\nline3\nline4\nline5\n"
	_ = os.WriteFile(sourcePath, []byte(content), 0644)

	res, err := ReadSourceRange(tempDir, "test.go", 2, 4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(res, "line2") || !strings.Contains(res, "line4") {
		t.Errorf("expected line2 and line4, got: %s", res)
	}
	if strings.Contains(res, "line1") || strings.Contains(res, "line5") {
		t.Errorf("expected line1 and line5 excluded, got: %s", res)
	}
}

func TestInventoryRepository(t *testing.T) {
	tempDir := t.TempDir()

	_ = os.MkdirAll(filepath.Join(tempDir, "src"), 0755)
	_ = os.MkdirAll(filepath.Join(tempDir, ".git"), 0755)
	_ = os.WriteFile(filepath.Join(tempDir, "src", "token.sol"), []byte("contract Token {}"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "foundry.toml"), []byte("[profile.default]"), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644)

	inv, err := InventoryRepository(tempDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inv.ProjectKind != "Solidity (Foundry)" {
		t.Errorf("expected Foundry ecosystem, got: %s", inv.ProjectKind)
	}
	if inv.Languages["Solidity"].FileCount != 1 {
		t.Errorf("expected 1 Solidity file, got: %d", inv.Languages["Solidity"].FileCount)
	}
	// Verify .git is excluded
	if _, exists := inv.Languages["Git"]; exists {
		t.Errorf(".git should have been excluded from inventory")
	}
}

func TestStoreArtifact(t *testing.T) {
	tempDir := t.TempDir()
	content := []byte("execution log stdout")

	rec, err := StoreArtifact(tempDir, "stdout.log", content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.SizeBytes != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), rec.SizeBytes)
	}
	if rec.SHA256 == "" {
		t.Errorf("expected non-empty SHA256")
	}
}
