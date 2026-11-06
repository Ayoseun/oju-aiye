package tools

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LanguageStats holds file and line counts for a programming language.
type LanguageStats struct {
	Language  string   `json:"language"`
	FileCount int      `json:"file_count"`
	Files     []string `json:"files"`
}

// RepositoryInventory summarizes the source files detected in the repository.
type RepositoryInventory struct {
	TotalFiles  int                      `json:"total_files"`
	Languages   map[string]LanguageStats `json:"languages"`
	ProjectKind string                   `json:"project_kind"`
}

var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"target":       true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	".idea":        true,
	".vscode":      true,
}

var extToLang = map[string]string{
	".go":   "Go",
	".sol":  "Solidity",
	".rs":   "Rust",
	".py":   "Python",
	".js":   "JavaScript",
	".ts":   "TypeScript",
	".c":    "C",
	".cpp":  "C++",
	".h":    "C/C++ Header",
	".yaml": "YAML",
	".yml":  "YAML",
	".json": "JSON",
	".md":   "Markdown",
}

// InventoryRepository scans the repository directory, excluding noise directories, and categorizes files.
func InventoryRepository(repoPath string) (*RepositoryInventory, error) {
	inv := &RepositoryInventory{
		Languages: make(map[string]LanguageStats),
	}

	err := filepath.WalkDir(repoPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, err := filepath.Rel(repoPath, path)
		if err != nil {
			return err
		}

		ext := strings.ToLower(filepath.Ext(path))
		lang, recognized := extToLang[ext]
		if !recognized {
			lang = "Other"
		}

		stats := inv.Languages[lang]
		stats.Language = lang
		stats.FileCount++
		if len(stats.Files) < 50 { // Keep list bounded
			stats.Files = append(stats.Files, relPath)
		}
		inv.Languages[lang] = stats
		inv.TotalFiles++

		// Detect project ecosystem
		switch d.Name() {
		case "foundry.toml":
			inv.ProjectKind = "Solidity (Foundry)"
		case "hardhat.config.js", "hardhat.config.ts":
			if inv.ProjectKind == "" {
				inv.ProjectKind = "Solidity (Hardhat)"
			}
		case "Cargo.toml":
			if inv.ProjectKind == "" {
				inv.ProjectKind = "Rust (Cargo)"
			}
		case "go.mod":
			if inv.ProjectKind == "" {
				inv.ProjectKind = "Go Module"
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to inventory repository: %w", err)
	}

	return inv, nil
}

// BuildContextSummary creates a concise representation of the repository for Scout.
func (inv *RepositoryInventory) BuildContextSummary(repoPath string, maxBytes int) (string, error) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Project Ecosystem: %s\nTotal Files: %d\n\nFile Distribution:\n", inv.ProjectKind, inv.TotalFiles))

	for lang, stats := range inv.Languages {
		sb.WriteString(fmt.Sprintf("- %s: %d files\n", lang, stats.FileCount))
	}
	sb.WriteString("\nKey Source Files:\n")

	// Read top source files up to maxBytes
	bytesWritten := sb.Len()

	for _, stats := range inv.Languages {
		if stats.Language == "Other" || stats.Language == "Markdown" || stats.Language == "JSON" {
			continue
		}
		for _, file := range stats.Files {
			if bytesWritten >= maxBytes {
				sb.WriteString("\n[Context truncated due to size limit...]\n")
				return sb.String(), nil
			}

			fullPath := filepath.Join(repoPath, file)
			content, err := os.ReadFile(fullPath)
			if err != nil {
				continue
			}

			header := fmt.Sprintf("\n--- File: %s ---\n", file)
			sb.WriteString(header)
			bytesWritten += len(header)

			if len(content) > 4000 {
				snippet := string(content[:4000]) + "\n...[truncated]..."
				sb.WriteString(snippet)
				bytesWritten += len(snippet)
			} else {
				sb.Write(content)
				bytesWritten += len(content)
			}
		}
	}

	return sb.String(), nil
}
