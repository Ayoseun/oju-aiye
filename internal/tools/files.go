package tools

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SafePath confines a requested relative path within the base directory to prevent path traversal attacks.
func SafePath(baseDir, requestedPath string) (string, error) {
	cleanBase := filepath.Clean(baseDir)
	cleanReq := filepath.Clean(requestedPath)

	// Disallow absolute paths that don't start with base
	var target string
	if filepath.IsAbs(cleanReq) {
		target = cleanReq
	} else {
		target = filepath.Join(cleanBase, cleanReq)
	}

	target = filepath.Clean(target)

	// Ensure target is strictly within cleanBase or equals cleanBase
	rel, err := filepath.Rel(cleanBase, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("path traversal violation: %s escapes workspace %s", requestedPath, baseDir)
	}

	return target, nil
}

// ReadSourceRange reads lines [startLine, endLine] (1-indexed, inclusive) from a confined file.
func ReadSourceRange(baseDir, relativePath string, startLine, endLine int) (string, error) {
	if startLine < 1 {
		startLine = 1
	}
	if endLine < startLine {
		return "", fmt.Errorf("invalid line range: startLine %d > endLine %d", startLine, endLine)
	}

	fullPath, err := SafePath(baseDir, relativePath)
	if err != nil {
		return "", err
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	currentLine := 1

	for scanner.Scan() {
		if currentLine >= startLine && currentLine <= endLine {
			lines = append(lines, fmt.Sprintf("%4d | %s", currentLine, scanner.Text()))
		}
		if currentLine > endLine {
			break
		}
		currentLine++
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading file %s: %w", relativePath, err)
	}

	return strings.Join(lines, "\n"), nil
}
