package tools

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vuln-research/internal/scope"
)

// ScopedFiles returns the repository-relative paths of the files an audit may look at.
// Scope rules are applied, and noise directories (dependencies, build output) are skipped.
func ScopedFiles(root string, sc *scope.Scope) ([]string, error) {
	var files []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if skippedDir(d.Name()) {
				return filepath.SkipDir
			}
			// A directory that is entirely out of scope is not worth walking, but the
			// parent of an included path is not itself included.
			if sc != nil && (!sc.IncludesSubtree(rel) || sc.Excluded(rel)) {
				return filepath.SkipDir
			}
			return nil
		}

		if sc != nil && !sc.InScope(rel) {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}

		files = append(files, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list scoped files: %w", err)
	}

	sort.Strings(files)
	return files, nil
}

// skippedDir reports whether a directory holds dependencies or build output rather than
// source the program wants audited.
func skippedDir(name string) bool {
	switch name {
	case ".git", "node_modules", "target", "vendor", "dist", "build", ".idea", ".vscode", "out", "cache":
		return true
	case "lib":
		// The vendored-dependency convention (Foundry, npm). A project that keeps
		// first-party source in lib/ can list it in the scope manifest instead.
		return true
	}
	return false
}

// Chunk is a batch of source files handed to an agent in one model call.
type Chunk struct {
	// Index is the position of the chunk in the whole target, starting at 1.
	Index int
	// Total is how many chunks the target was split into.
	Total int
	// Files are the repository-relative paths in this chunk.
	Files []string
	// Text is the rendered source of those files.
	Text string
}

// BuildChunks groups scoped files into batches of at most maxBytes characters, so a target
// larger than one model context is still read in full. A single file longer than
// maxFileBytes is truncated (with a marker) rather than dropped.
func BuildChunks(root string, files []string, maxBytes, maxFileBytes int) ([]Chunk, error) {
	if maxBytes <= 0 {
		maxBytes = 60000
	}
	if maxFileBytes <= 0 {
		maxFileBytes = 24000
	}

	var chunks []Chunk
	current := Chunk{}
	currentSize := 0

	flush := func() {
		if len(current.Files) > 0 {
			chunks = append(chunks, current)
			current = Chunk{}
			currentSize = 0
		}
	}

	for _, rel := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		data, err := os.ReadFile(full)
		if err != nil {
			continue // unreadable file: skip it rather than fail the whole audit
		}

		parts := splitIntoParts(string(data), maxFileBytes)
		header := fmt.Sprintf("\n--- File: %s%s (%d bytes) ---\n", rel, parts[0].label, len(data))

		if len(parts) == 1 {
			// A whole file: it goes into the current batch if it fits.
			entry := header + parts[0].text
			if currentSize > 0 && currentSize+len(entry) > maxBytes {
				flush()
			}
			current.Files = append(current.Files, rel)
			current.Text += entry
			currentSize += len(entry)
			continue
		}

		// A file bigger than the per-file budget is split. Each part gets a batch of its
		// own: one contiguous piece of one file is something a model can reason about,
		// while a batch holding three pieces of the same file looks like a duplication
		// and makes it deliberate instead of answer.
		flush()
		for _, part := range parts {
			entry := fmt.Sprintf("\n--- File: %s%s (%d bytes) ---\n", rel, part.label, len(data)) + part.text
			current.Files = append(current.Files, rel)
			current.Text += entry
			currentSize = len(entry)
			flush()
		}
	}
	flush()

	for i := range chunks {
		chunks[i].Index = i + 1
		chunks[i].Total = len(chunks)
	}
	return chunks, nil
}

// filePart is one slice of a file.
type filePart struct {
	text  string
	label string // e.g. " (part 2 of 3, lines 800-1600)"
}

// splitIntoParts cuts a file into slices of at most maxBytes, keeping the line numbers so
// a candidate can still be located in the original file.
func splitIntoParts(content string, maxBytes int) []filePart {
	if maxBytes <= 0 || len(content) <= maxBytes {
		return []filePart{{text: content}}
	}

	lines := strings.Split(content, "\n")
	var parts []filePart
	start := 0
	for start < len(lines) {
		size := 0
		end := start
		for end < len(lines) {
			lineSize := len(lines[end]) + 1
			if end > start && size+lineSize > maxBytes {
				break
			}
			size += lineSize
			end++
		}
		label := ""
		if len(lines) > 1 {
			label = fmt.Sprintf(" (part %d, lines %d-%d of %d)", len(parts)+1, start+1, end, len(lines))
		}
		parts = append(parts, filePart{text: strings.Join(lines[start:end], "\n"), label: label})
		start = end
	}
	return parts
}

// ResolveScopedPath finds the scoped file a model meant to refer to. Models are inconsistent
// about paths: they may give the full repository path, a path relative to the source root, or
// just the file name.
func ResolveScopedPath(files []string, reference string) string {
	ref := filepath.ToSlash(strings.TrimSpace(reference))
	if ref == "" {
		return ""
	}
	ref = strings.TrimPrefix(ref, "./")

	for _, f := range files {
		if f == ref {
			return f
		}
	}
	for _, f := range files {
		if strings.HasSuffix(f, "/"+ref) {
			return f
		}
	}
	base := filepath.Base(ref)
	for _, f := range files {
		if filepath.Base(f) == base {
			return f
		}
	}
	return ""
}

// FileContext returns the source of one file for an agent that has to reason about it. When
// the candidate cites a line range, the range is centred in the excerpt so the agent sees
// the code around it.
func FileContext(root, relPath string, lineStart, lineEnd, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 40000
	}

	full := filepath.Join(root, filepath.FromSlash(relPath))
	data, err := os.ReadFile(full)
	if err != nil {
		return ""
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// A cited range that exists in the file gets priority over a size cap.
	if lineStart >= 1 && lineEnd >= lineStart && lineEnd <= len(lines) {
		window := windowAround(lines, lineStart, lineEnd, maxBytes)
		if window != "" {
			return window
		}
	}

	if len(content) > maxBytes {
		return content[:maxBytes] + "\n...[truncated]...\n"
	}
	return content
}

// windowAround returns the excerpt of lines that contains the cited range, growing the
// window outwards until it fits the budget.
func windowAround(lines []string, lineStart, lineEnd, maxBytes int) string {
	before, after := 0, 0
	for {
		from := lineStart - 1 - before
		to := lineEnd + after
		if from < 0 {
			from = 0
		}
		if to > len(lines) {
			to = len(lines)
		}

		var sb strings.Builder
		if from > 0 {
			fmt.Fprintf(&sb, "...[%d lines omitted]...\n", from)
		}
		for i := from; i < to; i++ {
			fmt.Fprintf(&sb, "%4d | %s\n", i+1, lines[i])
		}
		if to < len(lines) {
			fmt.Fprintf(&sb, "...[%d lines omitted]...\n", len(lines)-to)
		}

		if sb.Len() <= maxBytes {
			return sb.String()
		}
		if before == 0 && after == 0 {
			// The cited range alone is too big: fall back to a head slice.
			return ""
		}
		if before <= after {
			before++
		} else {
			after++
		}
		if before+after > len(lines) {
			return ""
		}
	}
}
