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

// ProjectKind describes the language and build tool of a target, so the agents can be
// told how to run a test in it. A model given a Solidity project and no hint tends to
// write a Go test command for it.
type ProjectKind struct {
	// Language is the main language of the target, e.g. "Solidity" or "Go".
	Language string
	// BuildTool is the toolchain the project uses, e.g. "Foundry (forge)".
	BuildTool string
	// TestCommand is how the project's own tests are run.
	TestCommand string
	// TestDir is where the tests live, relative to the project root.
	TestDir string
	// PoCAdvice tells the agent how to write a proof of concept for this project.
	PoCAdvice string
}

// DescribeProject looks at the files in scope and says what the target is.
func DescribeProject(root string, files []string) ProjectKind {
	kind := ProjectKind{}

	has := func(name string) bool {
		for _, f := range files {
			if f == name || strings.HasSuffix(f, "/"+name) {
				return true
			}
		}
		return false
	}

	solidity := 0
	goFiles := 0
	for _, f := range files {
		switch {
		case strings.HasSuffix(f, ".sol"):
			solidity++
		case strings.HasSuffix(f, ".go"):
			goFiles++
		}
	}

	switch {
	case has("foundry.toml"):
		kind.Language = "Solidity"
		kind.BuildTool = "Foundry (forge)"
		kind.TestCommand = "forge test"
		kind.TestDir = "test"
		kind.PoCAdvice = "A proof of concept can be a `forge script` instead of a `forge test`: a script compiles the source and the script file only, while the test suite compiles every test file in the project, which on a large Solidity codebase takes a very long time.\n" +
			"Write the script into the package directory and run it with `forge script <file>.s.sol --sig \"run()\"`. The script must make the proof of concept fail: `require(false, \"<your failure_signature>\")` or an explicit `revert(\"<your failure_signature>\")`. A revert exits non-zero and prints the reason, which is what makes the finding reproducible.\n" +
			"The command must create the file and run it in one go, and must not pipe the output of forge: a pipeline reports the exit code of its last command, so a failed compile would look like a clean pass."
	case has("hardhat.config.js"), has("hardhat.config.ts"):
		kind.Language = "Solidity"
		kind.BuildTool = "Hardhat"
		kind.TestCommand = "npx hardhat test"
		kind.PoCAdvice = "Write the proof of concept as a Hardhat test and run it with `npx hardhat test <file>`."
	case has("Cargo.toml"):
		kind.Language = "Rust"
		kind.BuildTool = "Cargo"
		kind.TestCommand = "cargo test"
	case has("go.mod"):
		kind.Language = "Go"
		kind.BuildTool = "Go modules"
		kind.TestCommand = "go test ./..."
	case has("pyproject.toml"), has("requirements.txt"), has("setup.py"):
		kind.Language = "Python"
		kind.BuildTool = "Python"
		kind.TestCommand = "pytest"
	case has("package.json"):
		kind.Language = "JavaScript/TypeScript"
		kind.BuildTool = "npm"
		kind.TestCommand = "npm test"
	}

	if kind.Language == "" {
		switch {
		case solidity > goFiles:
			kind.Language = "Solidity"
		case goFiles > 0:
			kind.Language = "Go"
		}
	}
	if kind.TestDir == "" {
		kind.TestDir = "test"
	}
	return kind
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

// FileContext returns the source of one file for an agent that has to reason about it.
//
// The candidate names a symbol and a line range, but the line range is often a guess: a
// model that cannot count lines will say "line 115" for a function that is somewhere else
// in the file. The symbol is the reliable anchor, so the excerpt is centred on the
// definition of the symbol when it can be found, and on the cited lines only as a
// fallback.
func FileContext(root, relPath string, lineStart, lineEnd int, symbol string, maxBytes int) string {
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

// FileContextForSymbolAnywhere returns the source around the definition of a symbol. The
// file the candidate names is tried first; when the symbol is not there, the other files
// in scope are searched.
//
// The path a model gives is less reliable than the symbol it names: a function that a
// reader would call "CfdEngine._applyOpen" may live in a library the reader never had to
// open. Looking the symbol up across the scope turns a hypothesis that could have been
// judged into one that cannot be judged at all.
func FileContextForSymbolAnywhere(root, relPath string, lineStart, lineEnd int, symbol string, maxBytes int, scopedFiles []string) string {
	if symbol == "" {
		return FileContext(root, relPath, lineStart, lineEnd, "", maxBytes)
	}

	if ctx := FileContextForSymbol(root, relPath, lineStart, lineEnd, symbol, maxBytes); ctx != "" {
		if !strings.Contains(ctx, "was not found in it") {
			return ctx
		}
	}

	for _, candidate := range scopedFiles {
		if candidate == relPath {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(candidate))
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		if _, _, ok := findDefinition(lines, symbol); !ok {
			continue
		}
		ctx := FileContextForSymbol(root, candidate, lineStart, lineEnd, symbol, maxBytes)
		if ctx != "" {
			return ctx
		}
	}

	return FileContextForSymbol(root, relPath, lineStart, lineEnd, symbol, maxBytes)
}

// FileContextForSymbol returns the source around the definition of a symbol. When the
// symbol cannot be found, the whole file is returned rather than a window around the
// cited lines: those lines are the model's guess, and a window around a guess shows the
// Reviewer code that has nothing to do with the claim.
func FileContextForSymbol(root, relPath string, lineStart, lineEnd int, symbol string, maxBytes int) string {
	if maxBytes <= 0 {
		maxBytes = 40000
	}
	if symbol == "" {
		return FileContext(root, relPath, lineStart, lineEnd, "", maxBytes)
	}

	full := filepath.Join(root, filepath.FromSlash(relPath))
	data, err := os.ReadFile(full)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")

	start, end, ok := findDefinition(lines, symbol)
	if !ok {
		return wholeFile(root, relPath, maxBytes, symbol)
	}

	// The definition and its body, with room around it.
	from := start
	to := end
	if from > 0 {
		from--
	}
	if to < len(lines)-1 {
		to++
	}
	window := windowAround(lines, from+1, to+1, maxBytes)
	if window == "" {
		return wholeFile(root, relPath, maxBytes, symbol)
	}
	return fmt.Sprintf("(excerpt of %s around %s)\n%s", relPath, symbol, window)
}

// wholeFile returns the file, with its line numbers, when the symbol cannot be located.
// The line numbers are kept so that the cited range can still be checked against it.
func wholeFile(root, relPath string, maxBytes int, symbol string) string {
	full := filepath.Join(root, filepath.FromSlash(relPath))
	data, err := os.ReadFile(full)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")

	var sb strings.Builder
	if symbol != "" {
		fmt.Fprintf(&sb, "(whole file %s: %s was not found in it; the cited line numbers below are the model's own claim)\n", relPath, symbol)
	}
	for i, line := range lines {
		fmt.Fprintf(&sb, "%4d | %s\n", i+1, line)
		if sb.Len() >= maxBytes {
			sb.WriteString("...[truncated]...\n")
			break
		}
	}
	return sb.String()
}

// findDefinition locates a symbol's definition in a file and returns the line range of
// its body. It understands the shapes a definition takes in the languages the platform
// audits: a function, contract, modifier, event or error declaration.
//
// The symbol a model gives is often close to, but not exactly, the name in the source:
// "creditBounty" for "_creditBounty", or a different case. Those are tried too, because
// a missed symbol means the agent is shown the wrong code.
func findDefinition(lines []string, symbol string) (int, int, bool) {
	symbol = strings.TrimSpace(symbol)
	if symbol == "" {
		return 0, 0, false
	}
	// A model sometimes writes the symbol with its parameter list.
	if idx := strings.Index(symbol, "("); idx > 0 {
		symbol = strings.TrimSpace(symbol[:idx])
	}
	if symbol == "" {
		return 0, 0, false
	}

	for _, variant := range symbolVariants(symbol) {
		if start, end, ok := findDefinitionExact(lines, variant); ok {
			return start, end, true
		}
	}
	return 0, 0, false
}

// symbolVariants lists the forms of a symbol to look for.
func symbolVariants(symbol string) []string {
	variants := []string{symbol}
	if trimmed := strings.TrimPrefix(symbol, "_"); trimmed != symbol && trimmed != "" {
		variants = append(variants, trimmed)
	}
	for _, v := range variants {
		if lower := strings.ToLower(v); lower != v {
			variants = append(variants, lower)
		}
	}
	return variants
}

// findDefinitionExact looks for one exact spelling of a symbol.
func findDefinitionExact(lines []string, symbol string) (int, int, bool) {
	keywords := []string{"function ", "func ", "fn ", "contract ", "modifier ", "event ", "error ", "struct ", "interface ", "library ", "mapping ", "public ", "private ", "internal "}
	lowerSymbol := strings.ToLower(symbol)

	for i, line := range lines {
		if !strings.Contains(strings.ToLower(line), lowerSymbol) {
			continue
		}
		matched := false
		for _, kw := range keywords {
			if strings.Contains(line, kw) && strings.Index(line, kw) < strings.Index(line, symbol) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		// The body ends where the braces balance again. A signature often spans
		// several lines before the opening brace, so the search for it continues
		// until a brace is found or the declaration ends with a semicolon.
		depth := 0
		opened := false
		for j := i; j < len(lines) && j <= i+signatureLookaheadLines; j++ {
			if strings.Contains(lines[j], ";") && !opened {
				// A declaration without a body: the definition is that line.
				return i, i, true
			}
			for _, r := range lines[j] {
				switch r {
				case '{':
					depth++
					opened = true
				case '}':
					depth--
				}
			}
			if opened && depth <= 0 {
				return i, j, true
			}
		}
		return i, i, true
	}
	return 0, 0, false
}

// signatureLookaheadLines is how far past the definition line the opening brace of a
// body is looked for. A multi-line signature is the common case in Solidity.
const signatureLookaheadLines = 60

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
