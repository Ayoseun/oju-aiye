// Package scope describes which part of a repository an audit may look at, and what the
// program already knows.
//
// A bug bounty program usually does not hand over the whole repository: some packages are
// out of scope, a few contracts are excluded, and the findings of earlier audits are public
// and therefore not eligible for a reward. Carrying that in a manifest keeps the platform
// honest instead of guessing.
package scope

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Scope describes the audit surface.
type Scope struct {
	// Include limits the analysis to these paths, relative to the repository root.
	// An empty list means the whole repository.
	Include []string `yaml:"include"`
	// Exclude drops these files or directories from the analysis. Paths are relative
	// to the repository root and may name a directory.
	Exclude []string `yaml:"exclude"`
	// KnownIssues is free text describing findings that are already known and cannot
	// be rewarded. It is given to every agent.
	KnownIssues string `yaml:"known_issues"`
	// KnownIssuesFile points at a file holding the known issues. It is read when the
	// scope is loaded, so a long list does not have to live inside the manifest.
	KnownIssuesFile string `yaml:"known_issues_file"`
}

// Load reads a scope manifest from a YAML file.
func Load(path string) (*Scope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read scope file: %w", err)
	}

	var sc Scope
	if err := yaml.Unmarshal(data, &sc); err != nil {
		return nil, fmt.Errorf("failed to parse scope file %s: %w", path, err)
	}

	if sc.KnownIssuesFile != "" {
		// Relative to the manifest, so a scope file can travel with the repository.
		knownPath := sc.KnownIssuesFile
		if !filepath.IsAbs(knownPath) {
			knownPath = filepath.Join(filepath.Dir(path), knownPath)
		}
		known, err := os.ReadFile(knownPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read known issues file %s: %w", knownPath, err)
		}
		sc.KnownIssues = strings.TrimSpace(sc.KnownIssues + "\n\n" + string(known))
	}

	return &sc, nil
}

// IsEmpty reports whether the scope restricts nothing.
func (s *Scope) IsEmpty() bool {
	if s == nil {
		return true
	}
	return len(s.Include) == 0 && len(s.Exclude) == 0 && strings.TrimSpace(s.KnownIssues) == ""
}

// Excluded reports whether a repository-relative path is out of scope.
func (s *Scope) Excluded(relPath string) bool {
	if s == nil {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(relPath))
	for _, ex := range s.Exclude {
		ex = filepath.ToSlash(filepath.Clean(ex))
		if ex == "" {
			continue
		}
		if clean == ex || strings.HasPrefix(clean, ex+"/") {
			return true
		}
	}
	return false
}

// Included reports whether a repository-relative path is inside the scope.
func (s *Scope) Included(relPath string) bool {
	if s == nil || len(s.Include) == 0 {
		return true
	}
	clean := filepath.ToSlash(filepath.Clean(relPath))
	for _, in := range s.Include {
		in = filepath.ToSlash(filepath.Clean(in))
		if in == "" {
			continue
		}
		if clean == in || strings.HasPrefix(clean, in+"/") {
			return true
		}
	}
	return false
}

// IncludesSubtree reports whether any included path lies inside a directory. Walking a
// directory tree has to ask this, not Included: the parent of an included path is not
// itself included, and pruning on that would skip the whole tree.
func (s *Scope) IncludesSubtree(dir string) bool {
	if s == nil || len(s.Include) == 0 {
		return true
	}
	clean := filepath.ToSlash(filepath.Clean(dir))
	for _, in := range s.Include {
		in = filepath.ToSlash(filepath.Clean(in))
		if in == "" {
			continue
		}
		if in == clean || strings.HasPrefix(in, clean+"/") || strings.HasPrefix(clean, in+"/") {
			return true
		}
	}
	return false
}

// InScope reports whether a path is both inside the include list and not excluded.
func (s *Scope) InScope(relPath string) bool {
	return s.Included(relPath) && !s.Excluded(relPath)
}
