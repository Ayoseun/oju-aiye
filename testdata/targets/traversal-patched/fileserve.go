// Package fileserve reads files from inside a public document root.
package fileserve

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrOutsideRoot is returned when name resolves to a path outside root.
var ErrOutsideRoot = errors.New("fileserve: path escapes root")

// Read returns the contents of name, which must live inside root.
func Read(root, name string) ([]byte, error) {
	full := filepath.Join(root, name)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, ErrOutsideRoot
	}
	return os.ReadFile(full)
}
