// Package fileserve reads files from inside a public document root.
package fileserve

import (
	"os"
	"path/filepath"
)

// Read returns the contents of name, which is meant to live inside root.
func Read(root, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, name))
}
