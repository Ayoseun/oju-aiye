package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// ArtifactRecord represents a stored artifact file.
type ArtifactRecord struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// StoreArtifact writes content to a designated artifact directory, computing its SHA-256 fingerprint.
func StoreArtifact(artifactDir, filename string, content []byte) (*ArtifactRecord, error) {
	if err := os.MkdirAll(artifactDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create artifact directory: %w", err)
	}

	fullPath := filepath.Join(artifactDir, filename)
	if err := os.WriteFile(fullPath, content, 0644); err != nil {
		return nil, fmt.Errorf("failed to write artifact file: %w", err)
	}

	h := sha256.Sum256(content)
	hashStr := hex.EncodeToString(h[:])

	return &ArtifactRecord{
		Path:      fullPath,
		SHA256:    hashStr,
		SizeBytes: int64(len(content)),
	}, nil
}

// ComputeFileHash returns the hex-encoded SHA-256 of any file.
func ComputeFileHash(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}
