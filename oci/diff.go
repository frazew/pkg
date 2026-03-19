/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
)

// Diff compares the files included in an OCI image with the local files in the given path
// and returns an error if the contents is different
func (c *Client) Diff(ctx context.Context, url, dir string, ignorePaths []string) error {
	_, err := name.ParseReference(url)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	img, err := crane.Pull(url, c.optionsWithContext(ctx)...)
	if err != nil {
		return err
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("failed to list layers: %w", err)
	}

	if len(layers) < 1 {
		return fmt.Errorf("no layers found in artifact")
	}

	l0 := layers[0]

	h, err := l0.Digest()
	if err != nil {
		return fmt.Errorf("failed to get layer digest: %w", err)
	}

	s, err := l0.Size()
	if err != nil {
		return fmt.Errorf("failed to get layer size: %w", err)
	}

	ignoreFileModes := true
	for range 2 {
		h1, size, err := computeLocalArtifactSha256Sum(dir, ignorePaths, ignoreFileModes)
		if err != nil {
			return fmt.Errorf("failed to build and compute local artifact checksum: %w", err)
		}
		// If there's a diff, and we're ignoring file modes, check again without ignoring them to preserve
		// backwards-compatibility. Otherwise, break early: there's no diff!
		if h1 != h.Hex || size != s {
			if !ignoreFileModes {
				return fmt.Errorf("the remote artifact contents differs from the local one")
			}
			ignoreFileModes = false
		} else {
			break
		}
	}

	return nil
}

func computeLocalArtifactSha256Sum(dir string, ignorePaths []string, ignoreFileModes bool) (string, int64, error) {
	tmpBuildDir, err := os.MkdirTemp("", "ocibuild")
	if err != nil {
		return "", 0, fmt.Errorf("creating temp build dir failed: %w", err)
	}
	defer os.RemoveAll(tmpBuildDir)

	tmpFile := filepath.Join(tmpBuildDir, "artifact.tgz")

	if err := build(tmpFile, dir, ignorePaths, ignoreFileModes); err != nil {
		return "", 0, fmt.Errorf("building artifact failed: %w", err)
	}

	f, err := os.Open(tmpFile)
	if err != nil {
		return "", 0, fmt.Errorf("opening artifact failed: %w", err)
	}
	defer f.Close()

	fstat, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("failed to get file stats: %w", err)
	}

	h1 := sha256.New()
	if _, err := io.Copy(h1, f); err != nil {
		return "", 0, fmt.Errorf("calculating artifact hash failed: %w", err)
	}

	return hex.EncodeToString(h1.Sum(nil)), fstat.Size(), nil
}
