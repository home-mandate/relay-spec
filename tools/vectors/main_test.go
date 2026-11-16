// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func runTool(t *testing.T, dir, _ string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, dir, &out)
	return out.String(), err
}

func TestManifestWritesAndChecks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "conformance"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conformance", "jws-v0.json"), []byte(`{"cases":[{}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest", "-check"); err == nil {
		t.Error("manifest -check passed without a manifest")
	}
	if _, err := runTool(t, dir, "", "manifest"); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest", "-check"); err != nil {
		t.Errorf("manifest -check after writing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conformance", "jws-v0.json"), []byte(`{"cases":[{},{}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runTool(t, dir, "", "manifest", "-check"); err == nil {
		t.Error("manifest -check passed with a changed file")
	}
	if _, err := runTool(t, dir, "", "manifest", "extra"); err == nil {
		t.Error("manifest accepted an argument")
	}
}

func TestUnknownAndMissingCommandsFail(t *testing.T) {
	for _, args := range [][]string{nil, {"digest"}} {
		if _, err := runTool(t, ".", "", args...); err == nil {
			t.Errorf("run(%q) succeeded", args)
		}
	}
}
