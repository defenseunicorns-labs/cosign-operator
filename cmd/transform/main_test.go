package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunTransformsFileInPlace(t *testing.T) {
	input := readTestFile(t, "../../internal/transform/testdata/admission-deployment.input.yaml")
	want := readTestFile(t, "../../internal/transform/testdata/admission-deployment.golden.yaml")

	path := filepath.Join(t.TempDir(), "admission-deployment.yaml")
	if err := os.WriteFile(path, input, 0o644); err != nil {
		t.Fatalf("write temp input: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("run() code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "transformed ") {
		t.Fatalf("stdout = %q, want transformed message", stdout.String())
	}

	got := readTestFile(t, path)
	if string(got) != string(want) {
		t.Fatalf("transformed file mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"-input", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("second run() code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "already transformed ") {
		t.Fatalf("stdout = %q, want already transformed message", stdout.String())
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
