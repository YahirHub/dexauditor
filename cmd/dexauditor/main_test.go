package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--help) code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "DexAuditor") {
		t.Fatalf("help output missing title: %q", stderr.String())
	}
}

func TestRunAuditsDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "1 archivos analizables") {
		t.Fatalf("output = %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Resumen: 0 hallazgos") {
		t.Fatalf("summary missing: %q", stdout.String())
	}
}
