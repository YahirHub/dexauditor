package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YahirHub/dexauditor/internal/audit"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--help) code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "DexAuditor") || !strings.Contains(stderr.String(), "--ai") {
		t.Fatalf("help output incomplete: %q", stderr.String())
	}
}

func TestRunAuditsDirectory(t *testing.T) {
	root := writeSimpleProject(t)

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

func TestRunAIStreamsNDJSON(t *testing.T) {
	root := writeSimpleProject(t)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--ai", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--ai) code = %d, stderr=%q", code, stderr.String())
	}

	scanner := bufio.NewScanner(strings.NewReader(stdout.String()))
	types := make(map[string]bool)
	lines := 0
	for scanner.Scan() {
		lines++
		var envelope struct {
			SchemaVersion string `json:"schema_version"`
			Type          string `json:"type"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			t.Fatalf("line %d is not JSON: %q: %v", lines, scanner.Text(), err)
		}
		if envelope.SchemaVersion != audit.SchemaVersion {
			t.Fatalf("schema_version = %q", envelope.SchemaVersion)
		}
		types[envelope.Type] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if lines < 3 || !types[string(audit.EventStart)] || !types["report"] {
		t.Fatalf("unexpected AI event types: %#v output=%q", types, stdout.String())
	}
	if strings.Contains(stdout.String(), "Resumen:") {
		t.Fatalf("AI output contains human prose: %q", stdout.String())
	}
}

func TestRunJSONEmitsSingleReport(t *testing.T) {
	root := writeSimpleProject(t)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--format", "json", root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(json) code = %d, stderr=%q", code, stderr.String())
	}
	var report audit.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout is not report JSON: %v\n%s", err, stdout.String())
	}
	if report.SchemaVersion != audit.SchemaVersion || report.Project.Files != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestRunOutWritesFinalReportAndKeepsHumanProgress(t *testing.T) {
	root := writeSimpleProject(t)
	out := filepath.Join(t.TempDir(), "reports", "audit.json")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--out", out, root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--out) code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "[discovery]") || !strings.Contains(stdout.String(), "Resumen:") {
		t.Fatalf("human progress missing: %q", stdout.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report audit.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("saved report invalid: %v", err)
	}
	if report.Project.Files != 1 {
		t.Fatalf("saved report files = %d", report.Project.Files)
	}
}

func TestRunRejectsUnknownFormat(t *testing.T) {
	root := writeSimpleProject(t)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--format", "xml", root}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "formato de salida no soportado") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func writeSimpleProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
