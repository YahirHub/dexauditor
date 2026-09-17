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

func TestRunCoverageHuman(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"coverage", "--language", "go"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(coverage) code = %d, stderr=%q", code, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "Clases de ataque catalogadas: 162") || !strings.Contains(output, "DEXGO002") {
		t.Fatalf("coverage output incomplete: %q", output)
	}
	if strings.Contains(output, "  JS/TS:") {
		t.Fatalf("go filter leaked JS/TS rows: %q", output)
	}
}

func TestRunCoverageJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"coverage", "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(coverage json) code = %d, stderr=%q", code, stderr.String())
	}
	var report struct {
		Reference string `json:"reference"`
		Summary   struct {
			Total int `json:"total_classes"`
		} `json:"summary"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("coverage JSON invalid: %v\n%s", err, stdout.String())
	}
	if report.Reference != "cloudflare/security-audit-skill@c1c8a8c1471069fb0e188eeaff69b8e8db6564a8" || report.Summary.Total != 162 || len(report.Entries) != 162 {
		t.Fatalf("unexpected coverage report: reference=%q total=%d entries=%d", report.Reference, report.Summary.Total, len(report.Entries))
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--help) code = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "DexAuditor") || !strings.Contains(stderr.String(), "--ai") || !strings.Contains(stderr.String(), "--include-ignored") {
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

func TestRunAcceptsSpacePathWithResidualQuote(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Proyecto Go Con Espacios")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{root + `"`}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(space path) code = %d, stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), root+`"`) {
		t.Fatalf("output kept residual quote: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Objetivo: "+filepath.Clean(root)) {
		t.Fatalf("resolved target missing: %q", stdout.String())
	}
}

func TestRunRegistersJavaScriptTypeScriptAnalyzer(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "service.ts"), []byte("const authToken = Math.random();\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{root}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(JS/TS) code = %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "[javascript-typescript] iniciando análisis") {
		t.Fatalf("JS/TS analyzer did not start: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "DEXJS005") {
		t.Fatalf("JS/TS finding missing: %q", stdout.String())
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
