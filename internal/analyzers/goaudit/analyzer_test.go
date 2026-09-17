package goaudit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/YahirHub/dexauditor/internal/audit"
)

func TestAnalyzerFindsHighSignalGoPatterns(t *testing.T) {
	root := t.TempDir()
	source := `package service

import (
    "crypto/tls"
    "database/sql"
    "fmt"
    "html/template"
    "io"
    "log"
    "math/rand"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
)

// TODO: add authorization validation before this handler is exposed.
func handle(r *http.Request, db *sql.DB, input, name, password string) {
    _ = &tls.Config{InsecureSkipVerify: true}
    _ = exec.Command("sh", "-c", input)
    _, _ = db.Query("SELECT * FROM users WHERE name = '" + input + "'")
    _, _ = os.ReadFile(filepath.Join("data", name))
    _, _ = io.ReadAll(r.Body)
    token := rand.Int63()
    fmt.Println(token)
    log.Printf("password=%s", password)
    _ = template.HTML(input)
    _ = &http.Client{}
    _, _ = http.Get("https://example.invalid")
    _ = os.WriteFile("shared.txt", nil, 0666)
    log.Fatal("fatal")
}
`
	file := writeGoFixture(t, root, "service.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{
		"DEXGO001", "DEXGO002", "DEXGO003", "DEXGO004", "DEXGO005",
		"DEXGO006", "DEXGO007", "DEXGO008", "DEXGO009", "DEXGO010",
		"DEXGO011", "DEXGO012", "DEXGO015",
	} {
		if !hasGoRule(result.Findings, rule) {
			t.Fatalf("expected %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerDoesNotFlagBoundedOrParameterizedVariants(t *testing.T) {
	root := t.TempDir()
	source := `package service

import (
    crand "crypto/rand"
    "database/sql"
    "io"
    "net/http"
    "os/exec"
)

func handle(r *http.Request, db *sql.DB, input string) {
    _ = exec.Command("echo", input)
    _, _ = db.Query("SELECT * FROM users WHERE name = ?", input)
    _, _ = io.ReadAll(io.LimitReader(r.Body, 1024))
    token := make([]byte, 32)
    _, _ = crand.Read(token)
}
`
	file := writeGoFixture(t, root, "service.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXGO002", "DEXGO003", "DEXGO005", "DEXGO006"} {
		if hasGoRule(result.Findings, rule) {
			t.Fatalf("did not expect %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestNeedsValidationDowngradesToHardeningInTests(t *testing.T) {
	root := t.TempDir()
	source := `package service
import "crypto/tls"
func fixture() { _ = &tls.Config{InsecureSkipVerify: true} }
`
	file := writeGoFixture(t, root, "service_test.go", source, true)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXGO001" {
			if finding.Verdict != audit.VerdictHardening {
				t.Fatalf("test finding verdict = %s, want hardening", finding.Verdict)
			}
			if finding.Blocker != "" {
				t.Fatalf("test hardening should not keep blocker: %q", finding.Blocker)
			}
			return
		}
	}
	t.Fatal("expected DEXGO001")
}

func writeGoFixture(t *testing.T, root, rel, content string, isTest bool) audit.File {
	t.Helper()
	abs := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		t.Fatal(err)
	}
	return audit.File{Path: filepath.ToSlash(rel), AbsPath: abs, Ext: ".go", Size: info.Size(), IsTest: isTest}
}

func hasGoRule(findings []audit.Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}
