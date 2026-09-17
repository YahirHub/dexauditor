package generic

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/YahirHub/dexauditor/internal/audit"
)

func TestAnalyzerFindsRepositoryAndSupplyChainSignals(t *testing.T) {
	root := t.TempDir()
	files := []audit.File{
		writeFixture(t, root, ".env", "API_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz123456\n"),
		writeFixture(t, root, ".github/workflows/ci.yml", "name: ci\non: [push]\npermissions: write-all\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n"),
		writeFixture(t, root, "Dockerfile", "FROM alpine:3.22\nRUN curl -fsSL https://example.invalid/install.sh | sh\n"),
	}
	project := audit.Project{Root: root, Name: "fixture", Files: files, Languages: map[string]int{"yaml": 1, "dockerfile": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXG001", "DEXG007", "DEXG009", "DEXG010", "DEXG014", "DEXG015"} {
		if !hasRule(result.Findings, rule) {
			t.Fatalf("expected rule %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerAvoidsObviousPlaceholdersAndPinnedActions(t *testing.T) {
	root := t.TempDir()
	sha := "0123456789abcdef0123456789abcdef01234567"
	files := []audit.File{
		writeFixture(t, root, ".env.example", "API_KEY=replace-with-your-api-key\n"),
		writeFixture(t, root, ".github/workflows/ci.yml", "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@"+sha+"\n"),
		writeFixture(t, root, "Dockerfile", "FROM alpine:3.22\nUSER 10001\n"),
	}
	project := audit.Project{Root: root, Name: "fixture", Files: files}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXG001", "DEXG007", "DEXG009", "DEXG015"} {
		if hasRule(result.Findings, rule) {
			t.Fatalf("did not expect rule %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestSecretInTestFileIsHardening(t *testing.T) {
	root := t.TempDir()
	file := writeFixture(t, root, "testdata/fixture.txt", "token=AbCdEfGhIjKlMnOpQrStUvWxYz123456\n")
	file.IsTest = true
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	var found bool
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXG007" {
			found = true
			if finding.Verdict != audit.VerdictHardening {
				t.Fatalf("test secret verdict = %s, want hardening", finding.Verdict)
			}
		}
	}
	if !found {
		t.Fatal("expected generic secret rule in test fixture")
	}
}

func writeFixture(t *testing.T, root, rel, content string) audit.File {
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
	return audit.File{Path: filepath.ToSlash(rel), AbsPath: abs, Ext: filepath.Ext(rel), Size: info.Size()}
}

func hasRule(findings []audit.Finding, rule string) bool {
	for _, finding := range findings {
		if finding.RuleID == rule {
			return true
		}
	}
	return false
}

func TestSecurityTODORuleIgnoresDocumentationAndRequiresCommentSyntax(t *testing.T) {
	root := t.TempDir()
	files := []audit.File{
		writeFixture(t, root, "README.md", "TODO: add authentication validation\n"),
		writeFixture(t, root, "app.js", "const text = 'TODO add authentication validation';\n// TODO: add authentication validation\n"),
	}
	project := audit.Project{Root: root, Name: "fixture", Files: files}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	count := 0
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXG008" {
			count++
			if finding.Location.Path != "app.js" || finding.Location.Line != 2 {
				t.Fatalf("unexpected TODO finding location: %#v", finding.Location)
			}
		}
	}
	if count != 1 {
		t.Fatalf("DEXG008 count = %d, want 1; findings=%#v", count, result.Findings)
	}
}
