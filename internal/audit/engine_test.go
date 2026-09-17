package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

type fakeAnalyzer struct {
	name     string
	applies  bool
	findings []Finding
}

func (f fakeAnalyzer) Name() string         { return f.name }
func (f fakeAnalyzer) Applies(Project) bool { return f.applies }
func (f fakeAnalyzer) Analyze(_ context.Context, _ Project, _ EmitFunc) (AnalysisResult, error) {
	return AnalysisResult{
		Findings: append([]Finding(nil), f.findings...),
		Coverage: []Coverage{{Analyzer: f.name, AttackClass: "test", Status: "covered", Detail: "fixture"}},
	}, nil
}

func TestEngineRunsMultipleAnalyzersAndDeduplicates(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main\n")
	mustWrite(t, filepath.Join(root, "README.md"), "hello\n")
	mustWrite(t, filepath.Join(root, ".git", "ignored.go"), "package ignored\n")

	finding := Finding{
		RuleID:      "TEST001",
		AttackClass: "test",
		Verdict:     VerdictNeedsValidation,
		Confidence:  ConfidenceHigh,
		Title:       "fixture",
		Description: "fixture",
		Location:    Location{Path: "main.go", Line: 1},
		Evidence:    "package main",
		Remediation: "none",
	}
	engine := NewEngine("test", Options{IncludeTests: true},
		fakeAnalyzer{name: "zeta", applies: true, findings: []Finding{finding}},
		fakeAnalyzer{name: "alpha", applies: true, findings: []Finding{finding}},
	)

	var analyzerStarts []string
	analyzerDone := map[string]string{}
	report, err := engine.Audit(context.Background(), root, func(event Event) {
		if event.Type == EventAnalyzerStart {
			analyzerStarts = append(analyzerStarts, event.Analyzer)
		}
		if event.Type == EventAnalyzerDone {
			analyzerDone[event.Analyzer] = event.Message
		}
	})
	if err != nil {
		t.Fatalf("Audit() error: %v", err)
	}
	if got, want := len(report.Findings), 1; got != want {
		t.Fatalf("findings = %d, want %d", got, want)
	}
	if got, want := report.Project.Files, 2; got != want {
		t.Fatalf("project files = %d, want %d", got, want)
	}
	if len(analyzerStarts) != 2 || analyzerStarts[0] != "alpha" || analyzerStarts[1] != "zeta" {
		t.Fatalf("analyzer order = %#v, want [alpha zeta]", analyzerStarts)
	}
	if analyzerDone["alpha"] != "1 hallazgos únicos" || analyzerDone["zeta"] != "0 hallazgos únicos" {
		t.Fatalf("analyzer done messages = %#v", analyzerDone)
	}
}

func TestDiscoverProjectCanExcludeTests(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "main.go"), "package main\n")
	mustWrite(t, filepath.Join(root, "main_test.go"), "package main\n")

	project, err := DiscoverProject(context.Background(), root, Options{IncludeTests: false}, nil)
	if err != nil {
		t.Fatalf("DiscoverProject() error: %v", err)
	}
	if got, want := len(project.Files), 1; got != want {
		t.Fatalf("files = %d, want %d", got, want)
	}
	if project.Languages["go"] != 1 {
		t.Fatalf("go files = %d, want 1", project.Languages["go"])
	}
}

func TestResolveTargetPathRepairsQuotesAroundPathWithSpaces(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Proyecto Go Con Espacios")
	mustWrite(t, filepath.Join(root, "main.go"), "package main\n")

	for _, input := range []string{root, `"` + root + `"`, root + `"`} {
		resolved, err := ResolveTargetPath(input)
		if err != nil {
			t.Fatalf("ResolveTargetPath(%q) error: %v", input, err)
		}
		if resolved != filepath.Clean(root) {
			t.Fatalf("ResolveTargetPath(%q) = %q, want %q", input, resolved, filepath.Clean(root))
		}
	}
}

func TestDiscoverProjectUsesGitSourceSetAndCanIncludeIgnored(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git no disponible")
	}
	root := t.TempDir()
	if out, err := exec.Command("git", "init", root).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	mustWrite(t, filepath.Join(root, ".gitignore"), ".env\n")
	mustWrite(t, filepath.Join(root, "main.go"), "package main\n")
	mustWrite(t, filepath.Join(root, "README.md"), "# fixture\n")
	mustWrite(t, filepath.Join(root, ".env"), "TOKEN=fixture-secret-value\n")
	if out, err := exec.Command("git", "-C", root, "add", ".gitignore", "main.go").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}

	project, err := DiscoverProject(context.Background(), root, Options{IncludeTests: true}, nil)
	if err != nil {
		t.Fatalf("DiscoverProject() error: %v", err)
	}
	if project.DiscoveryMode != "git" {
		t.Fatalf("discovery mode = %q, want git", project.DiscoveryMode)
	}
	for _, file := range project.Files {
		if file.Path == ".env" {
			t.Fatalf("ignored .env was included: %#v", project.Files)
		}
	}
	if project.SkippedByReason["git_ignored"] == 0 {
		t.Fatalf("expected git_ignored count: %#v", project.SkippedByReason)
	}
	languageTotal := 0
	for _, count := range project.Languages {
		languageTotal += count
	}
	if languageTotal != len(project.Files) {
		t.Fatalf("language total = %d, files = %d: %#v", languageTotal, len(project.Files), project.Languages)
	}
	if project.Languages["markdown"] != 1 {
		t.Fatalf("markdown files = %d, want 1", project.Languages["markdown"])
	}

	withIgnored, err := DiscoverProject(context.Background(), root, Options{IncludeTests: true, IncludeIgnored: true}, nil)
	if err != nil {
		t.Fatalf("DiscoverProject(include ignored) error: %v", err)
	}
	if withIgnored.DiscoveryMode != "filesystem" {
		t.Fatalf("include-ignored mode = %q, want filesystem", withIgnored.DiscoveryMode)
	}
	foundEnv := false
	for _, file := range withIgnored.Files {
		foundEnv = foundEnv || file.Path == ".env"
	}
	if !foundEnv {
		t.Fatalf("--include-ignored equivalent did not include .env: %#v", withIgnored.Files)
	}
}

func TestDiscoverProjectCountsJSXAsJavaScript(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "view.jsx"), "export const View = () => <div />\n")
	mustWrite(t, filepath.Join(root, "service.tsx"), "export const value: string = 'ok'\n")

	project, err := DiscoverProject(context.Background(), root, Options{IncludeTests: true}, nil)
	if err != nil {
		t.Fatalf("DiscoverProject() error: %v", err)
	}
	if project.Languages["javascript"] != 1 {
		t.Fatalf("javascript files = %d, want 1; languages=%#v", project.Languages["javascript"], project.Languages)
	}
	if project.Languages["typescript"] != 1 {
		t.Fatalf("typescript files = %d, want 1; languages=%#v", project.Languages["typescript"], project.Languages)
	}
}

func TestIsTestFileRecognizesCommonCrossLanguageLayouts(t *testing.T) {
	cases := []string{
		"sdk/test/setup-env.ts",
		"sdk/e2e/utils/e2e-mocks.ts",
		"evals/buffbench/eval.json",
		"src/auth.test.ts",
		"src/auth.spec.tsx",
		"pkg/foo_test.go",
	}
	for _, path := range cases {
		if !isTestFile(path) {
			t.Fatalf("isTestFile(%q) = false, want true", path)
		}
	}
	if isTestFile("src/auth.ts") {
		t.Fatal("production source classified as test")
	}
}

func TestFingerprintDoesNotDependOnLineNumber(t *testing.T) {
	one := NewFingerprint("GO001", "main.go", 10, "same evidence")
	two := NewFingerprint("GO001", "main.go", 99, "same   evidence")
	if one != two {
		t.Fatalf("fingerprint changed with line/whitespace: %q != %q", one, two)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
