package audit

import (
	"context"
	"os"
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
