package jsaudit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/YahirHub/dexauditor/internal/audit"
)

func TestAnalyzerFindsHighSignalJavaScriptPatterns(t *testing.T) {
	root := t.TempDir()
	source := `import { exec as run } from "node:child_process";
const cp = require("child_process");
const agent = { rejectUnauthorized: false };
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
run(` + "`echo ${input}`" + `);
cp.execSync(command);
eval(input);
new Function(code);
element.innerHTML = html;
element.insertAdjacentHTML("beforeend", markup);
document.write(body);
const sessionToken = Math.random().toString(36);
`
	file := writeJSFixture(t, root, "service.js", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"javascript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS001", "DEXJS002", "DEXJS003", "DEXJS004", "DEXJS005"} {
		if !hasJSRule(result.Findings, rule) {
			t.Fatalf("expected %s; findings=%#v", rule, result.Findings)
		}
	}
	if countJSRule(result.Findings, "DEXJS001") != 2 {
		t.Fatalf("expected both TLS disabling forms, findings=%#v", result.Findings)
	}
	if countJSRule(result.Findings, "DEXJS002") != 2 {
		t.Fatalf("expected both imported child_process calls, findings=%#v", result.Findings)
	}
}

func TestAnalyzerAvoidsStaticAndUnrelatedPatterns(t *testing.T) {
	root := t.TempDir()
	source := `import { exec } from "node:child_process";
function localExec(value) { return value; }
exec("echo safe");
exec(` + "`ps -p ${process.ppid} -o comm=`" + `);
exec(` + "`echo ${process.pid}-${process.ppid}`" + `);
localExec(input);
type TLSOptions = { rejectUnauthorized: false };
interface FixedTLS { rejectUnauthorized: false }
const agent = { rejectUnauthorized: true };
element.innerHTML = "<strong>safe</strong>";
element.insertAdjacentHTML("beforeend", "<span>safe</span>");
const retryJitter = Math.random();
eval("2 + 2");
`
	file := writeJSFixture(t, root, "safe.js", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"javascript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS001", "DEXJS002", "DEXJS004", "DEXJS005"} {
		if hasJSRule(result.Findings, rule) {
			t.Fatalf("did not expect %s; findings=%#v", rule, result.Findings)
		}
	}
	if countJSRule(result.Findings, "DEXJS003") != 1 || result.Findings[0].Verdict != audit.VerdictHardening {
		t.Fatalf("static eval should be one hardening finding: %#v", result.Findings)
	}
}

func TestAnalyzerHandlesTypeScriptAndTSXTokenization(t *testing.T) {
	root := t.TempDir()
	source := `type Props = { html: string };
export function View(props: Props) {
  const csrfToken: string = Math.random().toString(36);
  return <div dangerouslySetInnerHTML={{ __html: props.html }} data-token={csrfToken} />;
}
`
	file := writeJSFixture(t, root, "view.tsx", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS004", "DEXJS005"} {
		if !hasJSRule(result.Findings, rule) {
			t.Fatalf("expected %s from TSX fixture; findings=%#v", rule, result.Findings)
		}
	}
	for _, coverage := range result.Coverage {
		if coverage.Analyzer == analyzerName && coverage.Files != 1 {
			t.Fatalf("unexpected coverage file count: %#v", coverage)
		}
	}
}

func TestTokenizerReparsesRegularExpressionLiterals(t *testing.T) {
	source := []byte(`const parts = value.split(/[/\\\\]/); const ok = /^x+$/.test(value);`)
	_, errorsSeen := tokenize(source)
	if errorsSeen != 0 {
		t.Fatalf("regex literals produced %d lexical errors, want 0", errorsSeen)
	}
}

func TestTokenizerAcceptsShebangAndJSXClosingTags(t *testing.T) {
	source := []byte("#!/usr/bin/env bun\nconst view = <text>✓ listo · ↑/↓</text>;\n")
	_, errorsSeen := tokenizeFile(source, ".tsx")
	if errorsSeen != 0 {
		t.Fatalf("shebang/JSX text produced %d lexical errors, want 0", errorsSeen)
	}
}

func TestAnalyzerRecognizesRequireDestructuringAliases(t *testing.T) {
	root := t.TempDir()
	source := `const { exec: shell, execSync } = require("node:child_process");
shell(command);
execSync(` + "`echo ${value}`" + `);
`
	file := writeJSFixture(t, root, "require.cjs", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"javascript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if countJSRule(result.Findings, "DEXJS002") != 2 {
		t.Fatalf("expected two shell findings for destructured require aliases: %#v", result.Findings)
	}
}

func TestAnalyzerTokenizesTestsButDoesNotReportRuntimeFindings(t *testing.T) {
	root := t.TempDir()
	source := `const options = { rejectUnauthorized: false };
eval(userInput);
const authToken = Math.random();
`
	file := writeJSFixture(t, root, "service.test.ts", source, true)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("test-only runtime code should not produce JS/TS findings: %#v", result.Findings)
	}
	for _, coverage := range result.Coverage {
		if coverage.Analyzer == analyzerName && coverage.Files != 1 {
			t.Fatalf("test file should still count toward tokenized coverage: %#v", coverage)
		}
	}
}

func TestAnalyzerDoesNotTreatSessionCountAsSecretRandom(t *testing.T) {
	root := t.TempDir()
	source := `const sessionCount = Math.random();
const sessionToken = Math.random();
`
	file := writeJSFixture(t, root, "random.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if countJSRule(result.Findings, "DEXJS005") != 1 {
		t.Fatalf("only sessionToken should be flagged: %#v", result.Findings)
	}
}

func writeJSFixture(t *testing.T, root, rel, content string, isTest bool) audit.File {
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
	return audit.File{Path: filepath.ToSlash(rel), AbsPath: abs, Ext: strings.ToLower(filepath.Ext(rel)), Size: info.Size(), IsTest: isTest}
}

func hasJSRule(findings []audit.Finding, rule string) bool { return countJSRule(findings, rule) > 0 }

func countJSRule(findings []audit.Finding, rule string) int {
	count := 0
	for _, finding := range findings {
		if finding.RuleID == rule {
			count++
		}
	}
	return count
}
