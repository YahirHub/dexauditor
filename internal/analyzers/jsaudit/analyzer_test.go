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

func TestHTMLRuleTrustsSourceVisibleEscaperAndStaticConditional(t *testing.T) {
	root := t.TempDir()
	source := `const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
function render(node, text, active) {
  node.innerHTML = ` + "`<span class=\"${active ? 'on' : ''}\">${esc(text)}</span>`" + `;
}
`
	file := writeJSFixture(t, root, "safe-html.js", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"javascript": 1}}
	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if hasJSRule(result.Findings, "DEXJS004") {
		t.Fatalf("source-visible HTML escaping should be trusted: %#v", result.Findings)
	}
}

func TestHTMLRuleDoesNotTrustMixedEscapedAndRawValues(t *testing.T) {
	root := t.TempDir()
	source := `const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
function render(node, text) {
  node.innerHTML = ` + "`<span>${esc(text)}${text}</span>`" + `;
}
`
	file := writeJSFixture(t, root, "unsafe-html.js", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"javascript": 1}}
	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if countJSRule(result.Findings, "DEXJS004") != 1 {
		t.Fatalf("raw interpolation should remain visible once: %#v", result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXJS004" && finding.Verdict != audit.VerdictHardening {
			t.Fatalf("dynamic HTML without a visible lower-trust source should stay hardening: %#v", finding)
		}
	}
}

func TestHTMLRuleElevatesVisibleLowerTrustSource(t *testing.T) {
	root := t.TempDir()
	source := `function render(node, req) {
  node.innerHTML = req.body.html;
  return <div dangerouslySetInnerHTML={{ __html: req.body.html }} />;
}
`
	file := writeJSFixture(t, root, "visible-source.jsx", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"javascript": 1}}
	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if countJSRule(result.Findings, "DEXJS004") != 2 {
		t.Fatalf("visible request sources should reach both HTML sinks: %#v", result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXJS004" && finding.Verdict != audit.VerdictNeedsValidation {
			t.Fatalf("visible lower-trust HTML source should need validation: %#v", finding)
		}
	}
}

func TestAnalyzerCoversAdditionalSkillSurfaces(t *testing.T) {
	root := t.TempDir()
	source := `import fs from "node:fs";
import path from "node:path";
import { get as httpGet } from "node:http";
function handle(req, root, db, sessionToken) {
  db.query("SELECT * FROM users WHERE id=" + req.query.id);
  fs.readFile(path.join(root, req.params.name), () => {});
  httpGet(req.query.url);
  location.assign(location.search);
  window.postMessage(sessionToken, "*");
  localStorage.setItem("session_token", sessionToken);
}
`
	file := writeJSFixture(t, root, "surfaces.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS006", "DEXJS007", "DEXJS008", "DEXJS009", "DEXJS010", "DEXJS011"} {
		if !hasJSRule(result.Findings, rule) {
			t.Fatalf("expected %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerDoesNotPromoteSafeVariantsForAdditionalSurfaces(t *testing.T) {
	root := t.TempDir()
	source := `import fs from "node:fs";
import path from "node:path";
import { get as httpGet } from "node:http";
const FIXED_FILE = "fixed.txt";
const MANIFESTS = ["go.mod", "Cargo.toml"];
function safe(root, db, id, theme, publicCount) {
  db.query("SELECT * FROM users WHERE id = ?", [id]);
  fs.readFile(path.join(root, "fixed.txt"), () => {});
  fs.readFile(path.join(root, FIXED_FILE), () => {});
  for (const name of MANIFESTS) { fs.readFile(path.join(root, name), () => {}); }
  for (const name of fs.readdirSync(root)) { fs.rmSync(path.join(root, name)); }
  httpGet("https://example.com/health");
  location.assign("/dashboard");
  window.postMessage(publicCount, "https://example.com");
  localStorage.setItem("theme", theme);
}
`
	file := writeJSFixture(t, root, "safe-surfaces.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS006", "DEXJS007", "DEXJS008", "DEXJS009", "DEXJS010", "DEXJS011"} {
		if hasJSRule(result.Findings, rule) {
			t.Fatalf("did not expect %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerCoversRedirectLoggingDynamicModulesVMExecutablesAndCORS(t *testing.T) {
	root := t.TempDir()
	source := `import vm from "node:vm";
import { spawn } from "node:child_process";
async function handle(req, res, logger, sessionToken) {
  res.redirect(req.query.next);
  logger.info(sessionToken);
  await import(req.query.module);
  vm.runInNewContext(req.body.code, {});
  spawn(req.query.tool, ["--version"]);
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
`
	file := writeJSFixture(t, root, "more-surfaces.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS012", "DEXJS013", "DEXJS014", "DEXJS015", "DEXJS016", "DEXJS017"} {
		if !hasJSRule(result.Findings, rule) {
			t.Fatalf("expected %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerDoesNotFlagSafeVariantsForNewSkillSurfaces(t *testing.T) {
	root := t.TempDir()
	source := `import vm from "node:vm";
import { spawn } from "node:child_process";
const fingerprint = value => "fp:" + String(value).length;
async function handle(res, logger, sessionToken, tokenBudget, estimatedTokens) {
  res.redirect("/dashboard");
  logger.info(fingerprint(sessionToken));
  logger.debug({ tokenBudget, estimatedTokens });
  await import("./fixed.js");
  vm.runInNewContext("2 + 2", {});
  spawn("git", ["--version"]);
  res.setHeader("Access-Control-Allow-Origin", "https://app.example");
  res.setHeader("Access-Control-Allow-Credentials", "true");
}
`
	file := writeJSFixture(t, root, "safe-more-surfaces.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS012", "DEXJS013", "DEXJS014", "DEXJS015", "DEXJS016", "DEXJS017"} {
		if hasJSRule(result.Findings, rule) {
			t.Fatalf("did not expect %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestDataflowPropagatesLocalAliasesIntoSecuritySinks(t *testing.T) {
	root := t.TempDir()
	source := `import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
async function handle(req, res, rootDir, db, node) {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id=" + id;
  const name = req.params.name;
  const filePath = path.join(rootDir, name);
  const target = req.query.url;
  const moduleName = req.query.module;
  const executable = req.query.bin;
  const origin = req.headers.origin;
  const rawHTML = req.body.html;
  const safeHTML = esc(rawHTML);
  db.query(sql);
  fs.readFile(filePath, () => {});
  fetch(target);
  location.assign(target);
  res.redirect(target);
  await import(moduleName);
  spawn(executable, ["--version"]);
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  node.innerHTML = rawHTML;
  node.outerHTML = safeHTML;
}
`
	tokens, _ := tokenizeFile([]byte(source), ".ts")
	flow := newJSDataflow(tokens)
	for i := range tokens {
		if tokens[i].text != "fetch" || tokenText(tokens, i+1) != "(" {
			continue
		}
		expr, ok := argument(tokens, i+1, 0)
		if !ok || !flow.containsLowerTrust(expr, i) {
			t.Fatalf("simple target alias should retain lower-trust provenance: expr=%#v", expr)
		}
	}

	file := writeJSFixture(t, root, "dataflow.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}
	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXJS004", "DEXJS006", "DEXJS007", "DEXJS008", "DEXJS009", "DEXJS012", "DEXJS014", "DEXJS016", "DEXJS017"} {
		if !hasJSRule(result.Findings, rule) {
			t.Fatalf("expected propagated %s; findings=%#v", rule, result.Findings)
		}
	}
	if countJSRule(result.Findings, "DEXJS004") != 1 {
		t.Fatalf("sanitized HTML alias should be suppressed while raw alias remains: %#v", result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXJS004" && finding.Verdict != audit.VerdictNeedsValidation {
			t.Fatalf("raw HTML alias should preserve lower-trust provenance: %#v", finding)
		}
	}
}

func TestDataflowUsesLatestVisibleAssignmentAndIsolatesSiblingBlocks(t *testing.T) {
	root := t.TempDir()
	source := `function tainted(req) {
  const siblingOnly = req.query.url;
}
function safe(req) {
  let target = req.query.url;
  target = "https://example.com/health";
  fetch(target);
  fetch(siblingOnly);
}
`
	file := writeJSFixture(t, root, "dataflow-safe.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}
	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if hasJSRule(result.Findings, "DEXJS008") {
		t.Fatalf("reassignment and sibling-scope aliases should not leak taint: %#v", result.Findings)
	}
}

func TestDataflowHandlesTypeAnnotationsParametersAndShadowing(t *testing.T) {
	root := t.TempDir()
	source := `function typed(req) {
  const target: string = req.query.url;
  fetch(target);
}
function parameterBarrier(target: string) {
  fetch(target);
}
function defaultSafe(target: string = "https://example.com/health") {
  fetch(target);
}
function defaultTainted(req, target: string = req.query.url) {
  fetch(target);
}
function shadow(req) {
  const target = req.query.url;
  {
    const target: string = "https://example.com/safe";
    fetch(target);
  }
}
`
	file := writeJSFixture(t, root, "dataflow-types.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}
	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if got := countJSRule(result.Findings, "DEXJS008"); got != 2 {
		t.Fatalf("expected only typed local and tainted default parameter to reach fetch, got %d findings: %#v", got, result.Findings)
	}
}

func TestDataflowHandlesSemicolonlessAndMultilineAssignments(t *testing.T) {
	root := t.TempDir()
	source := `async function handle(req) {
  const tainted = req.query.url
  fetch(tainted)

  const safe =
    "https://example.com" +
    "/health"
  fetch(safe)

  const chained = req.body
    .url
  fetch(chained)
}
`
	file := writeJSFixture(t, root, "dataflow-asi.ts", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"typescript": 1}}
	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if got := countJSRule(result.Findings, "DEXJS008"); got != 2 {
		t.Fatalf("expected tainted and chained aliases only, got %d findings: %#v", got, result.Findings)
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
