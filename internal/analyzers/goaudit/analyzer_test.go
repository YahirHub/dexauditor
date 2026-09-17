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

func TestPathJoinRuleTrustsStaticRangesAndReadDirNames(t *testing.T) {
	root := t.TempDir()
	source := `package service
import (
    "os"
    "path/filepath"
)
func known(home string) {
    for _, name := range []string{"id_ed25519", "id_rsa"} {
        _, _ = os.ReadFile(filepath.Join(home, name))
    }
}
func clear(root string) {
    entries, _ := os.ReadDir(root)
    for _, entry := range entries {
        _ = os.RemoveAll(filepath.Join(root, entry.Name()))
    }
}
func unsafe(root, name string) {
    _, _ = os.ReadFile(filepath.Join(root, name))
}
`
	file := writeGoFixture(t, root, "paths.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	count := 0
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXGO004" {
			count++
			if finding.Location.Line != 18 {
				t.Fatalf("unexpected DEXGO004 location: line=%d evidence=%q", finding.Location.Line, finding.Evidence)
			}
		}
	}
	if count != 1 {
		t.Fatalf("DEXGO004 count = %d, want 1; findings=%#v", count, result.Findings)
	}
}

func TestPathJoinRuleTrustsStrictRegexGuardOnlyWhileValueIsStable(t *testing.T) {
	root := t.TempDir()
	source := `package service
import (
    "os"
    "path/filepath"
    "regexp"
)
var idPattern = regexp.MustCompile(` + "`^[A-Za-z0-9_-]{8,80}$`" + `)
var loosePattern = regexp.MustCompile(` + "`^.*$`" + `)
var mutablePattern = regexp.MustCompile(` + "`^[A-Za-z0-9_-]{8,80}$`" + `)
func init() { mutablePattern = regexp.MustCompile(` + "`^.*$`" + `) }
func safe(root, id string) {
    if !idPattern.MatchString(id) { return }
    _ = os.RemoveAll(filepath.Join(root, id))
}
func reassigned(root, id string) {
    if !idPattern.MatchString(id) { return }
    id = "../escape"
    _ = os.RemoveAll(filepath.Join(root, id))
}
func loose(root, id string) {
    if !loosePattern.MatchString(id) { return }
    _ = os.RemoveAll(filepath.Join(root, id))
}
func mutable(root, id string) {
    if !mutablePattern.MatchString(id) { return }
    _ = os.RemoveAll(filepath.Join(root, id))
}
`
	file := writeGoFixture(t, root, "regex_paths.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	count := 0
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXGO004" {
			count++
		}
	}
	if count != 3 {
		t.Fatalf("DEXGO004 count = %d, want 3 for reassigned value, permissive regex and reassigned regex; findings=%#v", count, result.Findings)
	}
}

func TestSensitiveLoggingIgnoresExplicitSanitizersAndMetadata(t *testing.T) {
	root := t.TempDir()
	source := `package service
import "log/slog"
type config struct { AuthSessionTTL int }
func fingerprint(value string) string { return "masked" }
func handle(token string, tokenErr error, cfg config) {
    slog.Debug("safe", "token", fingerprint(token))
    slog.Error("read failed", "error", tokenErr)
    slog.Debug("config", "auth_session_ttl", cfg.AuthSessionTTL)
}
`
	file := writeGoFixture(t, root, "service.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if hasGoRule(result.Findings, "DEXGO010") {
		t.Fatalf("sanitized/metadata logging was flagged: %#v", result.Findings)
	}
}

func TestSensitiveLoggingStillFindsRawSecret(t *testing.T) {
	root := t.TempDir()
	source := `package service
import "log/slog"
func handle(accessToken string) { slog.Debug("bad", "token", accessToken) }
`
	file := writeGoFixture(t, root, "service.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	if !hasGoRule(result.Findings, "DEXGO010") {
		t.Fatalf("raw sensitive log was not flagged: %#v", result.Findings)
	}
}

func TestGoAnalyzerParsesTestsButDoesNotReportRuntimeFindings(t *testing.T) {
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
	if len(result.Findings) != 0 {
		t.Fatalf("test-only runtime code should not produce Go findings: %#v", result.Findings)
	}
	for _, coverage := range result.Coverage {
		if coverage.Analyzer == analyzerName && coverage.Files != 1 {
			t.Fatalf("test file should still count toward parsed coverage: %#v", coverage)
		}
	}
}

func TestAnalyzerCoversDirectSSRFRedirectAndSensitiveCookies(t *testing.T) {
	root := t.TempDir()
	source := `package service
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
    _, _ = http.Get(r.URL.Query().Get("url"))
    http.Redirect(w, r, r.FormValue("next"), http.StatusFound)
    http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "opaque"})
}
`
	file := writeGoFixture(t, root, "web.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXGO016", "DEXGO017", "DEXGO018"} {
		if !hasGoRule(result.Findings, rule) {
			t.Fatalf("expected %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerDoesNotFlagStaticDestinationsOrHardenedCookie(t *testing.T) {
	root := t.TempDir()
	source := `package service
import "net/http"
func handle(w http.ResponseWriter, r *http.Request) {
    _, _ = http.Get("https://example.com/health")
    http.Redirect(w, r, "/dashboard", http.StatusFound)
    http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "opaque", Secure: true, HttpOnly: true})
}
`
	file := writeGoFixture(t, root, "safe_web.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXGO016", "DEXGO017", "DEXGO018"} {
		if hasGoRule(result.Findings, rule) {
			t.Fatalf("did not expect %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerCoversDynamicExecutableWeakHashAndCredentialedCORS(t *testing.T) {
	root := t.TempDir()
	source := `package service
import (
    "crypto/sha1"
    "net/http"
    "os/exec"
)
func handle(w http.ResponseWriter, r *http.Request, password string) {
    _ = exec.Command(r.FormValue("tool"), "--version")
    _ = sha1.Sum([]byte(password))
    w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
    w.Header().Set("Access-Control-Allow-Credentials", "true")
}
`
	file := writeGoFixture(t, root, "skill_surfaces.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXGO019", "DEXGO021", "DEXGO022"} {
		if !hasGoRule(result.Findings, rule) {
			t.Fatalf("expected %s; findings=%#v", rule, result.Findings)
		}
	}
}

func TestAnalyzerDoesNotFlagFixedExecutableChecksumOrStaticCORS(t *testing.T) {
	root := t.TempDir()
	source := `package service
import (
    "crypto/sha1"
    "net/http"
    "os/exec"
)
func handle(w http.ResponseWriter, payload []byte) {
    _ = exec.Command("git", "--version")
    _ = sha1.Sum(payload)
    w.Header().Set("Access-Control-Allow-Origin", "https://app.example")
    w.Header().Set("Access-Control-Allow-Credentials", "true")
}
`
	file := writeGoFixture(t, root, "safe_skill_surfaces.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	for _, rule := range []string{"DEXGO019", "DEXGO021", "DEXGO022"} {
		if hasGoRule(result.Findings, rule) {
			t.Fatalf("did not expect %s; findings=%#v", rule, result.Findings)
		}
	}
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

func TestLoggingRuleDoesNotTreatSessionCountAsCredential(t *testing.T) {
	root := t.TempDir()
	source := `package service
import (
    "fmt"
    "io"
)
func list(out io.Writer, sessions int, sessionToken string) {
    fmt.Fprintf(out, "%d", sessions)
    fmt.Fprintf(out, "%s", sessionToken)
}
`
	file := writeGoFixture(t, root, "service.go", source, false)
	project := audit.Project{Root: root, Name: "fixture", Files: []audit.File{file}, Languages: map[string]int{"go": 1}}

	result, err := New().Analyze(context.Background(), project, nil)
	if err != nil {
		t.Fatalf("Analyze() error: %v", err)
	}
	count := 0
	for _, finding := range result.Findings {
		if finding.RuleID == "DEXGO010" {
			count++
			if finding.Location.Line != 8 {
				t.Fatalf("DEXGO010 should point to sessionToken output, got line %d evidence=%q", finding.Location.Line, finding.Evidence)
			}
		}
	}
	if count != 1 {
		t.Fatalf("DEXGO010 count = %d, want 1; findings=%#v", count, result.Findings)
	}
}
