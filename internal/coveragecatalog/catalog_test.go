package coveragecatalog

import "testing"

func TestCatalogContainsAllSkillClasses(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	report := Matrix()
	if report.Reference != "cloudflare/security-audit-skill@c1c8a8c1471069fb0e188eeaff69b8e8db6564a8" {
		t.Fatalf("reference = %q", report.Reference)
	}
	if report.Summary.Total != 162 {
		t.Fatalf("total classes = %d, want 162", report.Summary.Total)
	}
	if len(report.Entries) != 162 {
		t.Fatalf("entries = %d, want 162", len(report.Entries))
	}
	for _, language := range []string{LanguageGo, LanguageJavaScriptTypeScript} {
		total := 0
		for _, count := range report.Summary.ByLanguageStatus[language] {
			total += count
		}
		if total != 162 {
			t.Fatalf("status total for %s = %d, want 162", language, total)
		}
	}
}

func TestCatalogMapsKnownImplementedClasses(t *testing.T) {
	report := Matrix()
	cases := []struct {
		source   string
		name     string
		language string
		rule     string
	}{
		{"ATTACK-CLASSES.md", "Injection", LanguageGo, "DEXGO002"},
		{"ATTACK-CLASSES.md", "Injection", LanguageJavaScriptTypeScript, "DEXJS002"},
		{"CLIENT-SIDE.md", "DOM-based XSS", LanguageJavaScriptTypeScript, "DEXJS004"},
		{"CLIENT-SIDE.md", "Credentialed CORS trust", LanguageGo, "DEXGO022"},
		{"CLIENT-SIDE.md", "Credentialed CORS trust", LanguageJavaScriptTypeScript, "DEXJS017"},
		{"DATA-ISOLATION-AND-LIFECYCLE.md", "Analytics, logs, traces, and diagnostics as alternate readers", LanguageJavaScriptTypeScript, "DEXJS013"},
		{"SUPPLY-CHAIN-AND-RELEASE.md", "Mutable and unbound build inputs", LanguageGo, "DEXG009"},
		{"SUPPLY-CHAIN-AND-RELEASE.md", "Plugin and extension trust expansion", LanguageJavaScriptTypeScript, "DEXJS014"},
	}
	for _, tc := range cases {
		entry, ok := findEntry(report, tc.source, tc.name)
		if !ok {
			t.Fatalf("missing %s#%s", tc.source, tc.name)
		}
		coverage := entry.Go
		if tc.language == LanguageJavaScriptTypeScript {
			coverage = entry.JavaScriptTypeScript
		}
		if coverage.Status != StatusPartial {
			t.Fatalf("%s %s#%s status = %s, want partial", tc.language, tc.source, tc.name, coverage.Status)
		}
		if !contains(coverage.Rules, tc.rule) {
			t.Fatalf("%s %s#%s rules = %#v, missing %s", tc.language, tc.source, tc.name, coverage.Rules, tc.rule)
		}
	}
}

func TestMemorySafetyIsNotApplicableToManagedJavaScript(t *testing.T) {
	report := Matrix()
	for _, entry := range report.Entries {
		if entry.Source != "MEMORY-SAFETY-AND-BINARY.md" {
			continue
		}
		if entry.JavaScriptTypeScript.Status != StatusNotApplicable {
			t.Fatalf("%s JS/TS status = %s, want not_applicable", entry.Name, entry.JavaScriptTypeScript.Status)
		}
	}
}

func findEntry(report MatrixReport, source, name string) (Entry, bool) {
	for _, entry := range report.Entries {
		if entry.Source == source && entry.Name == name {
			return entry, true
		}
	}
	return Entry{}, false
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}
