package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/YahirHub/dexauditor/internal/audit"
)

func TestHumanRendersFindingAndCoverageWarning(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewHuman(&buf, "test", "repo")
	finding := audit.Finding{
		RuleID:      "DEXTEST001",
		Verdict:     audit.VerdictNeedsValidation,
		Title:       "Prueba",
		Location:    audit.Location{Path: "main.go", Line: 7},
		Confidence:  audit.ConfidenceHigh,
		AttackClass: "Injection",
	}
	renderer.Emit(audit.Event{Type: audit.EventStart, Time: time.Now()})
	renderer.Emit(audit.Event{Type: audit.EventFinding, Time: time.Now(), Finding: &finding})
	report := audit.Report{
		DurationMS: 12,
		Summary:    audit.Summary{Total: 1, NeedsValidation: 1},
		Coverage:   []audit.Coverage{{Analyzer: "go", AttackClass: "Access control", Status: "not_automated"}},
	}
	if err := renderer.Finish(report); err != nil {
		t.Fatal(err)
	}
	text := buf.String()
	for _, want := range []string{"DexAuditor test", "[NEEDS_VALIDATION] DEXTEST001", "Resumen: 1 hallazgos", "not_automated=1", "ausencia de hallazgos no equivale"} {
		if !strings.Contains(text, want) {
			t.Fatalf("human output missing %q: %q", want, text)
		}
	}
}

func TestAIProducesOneJSONObjectPerLine(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewAI(&buf, "test", "repo")
	renderer.Emit(audit.Event{Type: audit.EventStart, Time: time.Unix(1, 0).UTC()})
	report := audit.Report{SchemaVersion: audit.SchemaVersion, ToolVersion: "test", FinishedAt: time.Unix(2, 0).UTC()}
	if err := renderer.Finish(report); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(strings.NewReader(buf.String()))
	var got []map[string]any
	for scanner.Scan() {
		var item map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			t.Fatalf("invalid NDJSON line %q: %v", scanner.Text(), err)
		}
		got = append(got, item)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0]["type"] != string(audit.EventStart) || got[1]["type"] != "report" {
		t.Fatalf("unexpected envelopes: %#v", got)
	}
}

func TestJSONProducesFinalDocumentOnly(t *testing.T) {
	var buf bytes.Buffer
	renderer := NewJSON(&buf)
	renderer.Emit(audit.Event{Type: audit.EventStart, Time: time.Now()})
	report := audit.Report{SchemaVersion: audit.SchemaVersion, ToolVersion: "test", Project: audit.ProjectSummary{Name: "repo"}}
	if err := renderer.Finish(report); err != nil {
		t.Fatal(err)
	}
	var decoded audit.Report
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Project.Name != "repo" {
		t.Fatalf("project name = %q", decoded.Project.Name)
	}
}
