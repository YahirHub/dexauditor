package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "1"

type Verdict string

const (
	VerdictConfirmed       Verdict = "confirmed"
	VerdictNeedsValidation Verdict = "needs_validation"
	VerdictHardening       Verdict = "hardening"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "informational"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Location struct {
	Path   string `json:"path"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

type Finding struct {
	Fingerprint string     `json:"fingerprint"`
	RuleID      string     `json:"rule_id"`
	Analyzer    string     `json:"analyzer"`
	AttackClass string     `json:"attack_class"`
	Verdict     Verdict    `json:"verdict"`
	Severity    Severity   `json:"severity,omitempty"`
	Confidence  Confidence `json:"confidence"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Location    Location   `json:"location"`
	Evidence    string     `json:"evidence"`
	Remediation string     `json:"remediation"`
	Blocker     string     `json:"blocker,omitempty"`
	Tags        []string   `json:"tags,omitempty"`
}

type Coverage struct {
	Analyzer    string `json:"analyzer"`
	AttackClass string `json:"attack_class"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	Files       int    `json:"files,omitempty"`
}

type File struct {
	Path    string `json:"path"`
	AbsPath string `json:"-"`
	Ext     string `json:"ext,omitempty"`
	Size    int64  `json:"size"`
	IsTest  bool   `json:"is_test,omitempty"`
}

type Project struct {
	Root         string         `json:"-"`
	Name         string         `json:"name"`
	Files        []File         `json:"-"`
	Languages    map[string]int `json:"languages"`
	TotalBytes   int64          `json:"total_bytes"`
	SkippedFiles int            `json:"skipped_files"`
}

type ProjectSummary struct {
	Name         string         `json:"name"`
	Files        int            `json:"files"`
	Languages    map[string]int `json:"languages"`
	TotalBytes   int64          `json:"total_bytes"`
	SkippedFiles int            `json:"skipped_files"`
}

type Summary struct {
	Total           int              `json:"total"`
	Confirmed       int              `json:"confirmed"`
	NeedsValidation int              `json:"needs_validation"`
	Hardening       int              `json:"hardening"`
	BySeverity      map[Severity]int `json:"by_severity"`
}

type Report struct {
	SchemaVersion string         `json:"schema_version"`
	ToolVersion   string         `json:"tool_version"`
	Target        string         `json:"target"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    time.Time      `json:"finished_at"`
	DurationMS    int64          `json:"duration_ms"`
	Project       ProjectSummary `json:"project"`
	Findings      []Finding      `json:"findings"`
	Coverage      []Coverage     `json:"coverage"`
	Summary       Summary        `json:"summary"`
}

type EventType string

const (
	EventStart         EventType = "audit.start"
	EventDiscovery     EventType = "discovery.progress"
	EventDiscoveryDone EventType = "discovery.done"
	EventAnalyzerStart EventType = "analyzer.start"
	EventFinding       EventType = "finding"
	EventAnalyzerDone  EventType = "analyzer.done"
	EventWarning       EventType = "warning"
	EventComplete      EventType = "audit.complete"
)

type Progress struct {
	Current int `json:"current"`
	Total   int `json:"total,omitempty"`
}

type Event struct {
	Type     EventType `json:"type"`
	Time     time.Time `json:"time"`
	Phase    string    `json:"phase,omitempty"`
	Analyzer string    `json:"analyzer,omitempty"`
	Message  string    `json:"message,omitempty"`
	Progress *Progress `json:"progress,omitempty"`
	Finding  *Finding  `json:"finding,omitempty"`
	Summary  *Summary  `json:"summary,omitempty"`
}

type EmitFunc func(Event)

type AnalysisResult struct {
	Findings []Finding
	Coverage []Coverage
}

type Analyzer interface {
	Name() string
	Applies(Project) bool
	Analyze(context.Context, Project, EmitFunc) (AnalysisResult, error)
}

func NewFingerprint(ruleID, path string, line int, evidence string) string {
	normalized := strings.Join(strings.Fields(evidence), " ")
	payload := strings.Join([]string{
		strings.TrimSpace(ruleID),
		filepath.ToSlash(strings.TrimSpace(path)),
		strings.TrimSpace(normalized),
	}, "\x00")
	sum := sha256.Sum256([]byte(payload))
	return "dex:" + hex.EncodeToString(sum[:12])
}

func NormalizeFinding(f Finding) Finding {
	f.Location.Path = filepath.ToSlash(strings.TrimSpace(f.Location.Path))
	f.RuleID = strings.TrimSpace(f.RuleID)
	f.Analyzer = strings.TrimSpace(f.Analyzer)
	f.AttackClass = strings.TrimSpace(f.AttackClass)
	f.Title = strings.TrimSpace(f.Title)
	f.Description = strings.TrimSpace(f.Description)
	f.Evidence = strings.TrimSpace(f.Evidence)
	f.Remediation = strings.TrimSpace(f.Remediation)
	f.Blocker = strings.TrimSpace(f.Blocker)
	if f.Fingerprint == "" {
		f.Fingerprint = NewFingerprint(f.RuleID, f.Location.Path, f.Location.Line, f.Evidence)
	}
	if f.Confidence == "" {
		f.Confidence = ConfidenceMedium
	}
	if f.Verdict != VerdictConfirmed {
		f.Severity = ""
	}
	if len(f.Tags) > 0 {
		seen := make(map[string]struct{}, len(f.Tags))
		tags := make([]string, 0, len(f.Tags))
		for _, tag := range f.Tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		f.Tags = tags
	}
	return f
}

func Summarize(findings []Finding) Summary {
	s := Summary{BySeverity: make(map[Severity]int)}
	for _, f := range findings {
		s.Total++
		switch f.Verdict {
		case VerdictConfirmed:
			s.Confirmed++
			if f.Severity != "" {
				s.BySeverity[f.Severity]++
			}
		case VerdictNeedsValidation:
			s.NeedsValidation++
		case VerdictHardening:
			s.Hardening++
		}
	}
	return s
}
