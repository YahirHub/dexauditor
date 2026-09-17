package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/YahirHub/dexauditor/internal/audit"
)

type Renderer interface {
	Emit(audit.Event)
	Finish(audit.Report) error
	Err() error
}

type Human struct {
	w       io.Writer
	version string
	target  string
	mu      sync.Mutex
	err     error
}

func NewHuman(w io.Writer, version, target string) *Human {
	return &Human{w: w, version: version, target: target}
}

func (h *Human) Emit(event audit.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return
	}
	var err error
	switch event.Type {
	case audit.EventStart:
		_, err = fmt.Fprintf(h.w, "DexAuditor %s — auditoría source-first\nObjetivo: %s\n", h.version, h.target)
	case audit.EventDiscovery:
		if event.Progress != nil {
			_, err = fmt.Fprintf(h.w, "[discovery] %d archivos inventariados...\n", event.Progress.Current)
		}
	case audit.EventDiscoveryDone:
		_, err = fmt.Fprintf(h.w, "[discovery] %s\n", event.Message)
	case audit.EventAnalyzerStart:
		_, err = fmt.Fprintf(h.w, "[%s] iniciando análisis\n", event.Analyzer)
	case audit.EventFinding:
		if event.Finding != nil {
			err = writeHumanFinding(h.w, *event.Finding)
		}
	case audit.EventAnalyzerDone:
		_, err = fmt.Fprintf(h.w, "[%s] %s\n", event.Analyzer, event.Message)
	case audit.EventWarning:
		_, err = fmt.Fprintf(h.w, "[warning] %s: %s\n", event.Analyzer, event.Message)
	}
	if err != nil {
		h.err = err
	}
}

func writeHumanFinding(w io.Writer, f audit.Finding) error {
	label := strings.ToUpper(string(f.Verdict))
	if f.Verdict == audit.VerdictConfirmed && f.Severity != "" {
		label += "/" + strings.ToUpper(string(f.Severity))
	}
	location := f.Location.Path
	if f.Location.Line > 0 {
		location = fmt.Sprintf("%s:%d", location, f.Location.Line)
	}
	if _, err := fmt.Fprintf(w, "\n[%s] %s — %s\n", label, f.RuleID, f.Title); err != nil {
		return err
	}
	fields := [][2]string{
		{"Clase", f.AttackClass},
		{"Confianza", string(f.Confidence)},
		{"Ubicación", location},
		{"Por qué", f.Description},
		{"Evidencia", f.Evidence},
	}
	if f.Blocker != "" {
		fields = append(fields, [2]string{"Qué falta validar", f.Blocker})
	}
	fields = append(fields,
		[2]string{"Recomendación", f.Remediation},
		[2]string{"Fingerprint", f.Fingerprint},
	)
	for _, field := range fields {
		if strings.TrimSpace(field[1]) == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "  %s: %s\n", field[0], field[1]); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, strings.Repeat("-", 72))
	return err
}

func (h *Human) Finish(report audit.Report) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return h.err
	}
	_, h.err = fmt.Fprintf(h.w,
		"\nResumen: %d hallazgos (%d confirmados, %d por validar, %d hardening) en %d ms\n",
		report.Summary.Total,
		report.Summary.Confirmed,
		report.Summary.NeedsValidation,
		report.Summary.Hardening,
		report.DurationMS,
	)
	if h.err != nil {
		return h.err
	}
	if _, h.err = fmt.Fprintf(h.w, "Inventario: %d archivos, fuente=%s, omitidos=%d\n", report.Project.Files, report.Project.DiscoveryMode, report.Project.SkippedFiles); h.err != nil {
		return h.err
	}
	if len(report.Project.Languages) > 0 {
		if h.err = writeCountMap(h.w, "Lenguajes", report.Project.Languages); h.err != nil {
			return h.err
		}
	}
	if len(report.Project.SkippedByReason) > 0 {
		if h.err = writeCountMap(h.w, "Omitidos", report.Project.SkippedByReason); h.err != nil {
			return h.err
		}
	}

	statusCounts := make(map[string]int)
	for _, coverage := range report.Coverage {
		statusCounts[coverage.Status]++
	}
	keys := make([]string, 0, len(statusCounts))
	for key := range statusCounts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) > 0 {
		if _, h.err = fmt.Fprint(h.w, "Cobertura: "); h.err != nil {
			return h.err
		}
		for i, key := range keys {
			if i > 0 {
				if _, h.err = fmt.Fprint(h.w, ", "); h.err != nil {
					return h.err
				}
			}
			if _, h.err = fmt.Fprintf(h.w, "%s=%d", key, statusCounts[key]); h.err != nil {
				return h.err
			}
		}
		_, h.err = fmt.Fprintln(h.w)
	}
	if hasUnautomatedCoverage(report.Coverage) {
		_, h.err = fmt.Fprintln(h.w, "Nota: existe cobertura partial, not_automated o blocked; ausencia de hallazgos no equivale a auditoría semántica completa.")
	}
	return h.err
}

func (h *Human) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.err
}

type AI struct {
	w       io.Writer
	enc     *json.Encoder
	version string
	target  string
	mu      sync.Mutex
	err     error
}

type aiEnvelope struct {
	SchemaVersion string        `json:"schema_version"`
	Type          string        `json:"type"`
	Time          time.Time     `json:"time"`
	ToolVersion   string        `json:"tool_version"`
	Target        string        `json:"target"`
	Event         *audit.Event  `json:"event,omitempty"`
	Report        *audit.Report `json:"report,omitempty"`
}

func NewAI(w io.Writer, version, target string) *AI {
	return &AI{w: w, enc: json.NewEncoder(w), version: version, target: target}
}

func (a *AI) Emit(event audit.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return
	}
	copyEvent := event
	a.err = a.enc.Encode(aiEnvelope{
		SchemaVersion: audit.SchemaVersion,
		Type:          string(event.Type),
		Time:          event.Time,
		ToolVersion:   a.version,
		Target:        a.target,
		Event:         &copyEvent,
	})
}

func (a *AI) Finish(report audit.Report) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return a.err
	}
	copyReport := report
	a.err = a.enc.Encode(aiEnvelope{
		SchemaVersion: audit.SchemaVersion,
		Type:          "report",
		Time:          report.FinishedAt,
		ToolVersion:   a.version,
		Target:        a.target,
		Report:        &copyReport,
	})
	return a.err
}

func (a *AI) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

type JSON struct {
	w   io.Writer
	mu  sync.Mutex
	err error
}

func NewJSON(w io.Writer) *JSON { return &JSON{w: w} }

func (j *JSON) Emit(audit.Event) {}

func (j *JSON) Finish(report audit.Report) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.err != nil {
		return j.err
	}
	enc := json.NewEncoder(j.w)
	enc.SetIndent("", "  ")
	j.err = enc.Encode(report)
	return j.err
}

func (j *JSON) Err() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.err
}

func WriteReport(path string, report audit.Report) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolviendo ruta de reporte: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("creando carpeta de reporte: %w", err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("serializando reporte: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(abs, data, 0o600); err != nil {
		return fmt.Errorf("escribiendo reporte %s: %w", abs, err)
	}
	return nil
}

func writeCountMap(w io.Writer, label string, counts map[string]int) error {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if _, err := fmt.Fprintf(w, "%s: ", label); err != nil {
		return err
	}
	for i, key := range keys {
		if i > 0 {
			if _, err := fmt.Fprint(w, ", "); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "%s=%d", key, counts[key]); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

func hasUnautomatedCoverage(items []audit.Coverage) bool {
	for _, item := range items {
		if item.Status == "not_automated" || item.Status == "partial" || item.Status == "blocked" {
			return true
		}
	}
	return false
}
