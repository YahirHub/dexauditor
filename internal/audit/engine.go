package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultMaxFileBytes int64 = 4 << 20

type Options struct {
	MaxFileBytes int64
	IncludeTests bool
}

type Engine struct {
	version   string
	options   Options
	analyzers []Analyzer
}

func NewEngine(version string, options Options, analyzers ...Analyzer) *Engine {
	if options.MaxFileBytes <= 0 {
		options.MaxFileBytes = defaultMaxFileBytes
	}
	ordered := append([]Analyzer(nil), analyzers...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Name() < ordered[j].Name() })
	return &Engine{version: version, options: options, analyzers: ordered}
}

func (e *Engine) Audit(ctx context.Context, target string, emit EmitFunc) (Report, error) {
	if emit == nil {
		emit = func(Event) {}
	}
	started := time.Now().UTC()
	emit(Event{Type: EventStart, Time: started, Phase: "setup", Message: "iniciando auditoría estática"})

	project, err := DiscoverProject(ctx, target, e.options, emit)
	if err != nil {
		return Report{}, err
	}

	findings := make([]Finding, 0)
	coverage := make([]Coverage, 0)
	seen := make(map[string]struct{})

	for _, analyzer := range e.analyzers {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		if !analyzer.Applies(project) {
			coverage = append(coverage, Coverage{
				Analyzer: analyzer.Name(),
				Status:   "not_applicable",
				Detail:   "el analizador no detectó superficies compatibles",
			})
			continue
		}

		emit(Event{Type: EventAnalyzerStart, Time: time.Now().UTC(), Phase: "analysis", Analyzer: analyzer.Name(), Message: "analizando"})
		result, analyzeErr := analyzer.Analyze(ctx, project, emit)
		if analyzeErr != nil {
			if errors.Is(analyzeErr, context.Canceled) || errors.Is(analyzeErr, context.DeadlineExceeded) {
				return Report{}, analyzeErr
			}
			emit(Event{Type: EventWarning, Time: time.Now().UTC(), Phase: "analysis", Analyzer: analyzer.Name(), Message: analyzeErr.Error()})
			coverage = append(coverage, Coverage{Analyzer: analyzer.Name(), Status: "blocked", Detail: analyzeErr.Error()})
			continue
		}

		acceptedFindings := 0
		for _, finding := range result.Findings {
			finding = NormalizeFinding(finding)
			if finding.Analyzer == "" {
				finding.Analyzer = analyzer.Name()
			}
			if _, exists := seen[finding.Fingerprint]; exists {
				continue
			}
			seen[finding.Fingerprint] = struct{}{}
			findings = append(findings, finding)
			acceptedFindings++
			copyFinding := finding
			emit(Event{Type: EventFinding, Time: time.Now().UTC(), Phase: "analysis", Analyzer: analyzer.Name(), Finding: &copyFinding})
		}
		coverage = append(coverage, result.Coverage...)
		emit(Event{Type: EventAnalyzerDone, Time: time.Now().UTC(), Phase: "analysis", Analyzer: analyzer.Name(), Message: fmt.Sprintf("%d hallazgos únicos", acceptedFindings)})
	}

	sortFindings(findings)
	sort.SliceStable(coverage, func(i, j int) bool {
		if coverage[i].Analyzer != coverage[j].Analyzer {
			return coverage[i].Analyzer < coverage[j].Analyzer
		}
		if coverage[i].AttackClass != coverage[j].AttackClass {
			return coverage[i].AttackClass < coverage[j].AttackClass
		}
		return coverage[i].Detail < coverage[j].Detail
	})

	finished := time.Now().UTC()
	summary := Summarize(findings)
	report := Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   e.version,
		Target:        project.Root,
		StartedAt:     started,
		FinishedAt:    finished,
		DurationMS:    finished.Sub(started).Milliseconds(),
		Project: ProjectSummary{
			Name:         project.Name,
			Files:        len(project.Files),
			Languages:    cloneLanguageMap(project.Languages),
			TotalBytes:   project.TotalBytes,
			SkippedFiles: project.SkippedFiles,
		},
		Findings: findings,
		Coverage: coverage,
		Summary:  summary,
	}
	emit(Event{Type: EventComplete, Time: finished, Phase: "report", Message: "auditoría terminada", Summary: &report.Summary})
	return report, nil
}

func DiscoverProject(ctx context.Context, target string, options Options, emit EmitFunc) (Project, error) {
	if emit == nil {
		emit = func(Event) {}
	}
	if options.MaxFileBytes <= 0 {
		options.MaxFileBytes = defaultMaxFileBytes
	}

	abs, err := ResolveTargetPath(target)
	if err != nil {
		return Project{}, err
	}

	project := Project{
		Root:      filepath.Clean(abs),
		Name:      filepath.Base(filepath.Clean(abs)),
		Languages: make(map[string]int),
	}
	ignoredDirs := defaultIgnoredDirs()
	processed := 0

	err = filepath.WalkDir(project.Root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == project.Root {
			return nil
		}

		name := strings.ToLower(entry.Name())
		if entry.IsDir() {
			if _, ignore := ignoredDirs[name]; ignore {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			project.SkippedFiles++
			return nil
		}

		fileInfo, err := entry.Info()
		if err != nil {
			project.SkippedFiles++
			return nil
		}
		if !fileInfo.Mode().IsRegular() {
			project.SkippedFiles++
			return nil
		}
		if fileInfo.Size() > options.MaxFileBytes {
			project.SkippedFiles++
			return nil
		}

		rel, err := filepath.Rel(project.Root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		isTest := isTestFile(rel)
		if isTest && !options.IncludeTests {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(rel))
		project.Files = append(project.Files, File{
			Path:    rel,
			AbsPath: path,
			Ext:     ext,
			Size:    fileInfo.Size(),
			IsTest:  isTest,
		})
		project.TotalBytes += fileInfo.Size()
		if language := languageForFile(rel); language != "" {
			project.Languages[language]++
		}
		processed++
		if processed%250 == 0 {
			emit(Event{
				Type:     EventDiscovery,
				Time:     time.Now().UTC(),
				Phase:    "discovery",
				Message:  "inventariando archivos",
				Progress: &Progress{Current: processed},
			})
		}
		return nil
	})
	if err != nil {
		return Project{}, fmt.Errorf("recorriendo objetivo: %w", err)
	}

	sort.Slice(project.Files, func(i, j int) bool { return project.Files[i].Path < project.Files[j].Path })
	emit(Event{
		Type:     EventDiscoveryDone,
		Time:     time.Now().UTC(),
		Phase:    "discovery",
		Message:  fmt.Sprintf("%d archivos analizables, %d omitidos", len(project.Files), project.SkippedFiles),
		Progress: &Progress{Current: len(project.Files), Total: len(project.Files)},
	})
	return project, nil
}

func ResolveTargetPath(target string) (string, error) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		raw = "."
	}

	candidates := targetPathCandidates(raw)
	var firstErr error
	for _, candidate := range candidates {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("resolviendo ruta objetivo: %w", err)
			}
			continue
		}
		abs = filepath.Clean(abs)
		info, err := os.Stat(abs)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("abriendo objetivo: %w", err)
			}
			continue
		}
		if !info.IsDir() {
			if firstErr == nil {
				firstErr = fmt.Errorf("el objetivo debe ser un directorio: %s", abs)
			}
			continue
		}
		return abs, nil
	}
	if firstErr != nil {
		return "", firstErr
	}
	return "", fmt.Errorf("ruta objetivo inválida")
}

func targetPathCandidates(raw string) []string {
	candidates := []string{raw}
	seen := map[string]struct{}{raw: {}}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}

	if len(raw) >= 2 {
		first, last := raw[0], raw[len(raw)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			add(raw[1 : len(raw)-1])
		}
	}
	add(strings.Trim(raw, "\"'"))
	return candidates
}

func defaultIgnoredDirs() map[string]struct{} {
	names := []string{
		".git", ".hg", ".svn", ".idea", ".vscode", ".cache",
		"node_modules", "vendor", "dist", "build", "coverage", "target",
		"bin", "obj", ".next", ".nuxt", ".terraform",
	}
	out := make(map[string]struct{}, len(names))
	for _, name := range names {
		out[name] = struct{}{}
	}
	return out
}

func isTestFile(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(lower))
	return strings.HasSuffix(base, "_test.go") ||
		strings.Contains(lower, "/testdata/") ||
		strings.Contains(lower, "/tests/") ||
		strings.Contains(lower, "/fixtures/") ||
		strings.Contains(lower, "/__tests__/")
}

func languageForFile(path string) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(lower))
	switch filepath.Ext(base) {
	case ".go":
		return "go"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py":
		return "python"
	case ".rs":
		return "rust"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".php":
		return "php"
	case ".rb":
		return "ruby"
	case ".cs":
		return "csharp"
	case ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp":
		return "cpp"
	case ".sh", ".bash", ".zsh", ".ps1":
		return "shell"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".toml":
		return "toml"
	case ".xml":
		return "xml"
	}
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") {
		return "dockerfile"
	}
	return ""
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		left, right := findings[i], findings[j]
		if verdictRank(left.Verdict) != verdictRank(right.Verdict) {
			return verdictRank(left.Verdict) > verdictRank(right.Verdict)
		}
		if severityRank(left.Severity) != severityRank(right.Severity) {
			return severityRank(left.Severity) > severityRank(right.Severity)
		}
		if left.Location.Path != right.Location.Path {
			return left.Location.Path < right.Location.Path
		}
		if left.Location.Line != right.Location.Line {
			return left.Location.Line < right.Location.Line
		}
		return left.RuleID < right.RuleID
	})
}

func verdictRank(v Verdict) int {
	switch v {
	case VerdictConfirmed:
		return 3
	case VerdictNeedsValidation:
		return 2
	case VerdictHardening:
		return 1
	default:
		return 0
	}
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func cloneLanguageMap(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
