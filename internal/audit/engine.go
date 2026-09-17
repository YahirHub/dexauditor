package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultMaxFileBytes int64 = 4 << 20

type Options struct {
	MaxFileBytes   int64
	IncludeTests   bool
	IncludeIgnored bool
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
			Name:            project.Name,
			Files:           len(project.Files),
			Languages:       cloneLanguageMap(project.Languages),
			TotalBytes:      project.TotalBytes,
			SkippedFiles:    project.SkippedFiles,
			SkippedByReason: cloneIntMap(project.SkippedByReason),
			DiscoveryMode:   project.DiscoveryMode,
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
		Root:            filepath.Clean(abs),
		Name:            filepath.Base(filepath.Clean(abs)),
		Languages:       make(map[string]int),
		SkippedByReason: make(map[string]int),
	}

	if !options.IncludeIgnored {
		paths, ignored, gitRepo, gitErr := gitSourceFiles(ctx, project.Root)
		if gitErr != nil {
			emit(Event{Type: EventWarning, Time: time.Now().UTC(), Phase: "discovery", Analyzer: "discovery", Message: "no se pudo consultar metadatos Git; se usará recorrido del filesystem: " + gitErr.Error()})
		} else if gitRepo {
			project.DiscoveryMode = "git"
			if ignored > 0 {
				project.SkippedFiles += ignored
				project.SkippedByReason["git_ignored"] += ignored
			}
			for _, rel := range paths {
				if err := ctx.Err(); err != nil {
					return Project{}, err
				}
				if isDefaultIgnoredPath(rel) {
					project.SkippedFiles++
					project.SkippedByReason["dependency_or_build_dir"]++
					continue
				}
				if err := addProjectFile(&project, rel, options); err != nil {
					return Project{}, err
				}
				if len(project.Files)%250 == 0 && len(project.Files) > 0 {
					emit(Event{Type: EventDiscovery, Time: time.Now().UTC(), Phase: "discovery", Message: "inventariando archivos", Progress: &Progress{Current: len(project.Files)}})
				}
			}
			finishDiscovery(&project, emit)
			return project, nil
		}
	}

	project.DiscoveryMode = "filesystem"
	ignoredDirs := defaultIgnoredDirs()
	err = filepath.WalkDir(project.Root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			project.SkippedFiles++
			project.SkippedByReason["walk_error"]++
			return nil
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
		rel, err := filepath.Rel(project.Root, path)
		if err != nil {
			return err
		}
		if err := addProjectFile(&project, filepath.ToSlash(rel), options); err != nil {
			return err
		}
		if len(project.Files)%250 == 0 && len(project.Files) > 0 {
			emit(Event{Type: EventDiscovery, Time: time.Now().UTC(), Phase: "discovery", Message: "inventariando archivos", Progress: &Progress{Current: len(project.Files)}})
		}
		return nil
	})
	if err != nil {
		return Project{}, fmt.Errorf("recorriendo objetivo: %w", err)
	}

	finishDiscovery(&project, emit)
	return project, nil
}

func gitSourceFiles(ctx context.Context, root string) ([]string, int, bool, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, 0, false, nil
	}
	probe := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--is-inside-work-tree")
	probeOut, err := probe.Output()
	if err != nil || !strings.EqualFold(strings.TrimSpace(string(probeOut)), "true") {
		return nil, 0, false, nil
	}

	cmd := exec.CommandContext(ctx, "git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".")
	out, err := cmd.Output()
	if err != nil {
		return nil, 0, true, fmt.Errorf("git ls-files: %w", err)
	}
	paths := splitNULPaths(out)

	ignored := 0
	ignoredCmd := exec.CommandContext(ctx, "git", "-C", root, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", ".")
	if ignoredOut, ignoredErr := ignoredCmd.Output(); ignoredErr == nil {
		ignored = len(splitNULPaths(ignoredOut))
	}
	return paths, ignored, true, nil
}

func splitNULPaths(data []byte) []string {
	parts := bytes.Split(data, []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		out = append(out, filepath.ToSlash(string(part)))
	}
	return out
}

func addProjectFile(project *Project, rel string, options Options) error {
	rel = filepath.ToSlash(filepath.Clean(filepath.FromSlash(strings.TrimSpace(rel))))
	if rel == "" || rel == "." || strings.HasPrefix(rel, "../") || rel == ".." {
		return nil
	}
	abs := filepath.Join(project.Root, filepath.FromSlash(rel))
	info, err := os.Lstat(abs)
	if err != nil {
		project.SkippedFiles++
		project.SkippedByReason["inaccessible"]++
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		project.SkippedFiles++
		project.SkippedByReason["symlink"]++
		return nil
	}
	if !info.Mode().IsRegular() {
		project.SkippedFiles++
		project.SkippedByReason["non_regular"]++
		return nil
	}
	if info.Size() > options.MaxFileBytes {
		project.SkippedFiles++
		project.SkippedByReason["too_large"]++
		return nil
	}
	isTest := isTestFile(rel)
	if isTest && !options.IncludeTests {
		project.SkippedFiles++
		project.SkippedByReason["tests_excluded"]++
		return nil
	}

	ext := strings.ToLower(filepath.Ext(rel))
	project.Files = append(project.Files, File{Path: rel, AbsPath: abs, Ext: ext, Size: info.Size(), IsTest: isTest})
	project.TotalBytes += info.Size()
	project.Languages[languageForFile(rel)]++
	return nil
}

func finishDiscovery(project *Project, emit EmitFunc) {
	sort.Slice(project.Files, func(i, j int) bool { return project.Files[i].Path < project.Files[j].Path })
	emit(Event{
		Type:     EventDiscoveryDone,
		Time:     time.Now().UTC(),
		Phase:    "discovery",
		Message:  fmt.Sprintf("%d archivos analizables, %d omitidos (fuente: %s)", len(project.Files), project.SkippedFiles, project.DiscoveryMode),
		Progress: &Progress{Current: len(project.Files), Total: len(project.Files)},
	})
}

func isDefaultIgnoredPath(path string) bool {
	parts := strings.Split(strings.ToLower(filepath.ToSlash(path)), "/")
	ignored := defaultIgnoredDirs()
	for i := 0; i < len(parts)-1; i++ {
		if _, ok := ignored[parts[i]]; ok {
			return true
		}
	}
	return false
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
	normalized := "/" + strings.TrimPrefix(lower, "/")
	return strings.HasSuffix(base, "_test.go") ||
		strings.HasSuffix(base, ".test.js") ||
		strings.HasSuffix(base, ".test.jsx") ||
		strings.HasSuffix(base, ".test.ts") ||
		strings.HasSuffix(base, ".test.tsx") ||
		strings.HasSuffix(base, ".spec.js") ||
		strings.HasSuffix(base, ".spec.jsx") ||
		strings.HasSuffix(base, ".spec.ts") ||
		strings.HasSuffix(base, ".spec.tsx") ||
		strings.Contains(normalized, "/test/") ||
		strings.Contains(normalized, "/tests/") ||
		strings.Contains(normalized, "/testdata/") ||
		strings.Contains(normalized, "/fixtures/") ||
		strings.Contains(normalized, "/__tests__/") ||
		strings.Contains(normalized, "/e2e/") ||
		strings.Contains(normalized, "/evals/") ||
		strings.Contains(normalized, "/benchmarks/")
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
	case ".md", ".mdx":
		return "markdown"
	case ".txt":
		return "text"
	case ".html", ".htm":
		return "html"
	case ".css", ".scss", ".sass", ".less":
		return "css"
	case ".sql":
		return "sql"
	}
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") {
		return "dockerfile"
	}
	return "other"
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
	return cloneIntMap(in)
}

func cloneIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
