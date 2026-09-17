package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/YahirHub/dexauditor/internal/analyzers/generic"
	"github.com/YahirHub/dexauditor/internal/analyzers/goaudit"
	"github.com/YahirHub/dexauditor/internal/analyzers/jsaudit"
	"github.com/YahirHub/dexauditor/internal/audit"
	"github.com/YahirHub/dexauditor/internal/coveragecatalog"
	"github.com/YahirHub/dexauditor/internal/output"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && strings.EqualFold(args[0], "coverage") {
		return runCoverage(args[1:], stdout, stderr)
	}
	if len(args) > 0 && strings.EqualFold(args[0], "audit") {
		args = args[1:]
	}

	flags := flag.NewFlagSet("dexauditor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	maxFileMB := flags.Int64("max-file-mb", 4, "tamaño máximo por archivo que se leerá durante el análisis")
	excludeTests := flags.Bool("exclude-tests", false, "omite archivos y fixtures de prueba")
	includeIgnored := flags.Bool("include-ignored", false, "incluye archivos ignorados por Git; dependencias/builds comunes siguen excluidos")
	format := flags.String("format", "human", "formato de salida: human, ai o json")
	aiMode := flags.Bool("ai", false, "alias de --format ai; emite NDJSON estable para consumo automatizado")
	outPath := flags.String("out", "", "guarda además el reporte JSON final en esta ruta")
	showVersion := flags.Bool("version", false, "muestra la versión")
	flags.Usage = func() { printUsage(stderr) }

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "DexAuditor %s\n", version)
		return 0
	}
	if *maxFileMB <= 0 {
		fmt.Fprintln(stderr, "--max-file-mb debe ser mayor que cero")
		return 2
	}
	if flags.NArg() > 1 {
		fmt.Fprintln(stderr, "solo se puede auditar una ruta por ejecución")
		printUsage(stderr)
		return 2
	}

	target := "."
	if flags.NArg() == 1 {
		target = flags.Arg(0)
	}
	resolvedTarget, err := audit.ResolveTargetPath(target)
	if err != nil {
		fmt.Fprintf(stderr, "dexauditor: %v\n", err)
		return 1
	}
	target = resolvedTarget

	selectedFormat := strings.ToLower(strings.TrimSpace(*format))
	if *aiMode {
		selectedFormat = "ai"
	}
	renderer, err := newRenderer(selectedFormat, stdout, version, target)
	if err != nil {
		fmt.Fprintf(stderr, "dexauditor: %v\n", err)
		return 2
	}

	engine := audit.NewEngine(version, audit.Options{
		MaxFileBytes:   *maxFileMB << 20,
		IncludeTests:   !*excludeTests,
		IncludeIgnored: *includeIgnored,
	}, generic.New(), goaudit.New(), jsaudit.New())
	report, err := engine.Audit(ctx, target, renderer.Emit)
	if err != nil {
		fmt.Fprintf(stderr, "dexauditor: %v\n", err)
		return 1
	}
	if err := renderer.Err(); err != nil {
		fmt.Fprintf(stderr, "dexauditor: escribiendo salida: %v\n", err)
		return 1
	}
	if err := renderer.Finish(report); err != nil {
		fmt.Fprintf(stderr, "dexauditor: finalizando salida: %v\n", err)
		return 1
	}
	if err := output.WriteReport(*outPath, report); err != nil {
		fmt.Fprintf(stderr, "dexauditor: %v\n", err)
		return 1
	}
	return 0
}

func newRenderer(format string, w io.Writer, toolVersion, target string) (output.Renderer, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "human", "text":
		return output.NewHuman(w, toolVersion, target), nil
	case "ai", "ndjson", "jsonl":
		return output.NewAI(w, toolVersion, target), nil
	case "json":
		return output.NewJSON(w), nil
	default:
		return nil, fmt.Errorf("formato de salida no soportado %q; usa human, ai o json", format)
	}
}

func runCoverage(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dexauditor coverage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "human", "formato de salida: human o json")
	language := flags.String("language", "all", "filtrar salida humana: all, go o javascript-typescript")
	flags.Usage = func() { printCoverageUsage(stderr) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "coverage no acepta una ruta; describe las capacidades compiladas de DexAuditor")
		printCoverageUsage(stderr)
		return 2
	}
	if err := coveragecatalog.Validate(); err != nil {
		fmt.Fprintf(stderr, "dexauditor: catálogo de cobertura inválido: %v\n", err)
		return 1
	}
	report := coveragecatalog.Matrix()
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintf(stderr, "dexauditor: escribiendo cobertura: %v\n", err)
			return 1
		}
		return 0
	case "human", "text", "":
		if err := printCoverageHuman(stdout, report, strings.ToLower(strings.TrimSpace(*language))); err != nil {
			fmt.Fprintf(stderr, "dexauditor: %v\n", err)
			return 2
		}
		return 0
	default:
		fmt.Fprintf(stderr, "dexauditor: formato de cobertura no soportado %q; usa human o json\n", *format)
		return 2
	}
}

func printCoverageHuman(w io.Writer, report coveragecatalog.MatrixReport, language string) error {
	if language == "js" || language == "typescript" || language == "javascript" || language == "js-ts" {
		language = coveragecatalog.LanguageJavaScriptTypeScript
	}
	if language != "all" && language != coveragecatalog.LanguageGo && language != coveragecatalog.LanguageJavaScriptTypeScript {
		return fmt.Errorf("lenguaje de cobertura no soportado %q; usa all, go o javascript-typescript", language)
	}
	fmt.Fprintf(w, "DexAuditor — matriz de cobertura de %s\n", report.Reference)
	fmt.Fprintf(w, "Clases de ataque catalogadas: %d\n", report.Summary.Total)
	if language == "all" || language == coveragecatalog.LanguageGo {
		printCoverageSummary(w, "Go", report.Summary.ByLanguageStatus[coveragecatalog.LanguageGo])
	}
	if language == "all" || language == coveragecatalog.LanguageJavaScriptTypeScript {
		printCoverageSummary(w, "JavaScript/TypeScript", report.Summary.ByLanguageStatus[coveragecatalog.LanguageJavaScriptTypeScript])
	}

	lastDomain := ""
	for _, entry := range report.Entries {
		if entry.Domain != lastDomain {
			fmt.Fprintf(w, "\n[%s]\n", entry.Domain)
			lastDomain = entry.Domain
		}
		fmt.Fprintf(w, "- %s (%s)\n", entry.Name, entry.Source)
		if language == "all" || language == coveragecatalog.LanguageGo {
			printLanguageCoverage(w, "Go", entry.Go)
		}
		if language == "all" || language == coveragecatalog.LanguageJavaScriptTypeScript {
			printLanguageCoverage(w, "JS/TS", entry.JavaScriptTypeScript)
		}
	}
	fmt.Fprintln(w, "\nNota: partial significa cobertura determinista de patrones conocidos, no una auditoría semántica exhaustiva de esa clase.")
	return nil
}

func printCoverageSummary(w io.Writer, label string, counts map[string]int) {
	fmt.Fprintf(w, "%s: partial=%d, not_automated=%d, not_applicable=%d\n",
		label,
		counts[coveragecatalog.StatusPartial],
		counts[coveragecatalog.StatusNotAutomated],
		counts[coveragecatalog.StatusNotApplicable],
	)
}

func printLanguageCoverage(w io.Writer, label string, coverage coveragecatalog.LanguageCoverage) {
	rules := ""
	if len(coverage.Rules) > 0 {
		rules = " [" + strings.Join(coverage.Rules, ", ") + "]"
	}
	fmt.Fprintf(w, "  %s: %s%s — %s\n", label, coverage.Status, rules, coverage.Note)
}

func printCoverageUsage(w io.Writer) {
	fmt.Fprintln(w, "Uso:")
	fmt.Fprintln(w, "  dexauditor coverage [--format human|json] [--language all|go|javascript-typescript]")
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "DexAuditor — auditor estático de código source-first")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Uso:")
	fmt.Fprintln(w, "  dexauditor [opciones] <ruta>")
	fmt.Fprintln(w, "  dexauditor audit [opciones] <ruta>")
	fmt.Fprintln(w, "  dexauditor coverage [opciones]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Opciones:")
	fmt.Fprintln(w, "  --format human|ai|json  salida humana, NDJSON streaming o JSON final")
	fmt.Fprintln(w, "  --ai                    alias de --format ai")
	fmt.Fprintln(w, "  --out RUTA              guardar además el reporte JSON final")
	fmt.Fprintln(w, "  --max-file-mb N         tamaño máximo por archivo (default 4)")
	fmt.Fprintln(w, "  --exclude-tests         omitir tests y fixtures")
	fmt.Fprintln(w, "  --include-ignored       incluir archivos ignorados por Git")
	fmt.Fprintln(w, "  --version               mostrar versión")
	fmt.Fprintln(w, "  -h, --help              mostrar ayuda")
}
