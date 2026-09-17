package main

import (
	"context"
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
	"github.com/YahirHub/dexauditor/internal/output"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
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

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "DexAuditor — auditor estático de código source-first")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Uso:")
	fmt.Fprintln(w, "  dexauditor [opciones] <ruta>")
	fmt.Fprintln(w, "  dexauditor audit [opciones] <ruta>")
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
