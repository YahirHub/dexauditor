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
	"github.com/YahirHub/dexauditor/internal/audit"
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

	engine := audit.NewEngine(version, audit.Options{
		MaxFileBytes: *maxFileMB << 20,
		IncludeTests: !*excludeTests,
	}, generic.New(), goaudit.New())
	report, err := engine.Audit(ctx, target, humanEmitter(stdout))
	if err != nil {
		fmt.Fprintf(stderr, "dexauditor: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "\nResumen: %d hallazgos (%d confirmados, %d por validar, %d hardening)\n",
		report.Summary.Total,
		report.Summary.Confirmed,
		report.Summary.NeedsValidation,
		report.Summary.Hardening,
	)
	return 0
}

func humanEmitter(w io.Writer) audit.EmitFunc {
	return func(event audit.Event) {
		switch event.Type {
		case audit.EventStart:
			fmt.Fprintln(w, "DexAuditor — auditoría source-first")
		case audit.EventDiscoveryDone:
			fmt.Fprintf(w, "[discovery] %s\n", event.Message)
		case audit.EventAnalyzerStart:
			fmt.Fprintf(w, "[%s] iniciando análisis\n", event.Analyzer)
		case audit.EventFinding:
			if event.Finding != nil {
				fmt.Fprintf(w, "[%s] %s %s:%d — %s\n",
					event.Finding.Verdict,
					event.Finding.RuleID,
					event.Finding.Location.Path,
					event.Finding.Location.Line,
					event.Finding.Title,
				)
			}
		case audit.EventWarning:
			fmt.Fprintf(w, "[warning] %s: %s\n", event.Analyzer, event.Message)
		}
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
	fmt.Fprintln(w, "  --max-file-mb N   tamaño máximo por archivo (default 4)")
	fmt.Fprintln(w, "  --exclude-tests   omitir tests y fixtures")
	fmt.Fprintln(w, "  --version         mostrar versión")
	fmt.Fprintln(w, "  -h, --help        mostrar ayuda")
}
