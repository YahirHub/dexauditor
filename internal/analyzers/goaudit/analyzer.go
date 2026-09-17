package goaudit

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/YahirHub/dexauditor/internal/audit"
)

const analyzerName = "go"

type Analyzer struct{}

func New() Analyzer { return Analyzer{} }

func (Analyzer) Name() string { return analyzerName }

func (Analyzer) Applies(project audit.Project) bool {
	if project.Languages["go"] > 0 {
		return true
	}
	for _, file := range project.Files {
		if strings.EqualFold(file.Ext, ".go") {
			return true
		}
	}
	return false
}

func (Analyzer) Analyze(ctx context.Context, project audit.Project, emit audit.EmitFunc) (audit.AnalysisResult, error) {
	if emit == nil {
		emit = func(audit.Event) {}
	}
	result := audit.AnalysisResult{}
	parsedFiles := 0
	parseFailures := 0

	for _, file := range project.Files {
		if !strings.EqualFold(file.Ext, ".go") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return audit.AnalysisResult{}, err
		}

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, file.AbsPath, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			parseFailures++
			emit(audit.Event{
				Type:     audit.EventWarning,
				Phase:    "analysis",
				Analyzer: analyzerName,
				Message:  fmt.Sprintf("no se pudo parsear %s: %v", file.Path, err),
			})
			continue
		}
		parsedFiles++
		imports := importMap(node)
		result.Findings = append(result.Findings, scanGoFile(file, fset, node, imports)...)
	}

	status := "covered"
	detail := fmt.Sprintf("%d archivos Go parseados con AST", parsedFiles)
	if parseFailures > 0 {
		status = "partial"
		detail = fmt.Sprintf("%d archivos Go parseados; %d no pudieron parsearse", parsedFiles, parseFailures)
	}
	for _, class := range []string{
		"Injection",
		"Resource and file handling",
		"Cryptography and secrets",
		"Resource exhaustion and availability",
		"Client-side and rendering",
		"Obvious things",
	} {
		result.Coverage = append(result.Coverage, audit.Coverage{
			Analyzer:    analyzerName,
			AttackClass: class,
			Status:      status,
			Detail:      detail + "; reglas sintácticas específicas, no prueba exhaustiva",
			Files:       parsedFiles,
		})
	}
	for _, class := range []string{"Access control", "Business logic", "Chained vulnerabilities and trust boundaries"} {
		result.Coverage = append(result.Coverage, audit.Coverage{
			Analyzer:    analyzerName,
			AttackClass: class,
			Status:      "not_automated",
			Detail:      "requiere modelo semántico de autoridad/estado; DexAuditor V1 no afirma cobertura automática",
			Files:       parsedFiles,
		})
	}
	return result, nil
}

func scanGoFile(file audit.File, fset *token.FileSet, node *ast.File, imports map[string]string) []audit.Finding {
	findings := make([]audit.Finding, 0)
	dbImports := hasDatabaseImport(imports)

	ast.Inspect(node, func(n ast.Node) bool {
		switch value := n.(type) {
		case *ast.CompositeLit:
			if isType(value.Type, imports, "crypto/tls", "Config") && boolFieldTrue(value, "InsecureSkipVerify") {
				findings = append(findings, goFinding(file, fset, value, "DEXGO001", "Cryptography and secrets", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceHigh,
					"Validación TLS deshabilitada explícitamente",
					"`tls.Config` establece `InsecureSkipVerify: true`, lo que omite la verificación estándar del certificado/hostname cuando esa configuración se usa en una conexión TLS.",
					"Usa la verificación TLS normal o configura raíces/nombres esperados de forma explícita. Si existe pinning personalizado, documenta y prueba el verificador.",
					contextualBlocker(file, "Confirmar dónde se usa esta configuración y qué principal/recurso protege la conexión.")))
			}
			if isType(value.Type, imports, "net/http", "Client") && !hasField(value, "Timeout") {
				findings = append(findings, goFinding(file, fset, value, "DEXGO008", "Resource exhaustion and availability", audit.VerdictHardening, audit.ConfidenceMedium,
					"Cliente HTTP sin timeout total explícito",
					"Se construye `http.Client` sin campo `Timeout`. Timeouts parciales del Transport pueden existir, por lo que esto se mantiene como hardening.",
					"Define un timeout total apropiado o documenta timeouts equivalentes en el Transport y contextos de cada request.", ""))
			}
			if isType(value.Type, imports, "net/http", "Server") && !hasAnyField(value, "ReadHeaderTimeout", "ReadTimeout", "WriteTimeout", "IdleTimeout") {
				findings = append(findings, goFinding(file, fset, value, "DEXGO014", "Resource exhaustion and availability", audit.VerdictHardening, audit.ConfidenceMedium,
					"Servidor HTTP sin timeouts explícitos visibles",
					"El literal `http.Server` no configura timeouts de lectura/escritura/idle. Un wrapper externo puede imponer límites, por lo que no se eleva a vulnerabilidad.",
					"Configura `ReadHeaderTimeout` y los demás límites aplicables o documenta el control equivalente en la capa que expone el servidor.", ""))
			}
		case *ast.CallExpr:
			if finding, ok := shellCommandFinding(file, fset, value, imports); ok {
				findings = append(findings, finding)
			}
			if dbImports {
				if finding, ok := dynamicSQLFinding(file, fset, value, imports); ok {
					findings = append(findings, finding)
				}
			}
			if finding, ok := pathJoinSinkFinding(file, fset, value, imports); ok {
				findings = append(findings, finding)
			}
			if finding, ok := unboundedReadAllFinding(file, fset, value, imports); ok {
				findings = append(findings, finding)
			}
			if finding, ok := defaultHTTPClientFinding(file, fset, value, imports); ok {
				findings = append(findings, finding)
			}
			if finding, ok := unsafeTemplateHTMLFinding(file, fset, value, imports); ok {
				findings = append(findings, finding)
			}
			if finding, ok := sensitiveLoggingFinding(file, fset, value, imports); ok {
				findings = append(findings, finding)
			}
			if finding, ok := permissiveModeFinding(file, fset, value, imports); ok {
				findings = append(findings, finding)
			}
		case *ast.AssignStmt:
			findings = append(findings, randomAssignmentFindings(file, fset, value, imports)...)
		case *ast.ValueSpec:
			findings = append(findings, randomValueSpecFindings(file, fset, value, imports)...)
		}
		return true
	})

	for _, group := range node.Comments {
		if !isSecurityTODOComment(group.Text()) {
			continue
		}
		findings = append(findings, goFinding(file, fset, group, "DEXGO015", "Obvious things", audit.VerdictHardening, audit.ConfidenceHigh,
			"Comentario pendiente relacionado con seguridad",
			"Un comentario Go real contiene TODO/FIXME/HACK/XXX junto con un control de seguridad. No se eleva a vulnerabilidad sin una ruta de impacto.",
			"Resuelve el pendiente o documenta por qué el control actual es suficiente y agrega una prueba de regresión cuando corresponda.", ""))
	}

	if importedPath(imports, "net/http/pprof") {
		pos := fset.Position(node.Pos())
		findings = append(findings, audit.Finding{
			RuleID:      "DEXGO013",
			Analyzer:    analyzerName,
			AttackClass: "Obvious things",
			Verdict:     contextualVerdict(file, audit.VerdictNeedsValidation),
			Confidence:  audit.ConfidenceMedium,
			Title:       "Handlers pprof registrados por importación",
			Description: "La importación de `net/http/pprof` puede registrar endpoints de diagnóstico en el DefaultServeMux. La exposición real depende del mux y listener utilizados.",
			Location:    audit.Location{Path: file.Path, Line: pos.Line, Column: pos.Column},
			Evidence:    "import net/http/pprof",
			Remediation: "Expón pprof solo en una interfaz administrativa autenticada/aislada o usa un mux separado no accesible por clientes no confiables.",
			Blocker:     contextualBlocker(file, "Confirmar si DefaultServeMux queda accesible desde una interfaz de menor confianza."),
		})
	}

	if node.Name != nil && node.Name.Name != "main" {
		for _, decl := range node.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name == nil || fn.Name.Name == "init" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isPackageCall(call, imports, "log", "Fatal", "Fatalf", "Fatalln") || isPackageCall(call, imports, "os", "Exit") {
					findings = append(findings, goFinding(file, fset, call, "DEXGO012", "Resource exhaustion and availability", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceMedium,
						"Salida fatal de proceso dentro de lógica reutilizable",
						"Una función fuera de `main`/`init` termina el proceso. Si entrada no confiable alcanza esta ruta en un servicio compartido, un error local puede convertirse en indisponibilidad global.",
						"Devuelve un error al llamador y deja la decisión de terminar el proceso en el borde de arranque/CLI.",
						contextualBlocker(file, "Confirmar que una entrada de menor confianza puede alcanzar esta función y que el proceso comparte servicio con otros usuarios.")))
				}
				return true
			})
		}
	}

	return findings
}

func shellCommandFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !selectorPackage(sel, imports, "os/exec") {
		return audit.Finding{}, false
	}
	name := sel.Sel.Name
	argOffset := 0
	switch name {
	case "Command":
		argOffset = 0
	case "CommandContext":
		argOffset = 1
	default:
		return audit.Finding{}, false
	}
	if len(call.Args) < argOffset+3 {
		return audit.Finding{}, false
	}
	shell, shellOK := stringLiteral(call.Args[argOffset])
	flag, flagOK := stringLiteral(call.Args[argOffset+1])
	if !shellOK || !flagOK || !isShellMode(shell, flag) || isStaticString(call.Args[argOffset+2]) {
		return audit.Finding{}, false
	}
	return goFinding(file, fset, call, "DEXGO002", "Injection", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceHigh,
		"Comando de shell construido con expresión dinámica",
		"`os/exec` invoca un intérprete (`-c`, `/C` o equivalente) con una expresión no literal. Si esa expresión incorpora entrada de menor confianza, el shell puede reinterpretarla como comandos.",
		"Evita el intérprete y pasa argumentos separados a `exec.Command`; si el shell es imprescindible, aplica una allowlist estructural y no concatenes entrada no confiable.",
		contextualBlocker(file, "Trazar la expresión dinámica hasta su origen y confirmar si un principal de menor confianza puede controlarla.")), true
}

func dynamicSQLFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return audit.Finding{}, false
	}
	queryIndex := 0
	switch sel.Sel.Name {
	case "ExecContext", "QueryContext", "QueryRowContext":
		queryIndex = 1
	case "Exec", "Query", "QueryRow", "Raw", "Where", "Order", "Select":
		queryIndex = 0
	default:
		return audit.Finding{}, false
	}
	if len(call.Args) <= queryIndex || !isDynamicString(call.Args[queryIndex], imports) {
		return audit.Finding{}, false
	}
	return goFinding(file, fset, call, "DEXGO003", "Injection", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceMedium,
		"Consulta construida dinámicamente antes del sink SQL/ORM",
		"El primer argumento de una operación SQL/ORM se construye por concatenación o `fmt.Sprintf`. Si contiene valores controlables, puede romper la separación entre consulta y datos.",
		"Usa placeholders/parámetros del driver u ORM. Para identificadores dinámicos, usa una allowlist cerrada en vez de interpolación libre.",
		contextualBlocker(file, "Trazar los operandos dinámicos y confirmar si alguno proviene de entrada de menor confianza y alcanza sintaxis SQL/ORM.")), true
}

func pathJoinSinkFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !selectorPackage(sel, imports, "os") || len(call.Args) == 0 {
		return audit.Finding{}, false
	}
	switch sel.Sel.Name {
	case "Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "Mkdir", "MkdirAll", "Rename":
	default:
		return audit.Finding{}, false
	}
	join, ok := call.Args[0].(*ast.CallExpr)
	if !ok || !isPackageCall(join, imports, "path/filepath", "Join") || len(join.Args) < 2 {
		return audit.Finding{}, false
	}
	dynamic := false
	for _, arg := range join.Args[1:] {
		if !isStaticString(arg) {
			dynamic = true
			break
		}
	}
	if !dynamic {
		return audit.Finding{}, false
	}
	return goFinding(file, fset, call, "DEXGO004", "Resource and file handling", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceMedium,
		"Ruta dinámica unida directamente antes de acceso al filesystem",
		"Un sink de filesystem recibe `filepath.Join` con componentes dinámicos. `Join` normaliza separadores pero no impone que el resultado permanezca dentro de un directorio autorizado.",
		"Valida el componente contra una allowlist o resuelve/canonicaliza y verifica que el destino permanezca debajo del root permitido antes del último acceso confiable.",
		contextualBlocker(file, "Confirmar si el componente dinámico es controlable por un principal de menor confianza y si existe una validación de confinamiento antes de este sink.")), true
}

func unboundedReadAllFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	if !isPackageCall(call, imports, "io", "ReadAll") || len(call.Args) != 1 {
		return audit.Finding{}, false
	}
	if isPackageCallExpr(call.Args[0], imports, "io", "LimitReader") {
		return audit.Finding{}, false
	}
	sel, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Body" {
		return audit.Finding{}, false
	}
	return goFinding(file, fset, call, "DEXGO006", "Resource exhaustion and availability", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceHigh,
		"Cuerpo de request leído completo sin límite visible en el sink",
		"`io.ReadAll(...Body)` puede materializar todo el cuerpo en memoria. Puede existir un límite aguas arriba, por eso la ruta requiere validación antes de afirmar impacto compartido.",
		"Aplica `http.MaxBytesReader`, `io.LimitReader` con manejo de exceso, o un límite equivalente antes de leer todo el cuerpo.",
		contextualBlocker(file, "Confirmar el límite efectivo más cercano aguas arriba y si clientes de menor confianza pueden alcanzar este cuerpo.")), true
}

func defaultHTTPClientFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	if !isPackageCall(call, imports, "net/http", "Get", "Post", "PostForm") {
		return audit.Finding{}, false
	}
	return goFinding(file, fset, call, "DEXGO007", "Resource exhaustion and availability", audit.VerdictHardening, audit.ConfidenceMedium,
		"Cliente HTTP global sin timeout total explícito",
		"Los helpers globales de `net/http` usan `http.DefaultClient`, cuyo timeout total puede quedar sin límite. Contextos o transporte externo pueden reducir el riesgo.",
		"Usa un `http.Client` con timeout apropiado y propaga `context.Context` con deadlines para operaciones cancelables.", ""), true
}

func unsafeTemplateHTMLFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !selectorPackage(sel, imports, "html/template") || sel.Sel.Name != "HTML" || len(call.Args) != 1 || isStaticString(call.Args[0]) {
		return audit.Finding{}, false
	}
	return goFinding(file, fset, call, "DEXGO009", "Client-side and rendering", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceHigh,
		"Conversión dinámica a `template.HTML`",
		"Una expresión no literal se marca como HTML confiable, deshabilitando el escape contextual de `html/template` para ese valor.",
		"Conserva el valor como texto sin marcar o sanitiza mediante una política HTML explícita antes de convertirlo a contenido confiable.",
		contextualBlocker(file, "Confirmar si el valor puede contener datos de menor confianza y si llega a una respuesta/render compartido.")), true
}

func sensitiveLoggingFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	if !isLoggingCall(call, imports) {
		return audit.Finding{}, false
	}
	for _, arg := range call.Args {
		if expressionContainsSensitiveIdentifier(arg) {
			return goFinding(file, fset, call, "DEXGO010", "Cryptography and secrets", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceMedium,
				"Dato con nombre sensible enviado a logging/salida formateada",
				"Una expresión cuyo identificador parece contener token, contraseña, secreto, cookie, autorización o credencial se pasa a una función de logging/salida. El nombre no prueba que el valor sea secreto real.",
				"Evita registrar credenciales y valores de autenticación; registra identificadores no sensibles o versiones explícitamente redactadas.",
				contextualBlocker(file, "Confirmar qué valor contiene la expresión y si el destino de logs/salida es accesible fuera del principal autorizado.")), true
		}
	}
	return audit.Finding{}, false
}

func permissiveModeFinding(file audit.File, fset *token.FileSet, call *ast.CallExpr, imports map[string]string) (audit.Finding, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !selectorPackage(sel, imports, "os") {
		return audit.Finding{}, false
	}
	modeIndex := -1
	switch sel.Sel.Name {
	case "WriteFile":
		modeIndex = 2
	case "OpenFile":
		modeIndex = 2
	case "Mkdir", "MkdirAll":
		modeIndex = 1
	default:
		return audit.Finding{}, false
	}
	if len(call.Args) <= modeIndex {
		return audit.Finding{}, false
	}
	mode, ok := integerLiteral(call.Args[modeIndex])
	if !ok || mode&0o002 == 0 {
		return audit.Finding{}, false
	}
	return goFinding(file, fset, call, "DEXGO011", "Resource and file handling", audit.VerdictHardening, audit.ConfidenceHigh,
		"Archivo o directorio solicitado como world-writable",
		"El modo literal permite escritura a `others` antes de aplicar umask. La exposición real depende del sistema y del contenido almacenado.",
		"Usa el modo mínimo necesario (por ejemplo 0600/0640 para datos sensibles y 0700/0750 para directorios privados) y controla propietario/grupo explícitamente.", ""), true
}

func randomAssignmentFindings(file audit.File, fset *token.FileSet, stmt *ast.AssignStmt, imports map[string]string) []audit.Finding {
	findings := make([]audit.Finding, 0)
	if len(stmt.Lhs) == len(stmt.Rhs) {
		for i := range stmt.Lhs {
			if sensitiveName(exprName(stmt.Lhs[i])) && isMathRandCall(stmt.Rhs[i], imports) {
				findings = append(findings, goFinding(file, fset, stmt, "DEXGO005", "Cryptography and secrets", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceHigh,
					"`math/rand` usado para valor con nombre sensible",
					"Un valor con nombre de token/secreto/nonce/session/OTP se deriva de `math/rand`, que no ofrece aleatoriedad criptográficamente segura.",
					"Usa `crypto/rand` y codifica los bytes sin reducir entropía de forma predecible.",
					contextualBlocker(file, "Confirmar que el valor se usa como credencial, nonce de seguridad, token de sesión u otro secreto no predecible.")))
			}
		}
	}
	for _, rhs := range stmt.Rhs {
		call, ok := rhs.(*ast.CallExpr)
		if !ok || !isPackageCall(call, imports, "math/rand", "Read") || len(call.Args) != 1 || !sensitiveName(exprName(call.Args[0])) {
			continue
		}
		findings = append(findings, goFinding(file, fset, stmt, "DEXGO005", "Cryptography and secrets", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceHigh,
			"`math/rand` usado para valor con nombre sensible",
			"Un buffer con nombre sensible recibe bytes de `math/rand`, que no es una fuente criptográficamente segura.",
			"Usa `crypto/rand.Read` o `rand.Read` de `crypto/rand`.",
			contextualBlocker(file, "Confirmar que el buffer se usa como secreto, token o nonce de seguridad.")))
	}
	return findings
}

func randomValueSpecFindings(file audit.File, fset *token.FileSet, spec *ast.ValueSpec, imports map[string]string) []audit.Finding {
	findings := make([]audit.Finding, 0)
	if len(spec.Names) != len(spec.Values) {
		return findings
	}
	for i, name := range spec.Names {
		if sensitiveName(name.Name) && isMathRandCall(spec.Values[i], imports) {
			findings = append(findings, goFinding(file, fset, spec, "DEXGO005", "Cryptography and secrets", contextualVerdict(file, audit.VerdictNeedsValidation), audit.ConfidenceHigh,
				"`math/rand` usado para valor con nombre sensible",
				"Un valor con nombre de token/secreto/nonce/session/OTP se deriva de `math/rand`, que no ofrece aleatoriedad criptográficamente segura.",
				"Usa `crypto/rand` y conserva suficiente entropía para el propósito de seguridad.",
				contextualBlocker(file, "Confirmar que el valor protege una frontera real de seguridad.")))
		}
	}
	return findings
}

func goFinding(file audit.File, fset *token.FileSet, node ast.Node, rule, class string, verdict audit.Verdict, confidence audit.Confidence, title, description, remediation, blocker string) audit.Finding {
	position := fset.Position(node.Pos())
	return audit.Finding{
		RuleID:      rule,
		Analyzer:    analyzerName,
		AttackClass: class,
		Verdict:     verdict,
		Confidence:  confidence,
		Title:       title,
		Description: description,
		Location:    audit.Location{Path: file.Path, Line: position.Line, Column: position.Column},
		Evidence:    renderNode(fset, node),
		Remediation: remediation,
		Blocker:     blocker,
	}
}

func contextualVerdict(file audit.File, desired audit.Verdict) audit.Verdict {
	if file.IsTest && desired == audit.VerdictNeedsValidation {
		return audit.VerdictHardening
	}
	return desired
}

func contextualBlocker(file audit.File, blocker string) string {
	if file.IsTest {
		return ""
	}
	return blocker
}

func importMap(file *ast.File) map[string]string {
	imports := make(map[string]string, len(file.Imports))
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if spec.Name != nil {
			name = spec.Name.Name
		} else {
			name = filepath.Base(path)
		}
		imports[name] = path
	}
	return imports
}

func importedPath(imports map[string]string, path string) bool {
	for _, imported := range imports {
		if imported == path {
			return true
		}
	}
	return false
}

func hasDatabaseImport(imports map[string]string) bool {
	for _, path := range imports {
		if path == "database/sql" || strings.Contains(path, "gorm.io/") || strings.HasSuffix(path, "/gorm") || strings.Contains(path, "sqlx") {
			return true
		}
	}
	return false
}

func selectorPackage(sel *ast.SelectorExpr, imports map[string]string, path string) bool {
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return imports[ident.Name] == path
}

func isPackageCall(call *ast.CallExpr, imports map[string]string, path string, names ...string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || !selectorPackage(sel, imports, path) {
		return false
	}
	for _, name := range names {
		if sel.Sel.Name == name {
			return true
		}
	}
	return false
}

func isPackageCallExpr(expr ast.Expr, imports map[string]string, path string, names ...string) bool {
	call, ok := expr.(*ast.CallExpr)
	return ok && isPackageCall(call, imports, path, names...)
}

func isType(expr ast.Expr, imports map[string]string, path, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == name && selectorPackage(sel, imports, path)
}

func boolFieldTrue(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != field {
			continue
		}
		ident, ok := kv.Value.(*ast.Ident)
		return ok && ident.Name == "true"
	}
	return false
}

func hasField(lit *ast.CompositeLit, field string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if ok && key.Name == field {
			return true
		}
	}
	return false
}

func hasAnyField(lit *ast.CompositeLit, fields ...string) bool {
	for _, field := range fields {
		if hasField(lit, field) {
			return true
		}
	}
	return false
}

func isDynamicString(expr ast.Expr, imports map[string]string) bool {
	switch value := expr.(type) {
	case *ast.BinaryExpr:
		return value.Op == token.ADD
	case *ast.CallExpr:
		return isPackageCall(value, imports, "fmt", "Sprintf", "Sprint", "Sprintln")
	default:
		return false
	}
}

func isStaticString(expr ast.Expr) bool {
	_, ok := stringLiteral(expr)
	return ok
}

func stringLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func isShellMode(shell, flag string) bool {
	shell = strings.ToLower(filepath.Base(strings.TrimSpace(shell)))
	flag = strings.ToLower(strings.TrimSpace(flag))
	switch shell {
	case "sh", "bash", "zsh", "dash", "ksh":
		return flag == "-c"
	case "cmd", "cmd.exe":
		return flag == "/c"
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return flag == "-command" || flag == "-c"
	default:
		return false
	}
}

func isMathRandCall(expr ast.Expr, imports map[string]string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	return isPackageCall(call, imports, "math/rand", "Int", "Int31", "Int31n", "Int63", "Int63n", "Intn", "Uint32", "Uint64", "Float32", "Float64", "Read")
}

func sensitiveName(name string) bool {
	name = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "_", ""), "-", ""))
	for _, part := range []string{"password", "passwd", "secret", "token", "nonce", "session", "credential", "apikey", "otp", "authcode"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func sensitiveLogName(name string) bool {
	name = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "_", ""), "-", ""))
	for _, part := range []string{"password", "passwd", "secret", "token", "credential", "apikey", "authcode", "authorization", "cookie", "bearer"} {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func exprName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.SelectorExpr:
		if value.Sel != nil {
			return value.Sel.Name
		}
	}
	return ""
}

func expressionContainsSensitiveIdentifier(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		ident, ok := n.(*ast.Ident)
		if ok && sensitiveLogName(ident.Name) {
			found = true
			return false
		}
		return true
	})
	return found
}

func isLoggingCall(call *ast.CallExpr, imports map[string]string) bool {
	if isPackageCall(call, imports, "log", "Print", "Printf", "Println") || isPackageCall(call, imports, "log/slog", "Debug", "Info", "Warn", "Error", "Log") {
		return true
	}
	return isPackageCall(call, imports, "fmt", "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln")
}

func isSecurityTODOComment(text string) bool {
	lower := strings.ToLower(text)
	marker := strings.Contains(lower, "todo") || strings.Contains(lower, "fixme") || strings.Contains(lower, "hack") || strings.Contains(lower, "xxx")
	if !marker {
		return false
	}
	for _, term := range []string{"auth", "permission", "authoriz", "validat", "saniti", "secur", "secret", "token", "credential"} {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func integerLiteral(expr ast.Expr) (int64, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	value, err := strconv.ParseInt(lit.Value, 0, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func renderNode(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := format.Node(&buf, fset, node); err != nil {
		return fmt.Sprintf("%T", node)
	}
	text := strings.Join(strings.Fields(buf.String()), " ")
	const max = 280
	if len(text) > max {
		return text[:max-1] + "…"
	}
	return text
}
