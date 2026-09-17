package generic

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/YahirHub/dexauditor/internal/audit"
)

const analyzerName = "generic"

type Analyzer struct{}

func New() Analyzer { return Analyzer{} }

func (Analyzer) Name() string { return analyzerName }

func (Analyzer) Applies(project audit.Project) bool { return len(project.Files) > 0 }

var (
	privateKeyRE         = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)
	awsKeyRE             = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	githubTokenRE        = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{30,}\b`)
	slackTokenRE         = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`)
	stripeKeyRE          = regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{16,}\b`)
	genericSecretRE      = regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|client[_-]?secret|secret|password|passwd)\s*[:=]\s*["']?([A-Za-z0-9_./+\-=]{16,})`)
	securityTODORE       = regexp.MustCompile(`(?i)(?:TODO|FIXME|HACK|XXX).{0,120}(?:auth|permission|authoriz|validat|saniti|secur|secret|token|credential)|(?:auth|permission|authoriz|validat|saniti|secur|secret|token|credential).{0,120}(?:TODO|FIXME|HACK|XXX)`)
	workflowUsesRE       = regexp.MustCompile(`(?i)^\s*-?\s*uses:\s*([^\s#]+)@([^\s#]+)`)
	workflowUnsafeExprRE = regexp.MustCompile(`\$\{\{\s*github\.event\.(?:issue\.title|issue\.body|comment\.body|pull_request\.title|pull_request\.body|pull_request\.head\.ref|workflow_run\.head_branch)\s*\}\}`)
	dockerSecretRE       = regexp.MustCompile(`(?i)^\s*(?:ENV|ARG)\s+([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|APIKEY)[A-Z0-9_]*)\s*[= ]\s*(\S+)`)
	curlPipeShellRE      = regexp.MustCompile(`(?i)(?:curl|wget)\b[^\n|]*(?:\||\|\s*)(?:sh|bash|zsh|powershell|pwsh)\b`)
)

func (Analyzer) Analyze(ctx context.Context, project audit.Project, _ audit.EmitFunc) (audit.AnalysisResult, error) {
	result := audit.AnalysisResult{}

	for _, file := range project.Files {
		if err := ctx.Err(); err != nil {
			return audit.AnalysisResult{}, err
		}
		if !isTextCandidate(file.Path) {
			continue
		}
		data, err := os.ReadFile(file.AbsPath)
		if err != nil {
			return audit.AnalysisResult{}, fmt.Errorf("leyendo %s: %w", file.Path, err)
		}
		if looksBinary(data) {
			continue
		}
		text := string(data)

		result.Findings = append(result.Findings, scanSecrets(file, text)...)
		result.Findings = append(result.Findings, scanSecurityTODOs(file, text)...)

		lowerPath := strings.ToLower(filepath.ToSlash(file.Path))
		if isGitHubWorkflow(lowerPath) {
			result.Findings = append(result.Findings, scanWorkflow(file, text)...)
		}
		if isDockerfile(lowerPath) {
			result.Findings = append(result.Findings, scanDockerfile(file, text)...)
		}
		if isShellLike(lowerPath) {
			result.Findings = append(result.Findings, scanCurlPipeShell(file, text)...)
		}
	}

	for _, class := range []string{
		"Cryptography and secrets",
		"Supply chain and release",
		"Cloud and deployment",
		"Obvious things",
	} {
		result.Coverage = append(result.Coverage, audit.Coverage{
			Analyzer:    analyzerName,
			AttackClass: class,
			Status:      "covered",
			Detail:      "reglas estáticas deterministas; no implica ausencia de fallas de lógica",
			Files:       len(project.Files),
		})
	}
	return result, nil
}

func scanSecrets(file audit.File, text string) []audit.Finding {
	findings := make([]audit.Finding, 0)
	lowerBase := strings.ToLower(filepath.Base(file.Path))
	if (lowerBase == ".env" || strings.HasPrefix(lowerBase, ".env.")) && !strings.Contains(lowerBase, "example") && !strings.Contains(lowerBase, "sample") && !strings.Contains(lowerBase, "template") {
		findings = append(findings, finding(file, 1, "DEXG001", "Cryptography and secrets", audit.VerdictNeedsValidation, "", audit.ConfidenceHigh,
			"Archivo de entorno sensible presente",
			"El árbol auditado contiene un archivo .env real. La presencia local no demuestra por sí sola que esté versionado o distribuido.",
			file.Path,
			"Confirma si el archivo está versionado o empaquetado; si lo está, retíralo, rota credenciales reales y conserva solo una plantilla sin secretos.",
			"Confirmar que el archivo está versionado/distribuido y contiene credenciales activas."))
	}

	patterns := []struct {
		rule  string
		title string
		re    *regexp.Regexp
	}{
		{"DEXG002", "Material de clave privada en el árbol", privateKeyRE},
		{"DEXG003", "Posible credencial AWS embebida", awsKeyRE},
		{"DEXG004", "Posible token GitHub embebido", githubTokenRE},
		{"DEXG005", "Posible token Slack embebido", slackTokenRE},
		{"DEXG006", "Posible clave Stripe de producción embebida", stripeKeyRE},
	}
	for _, pattern := range patterns {
		for _, match := range matchesByLine(text, pattern.re) {
			verdict := audit.VerdictNeedsValidation
			blocker := "Confirmar que el valor está versionado/distribuido y sigue siendo una credencial válida."
			if file.IsTest {
				verdict = audit.VerdictHardening
				blocker = ""
			}
			findings = append(findings, finding(file, match.line, pattern.rule, "Cryptography and secrets", verdict, "", audit.ConfidenceHigh,
				pattern.title,
				"Se detectó una forma de credencial de alta señal en texto fuente. DexAuditor no intenta usarla ni comprobarla contra servicios externos.",
				redact(match.value),
				"Elimina secretos del código, usa un almacén de secretos o variables de entorno y rota cualquier credencial que haya sido compartida.",
				blocker))
		}
	}

	for _, match := range matchesByLine(text, genericSecretRE) {
		value := genericSecretValue(match.value)
		if !looksLikeRealSecret(value) {
			continue
		}
		verdict := audit.VerdictNeedsValidation
		blocker := "Confirmar que el literal es una credencial real, está versionado/distribuido y permanece activo."
		if file.IsTest {
			verdict = audit.VerdictHardening
			blocker = ""
		}
		findings = append(findings, finding(file, match.line, "DEXG007", "Cryptography and secrets", verdict, "", audit.ConfidenceMedium,
			"Literal con nombre sensible y valor de alta entropía aparente",
			"Un nombre asociado a credenciales contiene un literal largo no reconocido como placeholder. La señal requiere contexto antes de tratarse como secreto real.",
			redact(match.value),
			"Mueve credenciales reales fuera del código y usa valores ficticios inequívocos en ejemplos y pruebas.",
			blocker))
	}
	return findings
}

func scanSecurityTODOs(file audit.File, text string) []audit.Finding {
	ext := strings.ToLower(filepath.Ext(file.Path))
	if ext == ".go" || ext == ".md" || ext == ".txt" {
		return nil
	}
	findings := make([]audit.Finding, 0)
	for _, match := range matchesByLine(text, securityTODORE) {
		if !looksLikeCommentLine(match.value) {
			continue
		}
		findings = append(findings, finding(file, match.line, "DEXG008", "Obvious things", audit.VerdictHardening, "", audit.ConfidenceMedium,
			"Comentario pendiente relacionado con seguridad",
			"Existe un TODO/FIXME/HACK/XXX que menciona un control de seguridad. No se eleva a vulnerabilidad sin una ruta de impacto.",
			strings.TrimSpace(match.value),
			"Resuelve el pendiente o documenta por qué el control actual es suficiente y agrega una prueba de regresión si corresponde.",
			""))
	}
	return findings
}

func scanWorkflow(file audit.File, text string) []audit.Finding {
	findings := make([]audit.Finding, 0)
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	for i, line := range lines {
		match := workflowUsesRE.FindStringSubmatch(line)
		if len(match) == 3 {
			ref := strings.Trim(match[2], `"'`)
			if !isImmutableGitRef(ref) {
				findings = append(findings, finding(file, i+1, "DEXG009", "Supply chain and release", audit.VerdictHardening, "", audit.ConfidenceHigh,
					"GitHub Action referenciada por etiqueta o rama mutable",
					"El workflow consume una Action que no está fijada a un SHA completo. Una referencia mutable reduce la vinculación entre revisión y código ejecutado.",
					strings.TrimSpace(line),
					"Fija Actions de terceros a un commit SHA revisado y usa mecanismos automatizados para actualizarlo de forma controlada.",
					""))
			}
		}
		if strings.Contains(strings.ToLower(line), "permissions: write-all") {
			findings = append(findings, finding(file, i+1, "DEXG010", "Supply chain and release", audit.VerdictHardening, "", audit.ConfidenceHigh,
				"Workflow con permisos globales de escritura",
				"`permissions: write-all` amplía la autoridad del token de automatización. Por sí solo es hardening; el impacto depende del código y del evento que use esa identidad.",
				strings.TrimSpace(line),
				"Declara permisos mínimos por workflow o job y concede escritura solo al paso que realmente la necesita.",
				""))
		}
		if workflowUnsafeExprRE.MatchString(line) {
			findings = append(findings, finding(file, i+1, "DEXG011", "Supply chain and release", audit.VerdictNeedsValidation, "", audit.ConfidenceMedium,
				"Expresión de evento potencialmente inyectada en comando de workflow",
				"Un campo controlable por eventos aparece en el workflow. Si termina interpolado directamente en un shell privilegiado, puede alterar el comando ejecutado.",
				strings.TrimSpace(line),
				"Pasa datos no confiables mediante variables de entorno/argumentos correctamente citados o evita interpolarlos en `run`.",
				"Confirmar que esta expresión alcanza un bloque `run`/shell y qué permisos o secretos tiene ese job."))
		}
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "pull_request_target:") && strings.Contains(lower, "actions/checkout") && strings.Contains(lower, "github.event.pull_request.head") {
		line := lineOf(text, "pull_request_target:")
		findings = append(findings, finding(file, line, "DEXG012", "Supply chain and release", audit.VerdictNeedsValidation, "", audit.ConfidenceHigh,
			"Código de pull request puede mezclarse con contexto `pull_request_target`",
			"El mismo workflow usa `pull_request_target`, checkout y referencias al head del pull request. Esa combinación puede cruzar código no confiable con una identidad de workflow más privilegiada.",
			"pull_request_target + actions/checkout + github.event.pull_request.head",
			"Evita ejecutar código del PR en `pull_request_target`; separa validación no confiable de jobs con secretos/escritura y vincula artefactos por identidad inmutable.",
			"Confirmar el `ref` realmente checkout, los pasos ejecutados después y los permisos/secretos disponibles."))
	}
	return findings
}

func scanDockerfile(file audit.File, text string) []audit.Finding {
	findings := make([]audit.Finding, 0)
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	lastFrom := -1
	lastUser := -1
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "FROM ") {
			lastFrom = i
			lastUser = -1
		}
		if lastFrom >= 0 && strings.HasPrefix(upper, "USER ") {
			lastUser = i
		}
		if match := dockerSecretRE.FindStringSubmatch(line); len(match) == 3 && looksLikeRealSecret(strings.Trim(match[2], `"'`)) {
			findings = append(findings, finding(file, i+1, "DEXG013", "Cloud and deployment", audit.VerdictNeedsValidation, "", audit.ConfidenceMedium,
				"Posible secreto definido durante build de imagen",
				"Un ARG/ENV con nombre sensible contiene un valor literal. Dependiendo del mecanismo, puede quedar en capas, metadatos o configuración final.",
				redact(strings.TrimSpace(line)),
				"Inyecta secretos en runtime o usa secret mounts del builder; no los declares como valores persistentes de ARG/ENV.",
				"Confirmar si el valor es real y si llega a capas, historial o configuración distribuida de la imagen."))
		}
		if curlPipeShellRE.MatchString(line) {
			findings = append(findings, finding(file, i+1, "DEXG014", "Supply chain and release", audit.VerdictHardening, "", audit.ConfidenceHigh,
				"Descarga remota ejecutada directamente durante build",
				"El build canaliza contenido descargado directamente a un intérprete. La integridad del artefacto depende del origen remoto y de referencias potencialmente mutables.",
				strings.TrimSpace(line),
				"Descarga un artefacto versionado, verifica un hash/firma desde una raíz de confianza independiente y ejecútalo solo después de validar integridad.",
				""))
		}
	}
	if lastFrom >= 0 && lastUser < lastFrom {
		findings = append(findings, finding(file, lastFrom+1, "DEXG015", "Cloud and deployment", audit.VerdictHardening, "", audit.ConfidenceHigh,
			"Etapa final de contenedor sin usuario explícito",
			"La etapa final no contiene una instrucción USER posterior al último FROM, por lo que el runtime normalmente conserva el usuario predeterminado de la imagen base.",
			strings.TrimSpace(lines[lastFrom]),
			"Crea/selecciona un usuario no root en la etapa final salvo que el proceso necesite privilegios y estén justificados.",
			""))
	}
	return findings
}

func scanCurlPipeShell(file audit.File, text string) []audit.Finding {
	findings := make([]audit.Finding, 0)
	for _, match := range matchesByLine(text, curlPipeShellRE) {
		findings = append(findings, finding(file, match.line, "DEXG016", "Supply chain and release", audit.VerdictHardening, "", audit.ConfidenceHigh,
			"Contenido remoto canalizado directamente a un intérprete",
			"Un script descarga contenido y lo ejecuta inmediatamente. Esto dificulta fijar y revisar exactamente qué bytes se ejecutarán.",
			strings.TrimSpace(match.value),
			"Descarga una versión inmutable, valida integridad y ejecuta el archivo verificado como un paso separado.",
			""))
	}
	return findings
}

type lineMatch struct {
	line  int
	value string
}

func matchesByLine(text string, re *regexp.Regexp) []lineMatch {
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	matches := make([]lineMatch, 0)
	line := 0
	for scanner.Scan() {
		line++
		value := scanner.Text()
		if re.MatchString(value) {
			matches = append(matches, lineMatch{line: line, value: value})
		}
	}
	return matches
}

func finding(file audit.File, line int, rule, class string, verdict audit.Verdict, severity audit.Severity, confidence audit.Confidence, title, description, evidence, remediation, blocker string) audit.Finding {
	return audit.Finding{
		RuleID:      rule,
		Analyzer:    analyzerName,
		AttackClass: class,
		Verdict:     verdict,
		Severity:    severity,
		Confidence:  confidence,
		Title:       title,
		Description: description,
		Location:    audit.Location{Path: file.Path, Line: line},
		Evidence:    evidence,
		Remediation: remediation,
		Blocker:     blocker,
	}
}

func isTextCandidate(path string) bool {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(lower)
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || base == "go.mod" || base == "go.sum" || base == ".gitignore" || strings.HasPrefix(base, ".env") {
		return true
	}
	switch filepath.Ext(base) {
	case ".go", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rs", ".java", ".kt", ".kts", ".php", ".rb", ".cs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".sh", ".bash", ".zsh", ".ps1", ".yaml", ".yml", ".json", ".toml", ".xml", ".ini", ".conf", ".cfg", ".properties", ".md", ".txt":
		return true
	default:
		return false
	}
}

func looksBinary(data []byte) bool {
	limit := len(data)
	if limit > 8192 {
		limit = 8192
	}
	for _, b := range data[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}

func isGitHubWorkflow(path string) bool {
	return strings.HasPrefix(path, ".github/workflows/") && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml"))
}

func isDockerfile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.")
}

func isShellLike(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".bash", ".zsh", ".ps1":
		return true
	default:
		return false
	}
}

func isImmutableGitRef(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for _, r := range ref {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func looksLikeRealSecret(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if len(value) < 16 {
		return false
	}
	lower := strings.ToLower(value)
	placeholders := []string{"example", "sample", "dummy", "changeme", "change-me", "your_", "your-", "replace", "placeholder", "not-a-real", "fake", "testtest", "xxxx", "${", "{{"}
	for _, placeholder := range placeholders {
		if strings.Contains(lower, placeholder) {
			return false
		}
	}
	unique := make(map[rune]struct{})
	for _, r := range value {
		unique[r] = struct{}{}
	}
	return len(unique) >= 8
}

func genericSecretValue(line string) string {
	match := genericSecretRE.FindStringSubmatch(line)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}

func redact(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 12 {
		return "[redacted]"
	}
	return value[:6] + "…[redacted]…" + value[len(value)-4:]
}

func looksLikeCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "<!--") ||
		strings.HasPrefix(trimmed, ";")
}

func lineOf(text, needle string) int {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	needle = strings.ToLower(needle)
	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), needle) {
			return i + 1
		}
	}
	return 1
}
