package jsaudit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"

	"github.com/YahirHub/dexauditor/internal/audit"
)

const analyzerName = "javascript-typescript"

type Analyzer struct{}

func New() Analyzer { return Analyzer{} }

func (Analyzer) Name() string { return analyzerName }

func (Analyzer) Applies(project audit.Project) bool {
	return project.Languages["javascript"] > 0 || project.Languages["typescript"] > 0
}

type sourceToken struct {
	typ    js.TokenType
	text   string
	line   int
	column int
}

type childProcessBindings struct {
	direct     map[string]string
	namespaces map[string]struct{}
}

func (Analyzer) Analyze(ctx context.Context, project audit.Project, emit audit.EmitFunc) (audit.AnalysisResult, error) {
	if emit == nil {
		emit = func(audit.Event) {}
	}
	result := audit.AnalysisResult{}
	files := 0
	lexicalErrors := 0

	for _, file := range project.Files {
		if !isJavaScriptTypeScript(file.Ext) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return audit.AnalysisResult{}, err
		}
		source, err := os.ReadFile(file.AbsPath)
		if err != nil {
			emit(audit.Event{Type: audit.EventWarning, Phase: "analysis", Analyzer: analyzerName, Message: fmt.Sprintf("no se pudo leer %s: %v", file.Path, err)})
			continue
		}
		files++
		tokens, tokenErrors := tokenizeFile(source, file.Ext)
		lexicalErrors += tokenErrors
		if file.IsTest {
			continue
		}
		result.Findings = append(result.Findings, scanFile(file, tokens)...)
	}

	detail := fmt.Sprintf("%d archivos JavaScript/TypeScript tokenizados; análisis léxico conservador de sinks conocidos, sin type-checking ni dataflow interprocedural", files)
	if lexicalErrors > 0 {
		detail = fmt.Sprintf("%d archivos JavaScript/TypeScript tokenizados con %d errores léxicos recuperables; cobertura parcial sin type-checking", files, lexicalErrors)
	}
	for _, class := range []string{"Injection", "Cryptography and secrets", "Client-side and rendering"} {
		result.Coverage = append(result.Coverage, audit.Coverage{Analyzer: analyzerName, AttackClass: class, Status: "partial", Detail: detail, Files: files})
	}
	for _, class := range []string{"Access control", "Business logic", "Resource and file handling", "Resource exhaustion and availability", "Chained vulnerabilities and trust boundaries"} {
		result.Coverage = append(result.Coverage, audit.Coverage{
			Analyzer: analyzerName, AttackClass: class, Status: "not_automated",
			Detail: "la V1 no automatiza esta clase para JavaScript/TypeScript; requiere análisis semántico, de flujo o de fronteras de confianza",
			Files:  files,
		})
	}
	return result, nil
}

func isJavaScriptTypeScript(ext string) bool {
	switch strings.ToLower(ext) {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx":
		return true
	default:
		return false
	}
}

func tokenize(source []byte) ([]sourceToken, int) {
	return tokenizeMode(source, false)
}

func tokenizeFile(source []byte, ext string) ([]sourceToken, int) {
	jsxText := strings.EqualFold(ext, ".jsx") || strings.EqualFold(ext, ".tsx")
	return tokenizeMode(source, jsxText)
}

func tokenizeMode(source []byte, jsxText bool) ([]sourceToken, int) {
	if len(source) >= 2 && source[0] == '#' && source[1] == '!' {
		normalized := append([]byte(nil), source...)
		for i := 0; i < len(normalized) && normalized[i] != '\r' && normalized[i] != '\n'; i++ {
			normalized[i] = ' '
		}
		source = normalized
	}
	lexer := js.NewLexer(parse.NewInputBytes(source))
	tokens := make([]sourceToken, 0, len(source)/5)
	line, column := 1, 1
	errorsSeen := 0
	var previous sourceToken
	hasPrevious := false

	for {
		tt, raw := lexer.Next()
		if (tt == js.DivToken || tt == js.DivEqToken) && regexCanStartAfter(previous, hasPrevious) {
			tt, raw = lexer.RegExp()
		}
		text := string(raw)
		startLine, startColumn := line, column
		advancePosition(text, &line, &column)

		if tt == js.ErrorToken {
			if errors.Is(lexer.Err(), io.EOF) {
				break
			}
			if !(jsxText && len(raw) > 0) {
				errorsSeen++
			}
			if len(raw) == 0 {
				break
			}
			continue
		}
		if isTrivia(tt) {
			continue
		}
		token := sourceToken{typ: tt, text: text, line: startLine, column: startColumn}
		tokens = append(tokens, token)
		previous, hasPrevious = token, true
	}
	return tokens, errorsSeen
}

func regexCanStartAfter(previous sourceToken, hasPrevious bool) bool {
	if !hasPrevious {
		return true
	}
	switch previous.text {
	case "(", "[", "{", ",", ":", ";", "=", "==", "===", "!=", "!==", "!", "&&", "||", "??", "?", "=>",
		"+", "-", "*", "%", "&", "|", "^", "~", "<=", ">=", "<<", ">>", ">>>", "**",
		"+=", "-=", "*=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=", "**=", "&&=", "||=", "??=",
		"return", "throw", "case", "delete", "void", "typeof", "instanceof", "in", "of", "yield", "await":
		return true
	default:
		return false
	}
}

func advancePosition(text string, line, column *int) {
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\r':
			(*line)++
			*column = 1
			if i+1 < len(text) && text[i+1] == '\n' {
				i++
			}
		case '\n':
			(*line)++
			*column = 1
		default:
			(*column)++
		}
	}
}

func isTrivia(tt js.TokenType) bool {
	return tt == js.WhitespaceToken || tt == js.LineTerminatorToken || tt == js.CommentToken || tt == js.CommentLineTerminatorToken
}

func scanFile(file audit.File, tokens []sourceToken) []audit.Finding {
	findings := make([]audit.Finding, 0)
	bindings := collectChildProcessBindings(tokens)

	for i := range tokens {
		if finding, ok := tlsFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := shellFinding(file, tokens, i, bindings); ok {
			findings = append(findings, finding)
		}
		if finding, ok := dynamicCodeFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := htmlFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := weakRandomFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
	}
	return findings
}

func tlsFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if tokens[i].text == "rejectUnauthorized" && tokenText(tokens, i+1) != "" && !insideTypeOnlyObject(tokens, i) {
		j := i + 1
		if tokenText(tokens, j) == "?" {
			j++
		}
		if (tokenText(tokens, j) == ":" || tokenText(tokens, j) == "=") && tokenText(tokens, j+1) == "false" {
			return jsFinding(file, tokens[i], "DEXJS001", "Cryptography and secrets", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
				"Verificación TLS deshabilitada explícitamente",
				"La configuración establece `rejectUnauthorized: false`, lo que puede aceptar certificados no confiables cuando alcanza un cliente TLS/HTTPS real.",
				"Mantén la verificación TLS habilitada y configura CA/nombre esperado de forma explícita cuando uses certificados privados.",
				"Confirmar qué cliente consume esta configuración y si la conexión cruza una frontera de confianza.",
				"rejectUnauthorized: false"), true
		}
	}
	if tokens[i].text == "NODE_TLS_REJECT_UNAUTHORIZED" && tokenText(tokens, i+1) == "=" && isZeroLiteral(tokenAt(tokens, i+2)) {
		return jsFinding(file, tokens[i], "DEXJS001", "Cryptography and secrets", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
			"Verificación TLS global deshabilitada explícitamente",
			"El código asigna `NODE_TLS_REJECT_UNAUTHORIZED=0`, deshabilitando la validación TLS estándar para conexiones Node.js afectadas por ese proceso.",
			"Elimina esta configuración y configura confianza de certificados por cliente o mediante CA explícita.",
			"Confirmar si esta asignación se ejecuta en un entorno real y qué conexiones quedan afectadas.",
			"NODE_TLS_REJECT_UNAUTHORIZED = 0"), true
	}
	return audit.Finding{}, false
}

func insideTypeOnlyObject(tokens []sourceToken, index int) bool {
	depth := 0
	for i := index - 1; i >= 0; i-- {
		switch tokens[i].text {
		case "}":
			depth++
		case "{":
			if depth > 0 {
				depth--
				continue
			}
			return braceStartsTypeDeclaration(tokens, i)
		}
	}
	return false
}

func braceStartsTypeDeclaration(tokens []sourceToken, openBrace int) bool {
	start := openBrace - 32
	if start < 0 {
		start = 0
	}
	seenAssignment := false
	for i := openBrace - 1; i >= start; i-- {
		switch tokens[i].text {
		case "=":
			seenAssignment = true
		case "interface":
			return true
		case "type":
			return seenAssignment
		case ";", "}", "{":
			return false
		}
	}
	return false
}

func shellFinding(file audit.File, tokens []sourceToken, i int, bindings childProcessBindings) (audit.Finding, bool) {
	if i > 0 && tokens[i-1].text == "/" {
		return audit.Finding{}, false
	}
	name, openParen, ok := childProcessCall(tokens, i, bindings)
	if !ok || (name != "exec" && name != "execSync") {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, openParen, 0)
	if !ok || isSafeShellCommandExpression(expr) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS002", "Injection", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"Comando de shell construido dinámicamente",
		"Una llamada importada desde `child_process` usa `exec`/`execSync` con un argumento que no es una cadena estática demostrable. Si incorpora entrada de menor confianza, el shell puede interpretar metacaracteres.",
		"Evita el shell para datos variables; usa `spawn`/`execFile` con argumentos separados o aplica una allowlist estricta cuando el shell sea indispensable.",
		"Trazar el primer argumento hasta su origen y confirmar si un principal de menor confianza puede influirlo.",
		name+"(dynamic command)"), true
}

func dynamicCodeFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if i > 0 && tokens[i-1].text == "/" {
		return audit.Finding{}, false
	}
	name := ""
	openParen := -1
	anchor := tokens[i]
	if tokens[i].text == "eval" && tokenText(tokens, i+1) == "(" {
		name, openParen = "eval", i+1
	} else if tokens[i].text == "new" && tokenText(tokens, i+1) == "Function" && tokenText(tokens, i+2) == "(" {
		name, openParen = "new Function", i+2
	} else {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, openParen, 0)
	if !ok {
		return audit.Finding{}, false
	}
	if isStaticStringExpression(expr) {
		return jsFinding(file, anchor, "DEXJS003", "Injection", audit.VerdictHardening, audit.ConfidenceMedium,
			"Evaluación explícita de código mediante cadena estática",
			"El código usa `eval` o `Function` con una cadena estática. No demuestra inyección, pero mantiene una primitiva de ejecución dinámica que amplía la superficie de ataque y dificulta CSP/auditoría.",
			"Prefiere código normal, tablas de funciones o parsers específicos en lugar de evaluación dinámica.", "",
			name+"(static code)"), true
	}
	return jsFinding(file, anchor, "DEXJS003", "Injection", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"Evaluación dinámica de código",
		"El código usa `eval` o `Function` con una expresión no estática. Si la expresión contiene entrada controlable, puede convertirse en ejecución arbitraria de código JavaScript.",
		"Elimina la evaluación dinámica o limita la entrada a una representación de datos que se procese con un parser seguro.",
		"Trazar la expresión evaluada y confirmar si puede contener datos de menor confianza.",
		name+"(dynamic code)"), true
}

func htmlFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	name := tokens[i].text
	if (name == "innerHTML" || name == "outerHTML") && tokenText(tokens, i+1) == "=" {
		if expressionStartsStatic(tokens, i+2) {
			return audit.Finding{}, false
		}
		return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
			"HTML dinámico asignado a un sink del DOM",
			"Se asigna una expresión dinámica a `innerHTML`/`outerHTML`. Si contiene texto no confiable sin sanitización compatible con HTML, puede introducir XSS.",
			"Prefiere `textContent`/DOM APIs. Si necesitas HTML, sanitiza con una política explícita y revisada antes del sink.",
			"Confirmar el origen del valor y si existe sanitización HTML efectiva antes de esta asignación.",
			name+" = dynamic HTML"), true
	}
	if name == "insertAdjacentHTML" && tokenText(tokens, i+1) == "(" {
		expr, ok := argument(tokens, i+1, 1)
		if !ok || isStaticStringExpression(expr) {
			return audit.Finding{}, false
		}
		return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
			"HTML dinámico enviado a `insertAdjacentHTML`",
			"El segundo argumento de `insertAdjacentHTML` no es una cadena estática demostrable. Contenido no confiable puede interpretarse como HTML ejecutable.",
			"Construye nodos con DOM APIs o sanitiza el HTML con una política explícita antes de insertarlo.",
			"Confirmar el origen del segundo argumento y la sanitización aplicada.",
			"insertAdjacentHTML(..., dynamic HTML)"), true
	}
	if name == "document" && tokenText(tokens, i+1) == "." && tokenText(tokens, i+2) == "write" && tokenText(tokens, i+3) == "(" {
		expr, ok := argument(tokens, i+3, 0)
		if !ok || isStaticStringExpression(expr) {
			return audit.Finding{}, false
		}
		return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
			"Contenido dinámico enviado a `document.write`",
			"`document.write` recibe una expresión dinámica que puede convertirse en HTML/script si contiene entrada no confiable.",
			"Evita `document.write`; usa DOM APIs y trata texto no confiable como texto, no como markup.",
			"Confirmar el origen del argumento y si puede contener contenido controlado externamente.",
			"document.write(dynamic HTML)"), true
	}
	if name == "dangerouslySetInnerHTML" {
		for j := i + 1; j < len(tokens) && j <= i+16; j++ {
			if tokens[j].text != "__html" || tokenText(tokens, j+1) != ":" {
				continue
			}
			if expressionStartsStatic(tokens, j+2) {
				return audit.Finding{}, false
			}
			return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
				"HTML dinámico enviado a `dangerouslySetInnerHTML`",
				"La propiedad React `dangerouslySetInnerHTML` recibe una expresión dinámica. Si no está sanitizada para HTML, puede introducir XSS.",
				"Evita HTML crudo cuando sea posible; en caso contrario aplica un sanitizador explícito antes de `__html`.",
				"Confirmar el origen de `__html` y si existe una sanitización HTML efectiva.",
				"dangerouslySetInnerHTML={{__html: dynamic HTML}}"), true
		}
	}
	return audit.Finding{}, false
}

func weakRandomFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if !sensitiveJSName(tokens[i].text) {
		return audit.Finding{}, false
	}
	assign := -1
	for j := i + 1; j < len(tokens) && j <= i+10; j++ {
		if tokens[j].line > tokens[i].line+1 || tokens[j].text == ";" || tokens[j].text == "," {
			break
		}
		if tokens[j].text == "=" {
			assign = j
			break
		}
	}
	if assign < 0 {
		return audit.Finding{}, false
	}
	for j := assign + 1; j+3 < len(tokens) && j <= assign+18; j++ {
		if tokens[j].text == ";" || (tokens[j].text == "," && tokens[j].line == tokens[i].line) {
			break
		}
		if tokens[j].text == "Math" && tokenText(tokens, j+1) == "." && tokenText(tokens, j+2) == "random" && tokenText(tokens, j+3) == "(" {
			return jsFinding(file, tokens[i], "DEXJS005", "Cryptography and secrets", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
				"`Math.random` usado para un valor con nombre sensible",
				"Un valor con semántica aparente de token/secreto/nonce/sesión se deriva de `Math.random`, que no es un generador criptográficamente seguro.",
				"Usa `crypto.randomBytes`, `crypto.randomUUID` o Web Crypto `crypto.getRandomValues` según el entorno.",
				"Confirmar que el valor se usa como credencial, identificador impredecible, nonce u otro control de seguridad.",
				tokens[i].text+" = Math.random(...)"), true
		}
	}
	return audit.Finding{}, false
}

func collectChildProcessBindings(tokens []sourceToken) childProcessBindings {
	bindings := childProcessBindings{direct: map[string]string{}, namespaces: map[string]struct{}{}}
	for i := 0; i < len(tokens); i++ {
		if tokens[i].text == "import" {
			collectESImport(tokens, i, &bindings)
		}
		if tokens[i].text == "require" && tokenText(tokens, i+1) == "(" && isChildProcessModule(tokenText(tokens, i+2)) {
			collectRequireBinding(tokens, i, &bindings)
		}
	}
	return bindings
}

func collectESImport(tokens []sourceToken, start int, bindings *childProcessBindings) {
	from := -1
	source := -1
	limit := start + 40
	if limit > len(tokens) {
		limit = len(tokens)
	}
	for i := start + 1; i < limit; i++ {
		if tokens[i].text == ";" || tokens[i].text == "export" || tokens[i].text == "import" {
			break
		}
		if tokens[i].text == "from" && i+1 < len(tokens) {
			from, source = i, i+1
			break
		}
	}
	if from < 0 || source >= len(tokens) || !isChildProcessModule(tokens[source].text) {
		return
	}
	if start+3 < from && tokenText(tokens, start+1) == "*" && tokenText(tokens, start+2) == "as" {
		bindings.namespaces[tokenText(tokens, start+3)] = struct{}{}
		return
	}
	if tokenText(tokens, start+1) == "{" {
		for i := start + 2; i < from && tokens[i].text != "}"; i++ {
			if tokens[i].text == "," {
				continue
			}
			imported := tokens[i].text
			local := imported
			if tokenText(tokens, i+1) == "as" && i+2 < from {
				local = tokenText(tokens, i+2)
				i += 2
			}
			if imported == "exec" || imported == "execSync" {
				bindings.direct[local] = imported
			}
		}
		return
	}
	if start+1 < from {
		bindings.namespaces[tokenText(tokens, start+1)] = struct{}{}
	}
}

func collectRequireBinding(tokens []sourceToken, requireIndex int, bindings *childProcessBindings) {
	if requireIndex < 2 || tokenText(tokens, requireIndex-1) != "=" {
		return
	}
	eq := requireIndex - 1
	if eq >= 2 && isVariableKeyword(tokenText(tokens, eq-2)) {
		bindings.namespaces[tokenText(tokens, eq-1)] = struct{}{}
		return
	}
	if eq < 2 || tokenText(tokens, eq-1) != "}" {
		return
	}
	open := eq - 2
	for open >= 0 && tokens[open].text != "{" {
		open--
	}
	if open <= 0 || !isVariableKeyword(tokenText(tokens, open-1)) {
		return
	}
	for i := open + 1; i < eq-1; i++ {
		if tokens[i].text == "," {
			continue
		}
		imported := tokens[i].text
		local := imported
		if tokenText(tokens, i+1) == ":" && i+2 < eq-1 {
			local = tokenText(tokens, i+2)
			i += 2
		}
		if imported == "exec" || imported == "execSync" {
			bindings.direct[local] = imported
		}
	}
}

func childProcessCall(tokens []sourceToken, i int, bindings childProcessBindings) (string, int, bool) {
	if canonical, ok := bindings.direct[tokens[i].text]; ok && tokenText(tokens, i+1) == "(" {
		return canonical, i + 1, true
	}
	if _, ok := bindings.namespaces[tokens[i].text]; ok && tokenText(tokens, i+1) == "." {
		method := tokenText(tokens, i+2)
		if (method == "exec" || method == "execSync") && tokenText(tokens, i+3) == "(" {
			return method, i + 3, true
		}
	}
	return "", -1, false
}

func argument(tokens []sourceToken, openParen, wanted int) ([]sourceToken, bool) {
	if openParen < 0 || openParen >= len(tokens) || tokens[openParen].text != "(" {
		return nil, false
	}
	current := 0
	start := openParen + 1
	paren, brace, bracket, template := 1, 0, 0, 0
	for i := openParen + 1; i < len(tokens); i++ {
		t := tokens[i]
		if t.typ == js.TemplateStartToken {
			template++
		} else if t.typ == js.TemplateEndToken && template > 0 {
			template--
		}
		if template == 0 {
			switch t.text {
			case "(":
				paren++
			case ")":
				if paren == 1 && brace == 0 && bracket == 0 {
					if current == wanted && start < i {
						return tokens[start:i], true
					}
					return nil, false
				}
				paren--
			case "{":
				brace++
			case "}":
				if brace > 0 {
					brace--
				}
			case "[":
				bracket++
			case "]":
				if bracket > 0 {
					bracket--
				}
			case ",":
				if paren == 1 && brace == 0 && bracket == 0 {
					if current == wanted {
						if start < i {
							return tokens[start:i], true
						}
						return nil, false
					}
					current++
					start = i + 1
				}
			}
		}
	}
	return nil, false
}

func isStaticStringExpression(tokens []sourceToken) bool {
	if len(tokens) == 0 {
		return false
	}
	seenString := false
	for _, token := range tokens {
		if token.typ == js.TemplateStartToken || token.typ == js.TemplateMiddleToken || token.typ == js.TemplateEndToken {
			return false
		}
		if token.typ == js.StringToken || token.typ == js.TemplateToken {
			seenString = true
			continue
		}
		switch token.text {
		case "+", "(", ")":
			continue
		default:
			return false
		}
	}
	return seenString
}

func isSafeShellCommandExpression(tokens []sourceToken) bool {
	if isStaticStringExpression(tokens) {
		return true
	}
	if len(tokens) < 5 || tokens[0].typ != js.TemplateStartToken || tokens[len(tokens)-1].typ != js.TemplateEndToken {
		return false
	}

	start := 1
	for i := 1; i < len(tokens); i++ {
		if tokens[i].typ != js.TemplateMiddleToken && tokens[i].typ != js.TemplateEndToken {
			continue
		}
		if !isProcessIDExpression(tokens[start:i]) {
			return false
		}
		if tokens[i].typ == js.TemplateEndToken {
			return i == len(tokens)-1
		}
		start = i + 1
	}
	return false
}

func isProcessIDExpression(tokens []sourceToken) bool {
	return len(tokens) == 3 &&
		tokens[0].text == "process" &&
		tokens[1].text == "." &&
		(tokens[2].text == "pid" || tokens[2].text == "ppid")
}

func expressionStartsStatic(tokens []sourceToken, i int) bool {
	if i < 0 || i >= len(tokens) {
		return false
	}
	return tokens[i].typ == js.StringToken || tokens[i].typ == js.TemplateToken || tokens[i].text == "null" || tokens[i].text == "undefined"
}

func sensitiveJSName(name string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", "$", "").Replace(name))
	for _, suffix := range []string{"count", "ttl", "timeout", "duration", "window", "limit", "attempts", "method", "type", "name", "path", "file", "enabled", "present", "length"} {
		if strings.HasSuffix(normalized, suffix) {
			return false
		}
	}
	for _, part := range []string{"password", "passwd", "secret", "token", "nonce", "session", "credential", "apikey", "otp", "authcode", "csrf"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	return false
}

func isVariableKeyword(value string) bool {
	return value == "const" || value == "let" || value == "var"
}

func isChildProcessModule(raw string) bool {
	value := stripJSString(raw)
	return value == "child_process" || value == "node:child_process"
}

func stripJSString(value string) string {
	if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
		return value[1 : len(value)-1]
	}
	return value
}

func isZeroLiteral(token sourceToken) bool {
	if token.text == "0" {
		return true
	}
	return stripJSString(token.text) == "0" && (token.typ == js.StringToken || token.typ == js.TemplateToken)
}

func tokenAt(tokens []sourceToken, i int) sourceToken {
	if i < 0 || i >= len(tokens) {
		return sourceToken{}
	}
	return tokens[i]
}

func tokenText(tokens []sourceToken, i int) string { return tokenAt(tokens, i).text }

func jsFinding(file audit.File, token sourceToken, rule, class string, verdict audit.Verdict, confidence audit.Confidence, title, description, remediation, blocker, evidence string) audit.Finding {
	return audit.Finding{
		RuleID: rule, Analyzer: analyzerName, AttackClass: class, Verdict: verdict, Confidence: confidence,
		Title: title, Description: description,
		Location: audit.Location{Path: filepath.ToSlash(file.Path), Line: token.line, Column: token.column},
		Evidence: evidence, Remediation: remediation, Blocker: blocker,
	}
}
