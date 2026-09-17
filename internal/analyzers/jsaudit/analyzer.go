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
	for _, class := range []string{"Injection", "Cryptography and secrets", "Client-side and rendering", "Resource and file handling"} {
		result.Coverage = append(result.Coverage, audit.Coverage{Analyzer: analyzerName, AttackClass: class, Status: "partial", Detail: detail, Files: files})
	}
	for _, class := range []string{"Access control", "Business logic", "Resource exhaustion and availability", "Chained vulnerabilities and trust boundaries"} {
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
	fsBindings := collectAPIBindings(tokens, []string{"fs", "node:fs", "fs/promises", "node:fs/promises"}, []string{
		"readFile", "readFileSync", "writeFile", "writeFileSync", "open", "openSync", "rm", "rmSync", "unlink", "unlinkSync",
		"mkdir", "mkdirSync", "rmdir", "rmdirSync", "rename", "renameSync", "createReadStream", "createWriteStream", "readdirSync",
	})
	pathBindings := collectAPIBindings(tokens, []string{"path", "node:path"}, []string{"join", "resolve"})
	httpBindings := collectAPIBindings(tokens, []string{"http", "node:http", "https", "node:https"}, []string{"get", "request"})
	vmBindings := collectAPIBindings(tokens, []string{"vm", "node:vm"}, []string{"runInContext", "runInNewContext", "runInThisContext", "compileFunction", "Script"})
	processBindings := collectAPIBindings(tokens, []string{"child_process", "node:child_process"}, []string{"execFile", "execFileSync", "spawn", "spawnSync"})
	pathTrust := collectJSPathTrust(tokens, fsBindings)
	htmlSanitizers := collectHTMLSanitizers(tokens)

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
		if finding, ok := htmlFinding(file, tokens, i, htmlSanitizers); ok {
			findings = append(findings, finding)
		}
		if finding, ok := weakRandomFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := dynamicSQLFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := filePathFinding(file, tokens, i, fsBindings, pathBindings, pathTrust); ok {
			findings = append(findings, finding)
		}
		if finding, ok := outboundURLFinding(file, tokens, i, httpBindings); ok {
			findings = append(findings, finding)
		}
		if finding, ok := clientNavigationFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := postMessageFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := browserStorageFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := serverRedirectFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := sensitiveJSLoggingFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := dynamicModuleFinding(file, tokens, i); ok {
			findings = append(findings, finding)
		}
		if finding, ok := vmDynamicCodeFinding(file, tokens, i, vmBindings); ok {
			findings = append(findings, finding)
		}
		if finding, ok := dynamicExecutableJSFinding(file, tokens, i, processBindings); ok {
			findings = append(findings, finding)
		}
	}
	findings = append(findings, credentialedJSCORSFindings(file, tokens)...)
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

func collectHTMLSanitizers(tokens []sourceToken) map[string]struct{} {
	result := map[string]struct{}{}
	for i := 0; i < len(tokens); i++ {
		if tokens[i].text == "function" && i+1 < len(tokens) {
			name := tokenText(tokens, i+1)
			open := -1
			for j := i + 2; j < len(tokens) && j <= i+32; j++ {
				if tokens[j].text == "{" {
					open = j
					break
				}
				if tokens[j].text == ";" {
					break
				}
			}
			if open >= 0 {
				close := matchingDelimiter(tokens, open, "{", "}")
				if close > open && looksLikeHTMLEscaper(tokens[open+1:close]) {
					result[name] = struct{}{}
				}
			}
		}
		if tokens[i].text == "const" && i+3 < len(tokens) && tokenText(tokens, i+2) == "=" {
			name := tokenText(tokens, i+1)
			arrow := -1
			for j := i + 3; j < len(tokens) && j <= i+32; j++ {
				if tokens[j].text == "=>" {
					arrow = j
					break
				}
				if tokens[j].text == ";" {
					break
				}
			}
			if arrow < 0 {
				continue
			}
			end := arrow + 1
			if tokenText(tokens, end) == "{" {
				close := matchingDelimiter(tokens, end, "{", "}")
				if close > end && looksLikeHTMLEscaper(tokens[end+1:close]) {
					result[name] = struct{}{}
				}
				continue
			}
			for end < len(tokens) && tokenText(tokens, end) != ";" {
				end++
			}
			if end > arrow+1 && looksLikeHTMLEscaper(tokens[arrow+1:end]) {
				result[name] = struct{}{}
			}
		}
	}
	return result
}

func looksLikeHTMLEscaper(tokens []sourceToken) bool {
	hasReplace := false
	hasPattern := false
	entities := map[string]bool{"&amp;": false, "&lt;": false, "&gt;": false}
	for _, token := range tokens {
		if token.text == "replace" {
			hasReplace = true
		}
		if token.typ == js.RegExpToken && strings.Contains(token.text, "&") && strings.Contains(token.text, "<") && strings.Contains(token.text, ">") {
			hasPattern = true
		}
		value := stripJSString(token.text)
		if _, ok := entities[value]; ok {
			entities[value] = true
		}
	}
	return hasReplace && hasPattern && entities["&amp;"] && entities["&lt;"] && entities["&gt;"]
}

func isSafeHTMLExpression(tokens []sourceToken, sanitizers map[string]struct{}) bool {
	tokens = trimOuterParens(tokens)
	if len(tokens) == 0 {
		return false
	}
	if isStaticStringExpression(tokens) {
		return true
	}
	if isExactSanitizerCall(tokens, sanitizers) {
		return true
	}
	if tokens[0].typ == js.TemplateStartToken {
		start := 1
		for i := 1; i < len(tokens); i++ {
			if tokens[i].typ != js.TemplateMiddleToken && tokens[i].typ != js.TemplateEndToken {
				if tokens[i].typ == js.TemplateStartToken {
					return false
				}
				continue
			}
			if !isSafeHTMLExpression(tokens[start:i], sanitizers) {
				return false
			}
			if tokens[i].typ == js.TemplateEndToken {
				return i == len(tokens)-1
			}
			start = i + 1
		}
		return false
	}
	if question, colon, ok := topLevelTernary(tokens); ok {
		return isSafeHTMLExpression(tokens[question+1:colon], sanitizers) && isSafeHTMLExpression(tokens[colon+1:], sanitizers)
	}
	if parts := splitTopLevel(tokens, "+"); len(parts) > 1 {
		for _, part := range parts {
			if !isSafeHTMLExpression(part, sanitizers) {
				return false
			}
		}
		return true
	}
	return false
}

func isExactSanitizerCall(tokens []sourceToken, sanitizers map[string]struct{}) bool {
	if len(tokens) < 3 || tokenText(tokens, 1) != "(" {
		return false
	}
	if _, ok := sanitizers[tokenText(tokens, 0)]; !ok {
		return false
	}
	return matchingDelimiter(tokens, 1, "(", ")") == len(tokens)-1
}

func trimOuterParens(tokens []sourceToken) []sourceToken {
	for len(tokens) >= 2 && tokenText(tokens, 0) == "(" {
		close := matchingDelimiter(tokens, 0, "(", ")")
		if close != len(tokens)-1 {
			break
		}
		tokens = tokens[1:close]
	}
	return tokens
}

func topLevelTernary(tokens []sourceToken) (int, int, bool) {
	paren, brace, bracket := 0, 0, 0
	question := -1
	ternaryDepth := 0
	for i, token := range tokens {
		switch token.text {
		case "(":
			paren++
		case ")":
			paren--
		case "{":
			brace++
		case "}":
			brace--
		case "[":
			bracket++
		case "]":
			bracket--
		case "?":
			if paren == 0 && brace == 0 && bracket == 0 {
				if question < 0 {
					question = i
				}
				ternaryDepth++
			}
		case ":":
			if paren == 0 && brace == 0 && bracket == 0 && question >= 0 {
				ternaryDepth--
				if ternaryDepth == 0 {
					return question, i, true
				}
			}
		}
	}
	return -1, -1, false
}

func splitTopLevel(tokens []sourceToken, separator string) [][]sourceToken {
	paren, brace, bracket := 0, 0, 0
	start := 0
	parts := make([][]sourceToken, 0, 2)
	for i, token := range tokens {
		switch token.text {
		case "(":
			paren++
		case ")":
			paren--
		case "{":
			brace++
		case "}":
			brace--
		case "[":
			bracket++
		case "]":
			bracket--
		default:
			if token.text == separator && paren == 0 && brace == 0 && bracket == 0 {
				parts = append(parts, tokens[start:i])
				start = i + 1
			}
		}
	}
	if len(parts) == 0 {
		return nil
	}
	parts = append(parts, tokens[start:])
	return parts
}

func htmlFinding(file audit.File, tokens []sourceToken, i int, sanitizers map[string]struct{}) (audit.Finding, bool) {
	name := tokens[i].text
	if (name == "innerHTML" || name == "outerHTML") && tokenText(tokens, i+1) == "=" {
		expr := expressionUntilStatement(tokens, i+2)
		if isSafeHTMLExpression(expr, sanitizers) {
			return audit.Finding{}, false
		}
		verdict, confidence, blocker := htmlRisk(expr)
		return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", verdict, confidence,
			"HTML dinámico asignado a un sink del DOM",
			"Se asigna una expresión dinámica a `innerHTML`/`outerHTML`. DexAuditor solo la mantiene como candidato cuando puede ver una fuente de menor confianza en la misma expresión; en los demás casos es hardening hasta que exista dataflow que demuestre el origen.",
			"Prefiere `textContent`/DOM APIs. Si necesitas HTML, sanitiza con una política explícita y revisada antes del sink.",
			blocker,
			name+" = dynamic HTML"), true
	}
	if name == "insertAdjacentHTML" && tokenText(tokens, i+1) == "(" {
		expr, ok := argument(tokens, i+1, 1)
		if !ok || isSafeHTMLExpression(expr, sanitizers) {
			return audit.Finding{}, false
		}
		verdict, confidence, blocker := htmlRisk(expr)
		return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", verdict, confidence,
			"HTML dinámico enviado a `insertAdjacentHTML`",
			"El segundo argumento de `insertAdjacentHTML` es dinámico. Solo se trata como candidato cuando una fuente de menor confianza es visible en la expresión; sin ese vínculo queda como hardening.",
			"Construye nodos con DOM APIs o sanitiza el HTML con una política explícita antes de insertarlo.",
			blocker,
			"insertAdjacentHTML(..., dynamic HTML)"), true
	}
	if name == "document" && tokenText(tokens, i+1) == "." && tokenText(tokens, i+2) == "write" && tokenText(tokens, i+3) == "(" {
		expr, ok := argument(tokens, i+3, 0)
		if !ok || isSafeHTMLExpression(expr, sanitizers) {
			return audit.Finding{}, false
		}
		verdict, confidence, blocker := htmlRisk(expr)
		return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", verdict, confidence,
			"Contenido dinámico enviado a `document.write`",
			"`document.write` recibe una expresión dinámica. Solo se trata como candidato cuando la expresión contiene una fuente de menor confianza visible; en otro caso es hardening.",
			"Evita `document.write`; usa DOM APIs y trata texto no confiable como texto, no como markup.",
			blocker,
			"document.write(dynamic HTML)"), true
	}
	if name == "dangerouslySetInnerHTML" {
		for j := i + 1; j < len(tokens) && j <= i+16; j++ {
			if tokens[j].text != "__html" || tokenText(tokens, j+1) != ":" {
				continue
			}
			expr := expressionUntilPropertyEnd(tokens, j+2)
			if len(expr) == 0 || isSafeHTMLExpression(expr, sanitizers) {
				return audit.Finding{}, false
			}
			verdict, confidence, blocker := htmlRisk(expr)
			return jsFinding(file, tokens[i], "DEXJS004", "Client-side and rendering", verdict, confidence,
				"HTML dinámico enviado a `dangerouslySetInnerHTML`",
				"La propiedad React `dangerouslySetInnerHTML` recibe una expresión dinámica. DexAuditor solo la conserva como candidato si una fuente de menor confianza es visible en la misma expresión; en los demás casos queda como hardening.",
				"Evita HTML crudo cuando sea posible; en caso contrario aplica un sanitizador explícito antes de `__html`.",
				blocker,
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

func dynamicSQLFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if i == 0 || tokens[i-1].text != "." || tokenText(tokens, i+1) != "(" {
		return audit.Finding{}, false
	}
	method := tokens[i].text
	unsafeMethod := method == "$queryRawUnsafe" || method == "$executeRawUnsafe"
	switch method {
	case "query", "execute", "raw", "whereRaw", "orderByRaw", "$queryRawUnsafe", "$executeRawUnsafe":
	default:
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, i+1, 0)
	if !ok || isStaticStringExpression(expr) {
		return audit.Finding{}, false
	}
	if !unsafeMethod && (!isDynamicJSExpression(expr) || !expressionContainsSQLSyntax(expr)) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS006", "Injection", audit.VerdictNeedsValidation, audit.ConfidenceMedium,
		"Consulta SQL/ORM construida dinámicamente",
		"Una operación con semántica de SQL/ORM recibe una expresión dinámica que contiene sintaxis SQL visible, o usa una API marcada como unsafe. Si datos de menor confianza influyen esa expresión, pueden alterar la consulta.",
		"Usa parámetros/placeholders del driver u ORM. Para identificadores dinámicos, aplica una allowlist cerrada y evita APIs raw/unsafe con datos no confiables.",
		"Trazar la expresión hasta su origen y confirmar que el método pertenece a una API de base de datos y que datos de menor confianza pueden influir la sintaxis.",
		method+"(dynamic SQL)"), true
}

func filePathFinding(file audit.File, tokens []sourceToken, i int, fsBindings, pathBindings apiBindings, trust jsPathTrust) (audit.Finding, bool) {
	method, openParen, ok := apiCall(tokens, i, fsBindings)
	if !ok || method == "readdirSync" {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, openParen, 0)
	if !ok || isStaticStringExpression(expr) {
		return audit.Finding{}, false
	}
	if !expressionContainsLowerTrustSource(expr) && !containsRiskyPathConstruction(expr, pathBindings, trust, i) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS007", "Resource and file handling", audit.VerdictNeedsValidation, audit.ConfidenceMedium,
		"Ruta dinámica alcanza una operación de filesystem",
		"Una operación de `fs` recibe una ruta derivada directamente de una fuente de menor confianza o de `path.join`/`path.resolve` con un componente dinámico no demostrado como confinado.",
		"Valida segmentos contra una allowlist o canonicaliza el destino y verifica que permanezca bajo el root autorizado antes del último acceso confiable.",
		"Confirmar quién controla el componente dinámico y si existe confinamiento/canonicalización efectiva antes de esta operación.",
		method+"(dynamic path)"), true
}

func outboundURLFinding(file audit.File, tokens []sourceToken, i int, httpBindings apiBindings) (audit.Finding, bool) {
	name := ""
	openParen := -1
	if tokens[i].text == "fetch" && tokenText(tokens, i+1) == "(" && (i == 0 || tokens[i-1].text != ".") {
		name, openParen = "fetch", i+1
	} else if method, open, ok := apiCall(tokens, i, httpBindings); ok {
		name, openParen = method, open
	} else {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, openParen, 0)
	if !ok || !expressionContainsLowerTrustSource(expr) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS008", "Resource and file handling", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"URL de salida recibe directamente entrada de menor confianza",
		"Una operación HTTP saliente consume en la misma expresión datos de request, mensaje, argumentos de proceso o URL del navegador. Sin una política de esquema/host/destino, esa ruta puede convertirse en SSRF o navegación hacia recursos no autorizados.",
		"Parsea la URL, limita esquemas y hosts a una allowlist, resuelve y bloquea rangos internos/metadata cuando aplique y revalida redirects antes de conectar.",
		"Confirmar la frontera del dato, la política efectiva de destinos y el comportamiento de redirects/DNS antes de afirmar alcance a un recurso sensible.",
		name+"(lower-trust URL)"), true
}

func clientNavigationFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	name := ""
	var expr []sourceToken
	var ok bool

	if tokens[i].text == "location" && tokenText(tokens, i+1) == "." && (tokenText(tokens, i+2) == "assign" || tokenText(tokens, i+2) == "replace") && tokenText(tokens, i+3) == "(" {
		name = "location." + tokenText(tokens, i+2)
		expr, ok = argument(tokens, i+3, 0)
	} else if tokens[i].text == "window" && tokenText(tokens, i+1) == "." && tokenText(tokens, i+2) == "location" && tokenText(tokens, i+3) == "." && (tokenText(tokens, i+4) == "assign" || tokenText(tokens, i+4) == "replace") && tokenText(tokens, i+5) == "(" {
		name = "window.location." + tokenText(tokens, i+4)
		expr, ok = argument(tokens, i+5, 0)
	} else if tokens[i].text == "window" && tokenText(tokens, i+1) == "." && tokenText(tokens, i+2) == "open" && tokenText(tokens, i+3) == "(" {
		name = "window.open"
		expr, ok = argument(tokens, i+3, 0)
	} else if tokens[i].text == "href" && tokenText(tokens, i+1) == "=" && isLocationHref(tokens, i) {
		name = "location.href"
		expr = expressionUntilStatement(tokens, i+2)
		ok = len(expr) > 0
	} else {
		return audit.Finding{}, false
	}
	if !ok || !expressionContainsLowerTrustSource(expr) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS009", "Client-side and rendering", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"Navegación del navegador controlada por entrada de menor confianza",
		"Un sink de navegación recibe directamente datos procedentes de URL, mensajería o request-like input. Sin restricción de esquema/origen, puede facilitar open redirects, navegación a `javascript:` u otros cambios de contexto inesperados.",
		"Normaliza el destino y limita esquemas/orígenes/rutas a valores explícitamente permitidos antes de navegar.",
		"Confirmar qué principal controla el dato y qué esquemas/orígenes puede producir tras normalización.",
		name+"(lower-trust target)"), true
}

func postMessageFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if tokens[i].text != "postMessage" || tokenText(tokens, i+1) != "(" || i == 0 || tokens[i-1].text != "." {
		return audit.Finding{}, false
	}
	payload, ok := argument(tokens, i+1, 0)
	if !ok || !expressionContainsSensitiveJSToken(payload) {
		return audit.Finding{}, false
	}
	target, ok := argument(tokens, i+1, 1)
	if !ok || len(target) != 1 || stripJSString(target[0].text) != "*" {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS010", "Client-side and rendering", audit.VerdictHardening, audit.ConfidenceHigh,
		"Dato con nombre sensible enviado por `postMessage` a origen comodín",
		"El segundo argumento de `postMessage` es `*` mientras el payload contiene identificadores con semántica de token, secreto, sesión o credencial. El nombre no prueba sensibilidad real, por lo que se mantiene como hardening.",
		"Usa un `targetOrigin` exacto y minimiza/redacta el payload. En el receptor valida también `event.origin` y, cuando importe, `event.source`.",
		"", "postMessage(sensitive value, \"*\")"), true
}

func browserStorageFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if tokens[i].text != "localStorage" && tokens[i].text != "sessionStorage" {
		return audit.Finding{}, false
	}
	if tokenText(tokens, i+1) != "." || tokenText(tokens, i+2) != "setItem" || tokenText(tokens, i+3) != "(" {
		return audit.Finding{}, false
	}
	key, ok := argument(tokens, i+3, 0)
	if !ok || len(key) != 1 || key[0].typ != js.StringToken {
		return audit.Finding{}, false
	}
	keyName := stripJSString(key[0].text)
	if !sensitiveJSName(keyName) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS011", "Cryptography and secrets", audit.VerdictHardening, audit.ConfidenceHigh,
		"Valor con clave sensible almacenado en Web Storage",
		"Una clave con semántica aparente de token, sesión o credencial se guarda en `localStorage`/`sessionStorage`. Cualquier script que ejecute en ese origen puede leer Web Storage, y la persistencia puede sobrevivir a cambios de sesión según el mecanismo.",
		"Evita almacenar credenciales reutilizables en Web Storage; prefiere mecanismos con menor exposición a JavaScript y borra estado sensible al cambiar de cuenta/sesión.",
		"", tokens[i].text+".setItem("+keyName+", ...)"), true
}

func serverRedirectFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if !isResponseLikeJSName(tokens[i].text) || tokenText(tokens, i+1) != "." || tokenText(tokens, i+2) != "redirect" || tokenText(tokens, i+3) != "(" {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, i+3, 0)
	if !ok || !expressionContainsLowerTrustSource(expr) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS012", "Injection", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"Redirect servidor controlado directamente por entrada de menor confianza",
		"Un objeto con forma de respuesta llama `redirect` usando directamente datos de request/mensaje/URL. Si no existe una allowlist previa, el cliente puede influir el destino de navegación.",
		"Usa rutas relativas conocidas o valida esquema y host contra una allowlist antes del redirect final.",
		"Confirmar que el receptor es una respuesta HTTP real, la normalización previa y qué destinos puede producir el dato controlable.",
		"response.redirect(lower-trust target)"), true
}

func sensitiveJSLoggingFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if tokenText(tokens, i+1) != "." || tokenText(tokens, i+3) != "(" || !isLoggingJSReceiver(tokens[i].text) || !isLoggingJSMethod(tokenText(tokens, i+2)) {
		return audit.Finding{}, false
	}
	for argIndex := 0; ; argIndex++ {
		expr, ok := argument(tokens, i+3, argIndex)
		if !ok {
			break
		}
		sensitiveName := expressionSensitiveJSLogName(expr)
		if containsJSLogSanitizer(expr) || sensitiveName == "" {
			continue
		}
		return jsFinding(file, tokens[i], "DEXJS013", "Cryptography and secrets", audit.VerdictNeedsValidation, audit.ConfidenceMedium,
			"Dato con nombre sensible enviado a logging",
			"Una llamada de logging recibe un identificador con semántica aparente de token, contraseña, secreto, sesión o credencial sin un redactor visible. El nombre no prueba que el valor sea secreto real.",
			"Evita registrar credenciales reutilizables; registra identificadores no sensibles o aplica una función de redacción/fingerprint antes del sink.",
			"Confirmar qué contiene el valor y quién puede leer o exportar este destino de logs.",
			tokens[i].text+"."+tokenText(tokens, i+2)+"("+sensitiveName+")"), true
	}
	return audit.Finding{}, false
}

func dynamicModuleFinding(file audit.File, tokens []sourceToken, i int) (audit.Finding, bool) {
	if (tokens[i].text != "import" && tokens[i].text != "require") || tokenText(tokens, i+1) != "(" || (i > 0 && tokens[i-1].text == ".") {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, i+1, 0)
	if !ok || !expressionContainsLowerTrustSource(expr) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS014", "Injection", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"Módulo seleccionado dinámicamente por entrada de menor confianza",
		"`import()`/`require()` recibe directamente un selector de módulo controlable. Dependiendo del loader y del contenido disponible, esto puede ampliar qué código o plugin puede cargar el proceso.",
		"Mapea el selector externo a una allowlist cerrada de módulos conocidos y evita resolver rutas o nombres arbitrarios aportados por el solicitante.",
		"Confirmar el loader efectivo, el conjunto de módulos/rutas alcanzables y la autoridad con la que se ejecuta el módulo cargado.",
		tokens[i].text+"(lower-trust module)"), true
}

func vmDynamicCodeFinding(file audit.File, tokens []sourceToken, i int, bindings apiBindings) (audit.Finding, bool) {
	method, openParen, ok := apiCall(tokens, i, bindings)
	if !ok {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, openParen, 0)
	if !ok || isStaticStringExpression(expr) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS015", "Injection", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"Código dinámico compilado o ejecutado mediante `node:vm`",
		"Una API de `node:vm` que compila o ejecuta JavaScript recibe una expresión no estática. Un contexto VM no convierte por sí solo contenido no confiable en datos inertes.",
		"Evita compilar texto variable como JavaScript; usa una representación de datos y validación estructural. Si el VM es intencional, limita capacidades y valida estrictamente el origen del código.",
		"Trazar la expresión hasta su origen y confirmar qué capacidades/contexto obtiene el código resultante.",
		method+"(dynamic code)"), true
}

func dynamicExecutableJSFinding(file audit.File, tokens []sourceToken, i int, bindings apiBindings) (audit.Finding, bool) {
	method, openParen, ok := apiCall(tokens, i, bindings)
	if !ok {
		return audit.Finding{}, false
	}
	expr, ok := argument(tokens, openParen, 0)
	if !ok || !expressionContainsLowerTrustSource(expr) {
		return audit.Finding{}, false
	}
	return jsFinding(file, tokens[i], "DEXJS016", "Injection", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
		"Ejecutable seleccionado directamente por entrada de menor confianza",
		"`spawn`/`execFile` recibe el nombre o ruta del ejecutable directamente desde una fuente de menor confianza. Aunque estas APIs no usan shell por defecto, seleccionar el programa puede cruzar una frontera de ejecución.",
		"Mapea la entrada a una allowlist de ejecutables conocidos y pasa argumentos separados; no aceptes rutas o nombres arbitrarios.",
		"Confirmar qué ejecutables/rutas están disponibles, la autoridad del solicitante y los privilegios del proceso hijo.",
		method+"(lower-trust executable)"), true
}

func credentialedJSCORSFindings(file audit.File, tokens []sourceToken) []audit.Finding {
	type corsState struct {
		originIndex int
		origin      bool
		credentials bool
	}
	states := map[int]corsState{}
	for i := range tokens {
		header, value, ok := jsResponseHeaderSet(tokens, i)
		if !ok {
			continue
		}
		block := containingJSBlockStart(tokens, i)
		if block < 0 {
			continue
		}
		state := states[block]
		switch strings.ToLower(header) {
		case "access-control-allow-origin":
			if expressionContainsLowerTrustSource(value) {
				state.origin = true
				state.originIndex = i
			}
		case "access-control-allow-credentials":
			if isJSTrueExpression(value) {
				state.credentials = true
			}
		}
		states[block] = state
	}

	findings := make([]audit.Finding, 0)
	for _, state := range states {
		if !state.origin || !state.credentials {
			continue
		}
		findings = append(findings, jsFinding(file, tokens[state.originIndex], "DEXJS017", "Client-side and rendering", audit.VerdictNeedsValidation, audit.ConfidenceHigh,
			"Origen CORS reflejado junto con credenciales habilitadas",
			"El mismo bloque de respuesta refleja un origen derivado directamente del request y habilita `Access-Control-Allow-Credentials`. Sin una allowlist efectiva, un origen externo puede llegar a leer respuestas autenticadas.",
			"Valida el Origin contra una allowlist exacta antes de reflejarlo y habilita credenciales solo para orígenes explícitamente confiables.",
			"Confirmar que ambas cabeceras pertenecen a la misma respuesta/ruta, que no existe validación previa y que la ruta usa credenciales ambientales para datos o mutaciones protegidas.",
			"credentialed reflected CORS"))
	}
	return findings
}

func jsResponseHeaderSet(tokens []sourceToken, i int) (string, []sourceToken, bool) {
	if !isResponseLikeJSName(tokens[i].text) || tokenText(tokens, i+1) != "." || tokenText(tokens, i+3) != "(" {
		return "", nil, false
	}
	switch tokenText(tokens, i+2) {
	case "setHeader", "header", "set":
	default:
		return "", nil, false
	}
	name, ok := argument(tokens, i+3, 0)
	if !ok || len(name) != 1 || name[0].typ != js.StringToken {
		return "", nil, false
	}
	value, ok := argument(tokens, i+3, 1)
	if !ok {
		return "", nil, false
	}
	return stripJSString(name[0].text), value, true
}

func containingJSBlockStart(tokens []sourceToken, index int) int {
	depth := 0
	for i := index - 1; i >= 0; i-- {
		switch tokens[i].text {
		case "}":
			depth++
		case "{":
			if depth == 0 {
				return i
			}
			depth--
		}
	}
	return -1
}

func isJSTrueExpression(tokens []sourceToken) bool {
	if len(tokens) != 1 {
		return false
	}
	return tokens[0].text == "true" || strings.EqualFold(stripJSString(tokens[0].text), "true")
}

func isResponseLikeJSName(name string) bool {
	switch strings.ToLower(name) {
	case "res", "response", "reply":
		return true
	default:
		return false
	}
}

func isLoggingJSReceiver(name string) bool {
	lower := strings.ToLower(name)
	return lower == "console" || lower == "log" || lower == "logger" || strings.HasSuffix(lower, "logger")
}

func isLoggingJSMethod(name string) bool {
	switch strings.ToLower(name) {
	case "log", "debug", "info", "warn", "error", "fatal", "trace":
		return true
	default:
		return false
	}
}

func containsJSLogSanitizer(tokens []sourceToken) bool {
	for i := 0; i+1 < len(tokens); i++ {
		if tokenText(tokens, i+1) != "(" {
			continue
		}
		switch strings.ToLower(tokens[i].text) {
		case "redact", "redacted", "mask", "masked", "fingerprint", "hashforlog":
			return true
		}
	}
	return false
}

func isDynamicJSExpression(tokens []sourceToken) bool {
	if len(tokens) == 0 || isStaticStringExpression(tokens) {
		return false
	}
	for _, token := range tokens {
		if token.typ == js.TemplateStartToken || token.typ == js.TemplateMiddleToken || token.typ == js.TemplateEndToken || token.text == "+" {
			return true
		}
	}
	return expressionContainsLowerTrustSource(tokens)
}

func expressionContainsSQLSyntax(tokens []sourceToken) bool {
	var b strings.Builder
	for _, token := range tokens {
		if token.typ == js.StringToken || token.typ == js.TemplateToken || token.typ == js.TemplateStartToken || token.typ == js.TemplateMiddleToken || token.typ == js.TemplateEndToken {
			b.WriteString(" ")
			b.WriteString(strings.ToLower(stripJSString(token.text)))
		}
	}
	text := b.String()
	for _, needle := range []string{"select ", "insert ", "update ", "delete ", " from ", " where ", " order by ", " group by ", " union "} {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func expressionContainsLowerTrustSource(tokens []sourceToken) bool {
	for i := 0; i < len(tokens); i++ {
		if tokens[i].text == "process" && tokenText(tokens, i+1) == "." && tokenText(tokens, i+2) == "argv" {
			return true
		}
		if (tokens[i].text == "req" || tokens[i].text == "request" || tokens[i].text == "ctx") && tokenText(tokens, i+1) == "." {
			switch tokenText(tokens, i+2) {
			case "query", "params", "body", "headers", "header":
				return true
			}
		}
		if (tokens[i].text == "event" || tokens[i].text == "messageEvent") && tokenText(tokens, i+1) == "." && tokenText(tokens, i+2) == "data" {
			return true
		}
		if tokens[i].text == "location" && tokenText(tokens, i+1) == "." {
			switch tokenText(tokens, i+2) {
			case "search", "hash", "href":
				return true
			}
		}
		if tokens[i].text == "window" && tokenText(tokens, i+1) == "." && tokenText(tokens, i+2) == "location" && tokenText(tokens, i+3) == "." {
			switch tokenText(tokens, i+4) {
			case "search", "hash", "href":
				return true
			}
		}
	}
	return false
}

func expressionContainsSensitiveJSToken(tokens []sourceToken) bool {
	for _, token := range tokens {
		if token.typ == js.IdentifierToken && sensitiveJSName(token.text) {
			return true
		}
	}
	return false
}

func expressionSensitiveJSLogName(tokens []sourceToken) string {
	for _, token := range tokens {
		if token.typ == js.IdentifierToken && sensitiveJSLogName(token.text) {
			return token.text
		}
	}
	return ""
}

func htmlRisk(tokens []sourceToken) (audit.Verdict, audit.Confidence, string) {
	if expressionContainsLowerTrustSource(tokens) {
		return audit.VerdictNeedsValidation, audit.ConfidenceHigh,
			"Confirmar si existe una sanitización HTML efectiva o una allowlist previa que no sea visible en esta expresión."
	}
	return audit.VerdictHardening, audit.ConfidenceMedium, ""
}

func expressionUntilStatement(tokens []sourceToken, start int) []sourceToken {
	if start < 0 || start >= len(tokens) {
		return nil
	}
	paren, brace, bracket := 0, 0, 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			paren++
		case ")":
			if paren > 0 {
				paren--
			}
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
		case ";":
			if paren == 0 && brace == 0 && bracket == 0 {
				return tokens[start:i]
			}
		}
	}
	return tokens[start:]
}

func expressionUntilPropertyEnd(tokens []sourceToken, start int) []sourceToken {
	if start < 0 || start >= len(tokens) {
		return nil
	}
	paren, brace, bracket := 0, 0, 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			paren++
		case ")":
			if paren > 0 {
				paren--
			}
		case "{":
			brace++
		case "}":
			if paren == 0 && brace == 0 && bracket == 0 {
				return tokens[start:i]
			}
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
			if paren == 0 && brace == 0 && bracket == 0 {
				return tokens[start:i]
			}
		}
	}
	return tokens[start:]
}

func isLocationHref(tokens []sourceToken, i int) bool {
	if i >= 2 && tokens[i-2].text == "location" && tokens[i-1].text == "." {
		return true
	}
	return i >= 4 && tokens[i-4].text == "window" && tokens[i-3].text == "." && tokens[i-2].text == "location" && tokens[i-1].text == "."
}

type scopedJSPathName struct {
	name       string
	start, end int
}

type jsPathTrust struct {
	staticNames map[string]struct{}
	scopedNames []scopedJSPathName
}

func collectJSPathTrust(tokens []sourceToken, fsBindings apiBindings) jsPathTrust {
	trust := jsPathTrust{staticNames: map[string]struct{}{}}
	staticArrays := map[string]struct{}{}

	for i := 0; i+3 < len(tokens); i++ {
		if tokens[i].text != "const" || tokenText(tokens, i+2) != "=" {
			continue
		}
		name := tokenText(tokens, i+1)
		if name == "" {
			continue
		}
		value := tokenAt(tokens, i+3)
		if value.typ == js.StringToken || value.typ == js.TemplateToken {
			trust.staticNames[name] = struct{}{}
			continue
		}
		if value.text == "[" {
			if _, ok := staticStringArray(tokens, i+3); ok {
				staticArrays[name] = struct{}{}
			}
		}
	}

	for i := 0; i+6 < len(tokens); i++ {
		if tokens[i].text != "for" || tokenText(tokens, i+1) != "(" || (tokenText(tokens, i+2) != "const" && tokenText(tokens, i+2) != "let") || tokenText(tokens, i+4) != "of" {
			continue
		}
		name := tokenText(tokens, i+3)
		sourceIndex := i + 5
		trustedSource := false
		if _, ok := staticArrays[tokenText(tokens, sourceIndex)]; ok {
			trustedSource = true
		}
		if method, _, ok := apiCall(tokens, sourceIndex, fsBindings); ok && method == "readdirSync" {
			trustedSource = true
		}
		if !trustedSource {
			continue
		}
		closeParen := matchingDelimiter(tokens, i+1, "(", ")")
		if closeParen < 0 || tokenText(tokens, closeParen+1) != "{" {
			continue
		}
		openBrace := closeParen + 1
		closeBrace := matchingDelimiter(tokens, openBrace, "{", "}")
		if closeBrace < 0 {
			continue
		}
		trust.scopedNames = append(trust.scopedNames, scopedJSPathName{name: name, start: openBrace + 1, end: closeBrace - 1})
	}
	return trust
}

func staticStringArray(tokens []sourceToken, open int) (int, bool) {
	if tokenText(tokens, open) != "[" {
		return -1, false
	}
	seenValue := false
	for i := open + 1; i < len(tokens); i++ {
		switch tokens[i].text {
		case "]":
			return i, seenValue
		case ",":
			continue
		}
		if tokens[i].typ != js.StringToken && tokens[i].typ != js.TemplateToken {
			return -1, false
		}
		seenValue = true
	}
	return -1, false
}

func matchingDelimiter(tokens []sourceToken, open int, openText, closeText string) int {
	if tokenText(tokens, open) != openText {
		return -1
	}
	depth := 0
	for i := open; i < len(tokens); i++ {
		switch tokens[i].text {
		case openText:
			depth++
		case closeText:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func (t jsPathTrust) trustedName(name string, tokenIndex int) bool {
	if _, ok := t.staticNames[name]; ok {
		return true
	}
	for _, item := range t.scopedNames {
		if item.name == name && tokenIndex >= item.start && tokenIndex <= item.end {
			return true
		}
	}
	return false
}

type apiBindings struct {
	direct     map[string]string
	namespaces map[string]struct{}
	allowed    map[string]struct{}
}

func collectAPIBindings(tokens []sourceToken, modules, exports []string) apiBindings {
	bindings := apiBindings{direct: map[string]string{}, namespaces: map[string]struct{}{}, allowed: map[string]struct{}{}}
	moduleSet := make(map[string]struct{}, len(modules))
	for _, module := range modules {
		moduleSet[module] = struct{}{}
	}
	exportSet := make(map[string]struct{}, len(exports))
	for _, name := range exports {
		exportSet[name] = struct{}{}
		bindings.allowed[name] = struct{}{}
	}
	for i := 0; i < len(tokens); i++ {
		if tokens[i].text == "import" {
			collectGenericESImport(tokens, i, moduleSet, exportSet, &bindings)
		}
		if tokens[i].text == "require" && tokenText(tokens, i+1) == "(" {
			module := stripJSString(tokenText(tokens, i+2))
			if _, ok := moduleSet[module]; ok {
				collectGenericRequire(tokens, i, exportSet, &bindings)
			}
		}
	}
	return bindings
}

func collectGenericESImport(tokens []sourceToken, start int, modules, exports map[string]struct{}, bindings *apiBindings) {
	from := -1
	source := -1
	limit := start + 48
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
	if from < 0 || source >= len(tokens) {
		return
	}
	if _, ok := modules[stripJSString(tokens[source].text)]; !ok {
		return
	}
	if tokenText(tokens, start+1) == "*" && tokenText(tokens, start+2) == "as" {
		bindings.namespaces[tokenText(tokens, start+3)] = struct{}{}
		return
	}
	if tokenText(tokens, start+1) == "{" {
		for i := start + 2; i < from && tokens[i].text != "}"; i++ {
			if tokens[i].text == "," || tokens[i].text == "type" {
				continue
			}
			imported := tokens[i].text
			local := imported
			if tokenText(tokens, i+1) == "as" && i+2 < from {
				local = tokenText(tokens, i+2)
				i += 2
			}
			if _, ok := exports[imported]; ok {
				bindings.direct[local] = imported
			}
		}
		return
	}
	if start+1 < from {
		bindings.namespaces[tokenText(tokens, start+1)] = struct{}{}
	}
}

func collectGenericRequire(tokens []sourceToken, requireIndex int, exports map[string]struct{}, bindings *apiBindings) {
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
		if _, ok := exports[imported]; ok {
			bindings.direct[local] = imported
		}
	}
}

func apiCall(tokens []sourceToken, i int, bindings apiBindings) (string, int, bool) {
	if canonical, ok := bindings.direct[tokens[i].text]; ok && tokenText(tokens, i+1) == "(" {
		return canonical, i + 1, true
	}
	if _, ok := bindings.namespaces[tokens[i].text]; !ok {
		return "", -1, false
	}
	if tokenText(tokens, i+1) != "." {
		return "", -1, false
	}
	if tokenText(tokens, i+2) == "promises" && tokenText(tokens, i+3) == "." && tokenText(tokens, i+5) == "(" {
		method := tokenText(tokens, i+4)
		if _, allowed := bindings.allowed[method]; allowed {
			return method, i + 5, true
		}
		return "", -1, false
	}
	if tokenText(tokens, i+3) == "(" {
		method := tokenText(tokens, i+2)
		if _, allowed := bindings.allowed[method]; allowed {
			return method, i + 3, true
		}
	}
	return "", -1, false
}

func containsRiskyPathConstruction(tokens []sourceToken, pathBindings apiBindings, trust jsPathTrust, sinkIndex int) bool {
	for i := range tokens {
		method, openParen, ok := apiCall(tokens, i, pathBindings)
		if !ok || (method != "join" && method != "resolve") {
			continue
		}
		for argIndex := 1; ; argIndex++ {
			expr, exists := argument(tokens, openParen, argIndex)
			if !exists {
				break
			}
			if isStaticStringExpression(expr) {
				continue
			}
			if len(expr) == 1 && expr[0].typ == js.IdentifierToken && trust.trustedName(expr[0].text, sinkIndex) {
				continue
			}
			return true
		}
	}
	return false
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

func sensitiveJSLogName(name string) bool {
	normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "", "$", "").Replace(name))
	if strings.HasPrefix(normalized, "has") || strings.HasPrefix(normalized, "is") {
		return false
	}
	for _, suffix := range []string{"count", "counts", "ttl", "timeout", "duration", "window", "limit", "limits", "budget", "budgets", "usage", "cost", "costs", "score", "scores", "length", "size", "entry", "entries", "tokens", "enabled", "present", "name", "type", "path", "file"} {
		if strings.HasSuffix(normalized, suffix) {
			return false
		}
	}
	for _, part := range []string{"password", "passwd", "secret", "credential", "apikey", "authorization", "bearer", "cookie", "accesstoken", "refreshtoken", "authtoken", "idtoken", "sessiontoken", "csrftoken", "authcode"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	if strings.Contains(normalized, "token") {
		return true
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
