package coveragecatalog

import (
	"fmt"
	"sort"
)

const (
	LanguageGo                   = "go"
	LanguageJavaScriptTypeScript = "javascript-typescript"

	StatusPartial       = "partial"
	StatusNotAutomated  = "not_automated"
	StatusNotApplicable = "not_applicable"
)

type ClassDefinition struct {
	Domain string `json:"domain"`
	Source string `json:"source"`
	Name   string `json:"name"`
}

type LanguageCoverage struct {
	Status string   `json:"status"`
	Rules  []string `json:"rules,omitempty"`
	Note   string   `json:"note"`
}

type Entry struct {
	ClassDefinition
	Go                   LanguageCoverage `json:"go"`
	JavaScriptTypeScript LanguageCoverage `json:"javascript_typescript"`
}

type Summary struct {
	Total            int                       `json:"total_classes"`
	ByLanguageStatus map[string]map[string]int `json:"by_language_status"`
}

type MatrixReport struct {
	Reference string  `json:"reference"`
	Summary   Summary `json:"summary"`
	Entries   []Entry `json:"entries"`
}

type override struct {
	goCoverage LanguageCoverage
	jsCoverage LanguageCoverage
}

func Matrix() MatrixReport {
	entries := make([]Entry, 0, len(skillClasses))
	for _, class := range skillClasses {
		entry := Entry{
			ClassDefinition: class,
			Go: LanguageCoverage{
				Status: StatusNotAutomated,
				Note:   "la clase requiere análisis semántico, de flujo o de frontera que DexAuditor todavía no automatiza para Go",
			},
			JavaScriptTypeScript: LanguageCoverage{
				Status: StatusNotAutomated,
				Note:   "la clase requiere análisis semántico, de flujo o de frontera que DexAuditor todavía no automatiza para JavaScript/TypeScript",
			},
		}
		if class.Source == "MEMORY-SAFETY-AND-BINARY.md" {
			entry.JavaScriptTypeScript = LanguageCoverage{
				Status: StatusNotApplicable,
				Note:   "la clase corresponde a memoria nativa/binarios; no aplica al código JavaScript/TypeScript administrado salvo FFI o extensiones nativas, que deben auditarse en su lenguaje nativo",
			}
		}
		if class.Source == "CLIENT-SIDE.md" {
			entry.Go = LanguageCoverage{
				Status: StatusNotApplicable,
				Note:   "la clase es específica del runtime del navegador; el código Go servidor se cubre por clases web/inyección equivalentes",
			}
		}
		if item, ok := overrides[class.Source+"#"+class.Name]; ok {
			if item.goCoverage.Status != "" {
				entry.Go = cloneCoverage(item.goCoverage)
			}
			if item.jsCoverage.Status != "" {
				entry.JavaScriptTypeScript = cloneCoverage(item.jsCoverage)
			}
		}
		entries = append(entries, entry)
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Domain != entries[j].Domain {
			return entries[i].Domain < entries[j].Domain
		}
		if entries[i].Source != entries[j].Source {
			return entries[i].Source < entries[j].Source
		}
		return entries[i].Name < entries[j].Name
	})

	summary := Summary{
		Total: len(entries),
		ByLanguageStatus: map[string]map[string]int{
			LanguageGo:                   {},
			LanguageJavaScriptTypeScript: {},
		},
	}
	for _, entry := range entries {
		summary.ByLanguageStatus[LanguageGo][entry.Go.Status]++
		summary.ByLanguageStatus[LanguageJavaScriptTypeScript][entry.JavaScriptTypeScript.Status]++
	}
	return MatrixReport{
		Reference: "cloudflare/security-audit-skill@c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
		Summary:   summary,
		Entries:   entries,
	}
}

func Validate() error {
	seen := make(map[string]struct{}, len(skillClasses))
	for _, class := range skillClasses {
		if class.Domain == "" || class.Source == "" || class.Name == "" {
			return fmt.Errorf("clase de cobertura incompleta: %#v", class)
		}
		key := class.Source + "#" + class.Name
		if _, exists := seen[key]; exists {
			return fmt.Errorf("clase duplicada: %s", key)
		}
		seen[key] = struct{}{}
	}
	matrix := Matrix()
	for _, entry := range matrix.Entries {
		for language, coverage := range map[string]LanguageCoverage{
			LanguageGo:                   entry.Go,
			LanguageJavaScriptTypeScript: entry.JavaScriptTypeScript,
		} {
			switch coverage.Status {
			case StatusPartial, StatusNotAutomated, StatusNotApplicable:
			default:
				return fmt.Errorf("estado de cobertura inválido para %s %s#%s: %q", language, entry.Source, entry.Name, coverage.Status)
			}
			if coverage.Note == "" {
				return fmt.Errorf("cobertura sin nota para %s %s#%s", language, entry.Source, entry.Name)
			}
		}
	}
	return nil
}

func cloneCoverage(in LanguageCoverage) LanguageCoverage {
	out := in
	out.Rules = append([]string(nil), in.Rules...)
	sort.Strings(out.Rules)
	return out
}

func partial(rules []string, note string) LanguageCoverage {
	return LanguageCoverage{Status: StatusPartial, Rules: rules, Note: note}
}

var overrides = map[string]override{
	"ATTACK-CLASSES.md#Injection": {
		goCoverage: partial([]string{"DEXGO002", "DEXGO003", "DEXGO017", "DEXGO019"}, "cubre sinks conocidos de shell, SQL/ORM, redirects directos y selección dinámica de ejecutables desde entrada de menor confianza; no es dataflow interprocedural completo"),
		jsCoverage: partial([]string{"DEXJS002", "DEXJS003", "DEXJS006", "DEXJS009", "DEXJS012", "DEXJS014", "DEXJS015", "DEXJS016"}, "cubre shell, evaluación dinámica, SQL/ORM, redirects, módulos dinámicos, node:vm y selección de ejecutables en rutas de alta señal; falta dataflow interprocedural"),
	},
	"ATTACK-CLASSES.md#Resource and file handling": {
		goCoverage: partial([]string{"DEXGO004", "DEXGO011", "DEXGO016"}, "cubre rutas dinámicas en filesystem, permisos world-writable y SSRF directo desde request; faltan archives, TOCTOU y dataflow general"),
		jsCoverage: partial([]string{"DEXJS007", "DEXJS008"}, "cubre rutas dinámicas en APIs fs conocidas y SSRF directo desde fuentes de menor confianza; no es dataflow interprocedural completo"),
	},
	"ATTACK-CLASSES.md#Cryptography and secrets": {
		goCoverage: partial([]string{"DEXG001", "DEXG002", "DEXG003", "DEXG004", "DEXG005", "DEXG006", "DEXG007", "DEXGO001", "DEXGO005", "DEXGO010", "DEXGO018", "DEXGO021"}, "cubre secretos textuales, TLS inseguro, aleatoriedad débil, logging sensible, cookies con nombre sensible y MD5/SHA-1 sobre valores con semántica sensible; no cubre todos los usos criptográficos"),
		jsCoverage: partial([]string{"DEXG001", "DEXG002", "DEXG003", "DEXG004", "DEXG005", "DEXG006", "DEXG007", "DEXJS001", "DEXJS005", "DEXJS011", "DEXJS013"}, "cubre secretos textuales, TLS inseguro, Math.random en valores sensibles, credenciales aparentes en Web Storage y logging sensible; no cubre todos los usos criptográficos"),
	},
	"ATTACK-CLASSES.md#Obvious things": {
		goCoverage: partial([]string{"DEXG008", "DEXGO013", "DEXGO015"}, "cubre deuda de seguridad explícita y algunas superficies de debug; el checklist completo aún no está automatizado"),
		jsCoverage: partial([]string{"DEXG008", "DEXJS003"}, "cubre deuda de seguridad explícita y evaluación dinámica; el checklist completo aún no está automatizado"),
	},
	"WEB-PROTOCOL-AND-AUTH.md#Cookie scope and transport": {
		goCoverage: partial([]string{"DEXGO018"}, "detecta cookies con nombre sensible que no habilitan Secure y HttpOnly; no demuestra el contenido real ni la política efectiva del navegador"),
	},
	"CLIENT-SIDE.md#Credentialed CORS trust": {
		goCoverage: partial([]string{"DEXGO022"}, "detecta reflexión directa del header Origin junto con Access-Control-Allow-Credentials=true dentro de la misma función; requiere validar ruta, credenciales y allowlist previa"),
		jsCoverage: partial([]string{"DEXJS017"}, "detecta reflexión directa de origen junto con credenciales habilitadas en el mismo bloque de respuesta; requiere validar ruta, credenciales y controles previos"),
	},
	"CLIENT-SIDE.md#DOM-based XSS": {
		jsCoverage: partial([]string{"DEXJS004"}, "cubre varios sinks HTML/DOM conocidos; todavía no sigue de forma general las fuentes del navegador ni sanitizadores"),
	},
	"CLIENT-SIDE.md#`postMessage` origin and source trust": {
		jsCoverage: partial([]string{"DEXJS010"}, "detecta payloads con nombres sensibles enviados a targetOrigin comodín; aún no verifica receptores ni event.source de forma general"),
	},
	"CLIENT-SIDE.md#Browser-storage disclosure and stale authorization": {
		jsCoverage: partial([]string{"DEXJS011"}, "detecta claves con semántica de token/sesión/credencial almacenadas en localStorage/sessionStorage; no modela logout ni lectores"),
	},
	"CLIENT-SIDE.md#Client-side navigation confusion": {
		jsCoverage: partial([]string{"DEXJS009"}, "detecta sinks de navegación que reciben directamente fuentes de menor confianza; no sigue propagación interprocedural"),
	},
	"AI-AND-LLM.md#Insecure output rendering": {
		goCoverage: partial([]string{"DEXGO009"}, "detecta bypass explícito del escape contextual mediante template.HTML; requiere contexto para demostrar una frontera AI/modelo"),
		jsCoverage: partial([]string{"DEXJS004"}, "detecta sinks HTML dinámicos; requiere contexto para demostrar que el dato procede de salida de modelo"),
	},
	"AI-AND-LLM.md#Tool-argument injection into a downstream sink": {
		goCoverage: partial([]string{"DEXGO002", "DEXGO003", "DEXGO004"}, "detecta algunos sinks peligrosos que también pueden recibir argumentos de herramientas; aún no modela tool-calling ni autoridad"),
		jsCoverage: partial([]string{"DEXJS002", "DEXJS003", "DEXJS004"}, "detecta algunos sinks peligrosos que también pueden recibir argumentos de herramientas; aún no modela tool-calling ni autoridad"),
	},
	"RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Unbounded buffering and cardinality": {
		goCoverage: partial([]string{"DEXGO006"}, "detecta lectura completa de request.Body sin límite visible en el sink; no cubre todas las acumulaciones"),
	},
	"RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Reachable fatal error or deadlock": {
		goCoverage: partial([]string{"DEXGO012"}, "detecta salida fatal del proceso dentro de lógica reutilizable; alcance y compartición requieren validación"),
	},
	"RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Detached work after cancellation": {
		goCoverage: partial([]string{"DEXGO007", "DEXGO008", "DEXGO014"}, "timeouts HTTP ausentes son señales parciales de trabajo sin límite; no demuestra propagación completa de cancelación"),
	},
	"SUPPLY-CHAIN-AND-RELEASE.md#Plugin and extension trust expansion": {
		jsCoverage: partial([]string{"DEXJS014", "DEXJS016"}, "detecta selección directa de módulos o ejecutables desde fuentes de menor confianza; no modela firma, publisher, capability scope ni actualización completa"),
	},
	"SUPPLY-CHAIN-AND-RELEASE.md#Mutable and unbound build inputs": {
		goCoverage: partial([]string{"DEXG009", "DEXG014", "DEXG016"}, "reglas de repositorio aplican independientemente del lenguaje: Actions mutables y descargas ejecutadas directamente"),
		jsCoverage: partial([]string{"DEXG009", "DEXG014", "DEXG016"}, "reglas de repositorio aplican independientemente del lenguaje: Actions mutables y descargas ejecutadas directamente"),
	},
	"SUPPLY-CHAIN-AND-RELEASE.md#Untrusted code in a privileged workflow": {
		goCoverage: partial([]string{"DEXG012"}, "detecta una combinación de alto riesgo con pull_request_target; faltan más eventos y controles hospedados"),
		jsCoverage: partial([]string{"DEXG012"}, "detecta una combinación de alto riesgo con pull_request_target; faltan más eventos y controles hospedados"),
	},
	"SUPPLY-CHAIN-AND-RELEASE.md#Workflow command and expression confusion": {
		goCoverage: partial([]string{"DEXG011"}, "detecta campos GitHub controlables en expresiones; requiere validar si alcanzan shell privilegiado"),
		jsCoverage: partial([]string{"DEXG011"}, "detecta campos GitHub controlables en expresiones; requiere validar si alcanzan shell privilegiado"),
	},
	"CLOUD-AND-DEPLOYMENT.md#Metadata and internal-service reachability": {
		goCoverage: partial([]string{"DEXGO016"}, "detecta SSRF directo cuando un helper HTTP consume entrada del request; no resuelve DNS/redirects ni sigue valores interprocedurales"),
		jsCoverage: partial([]string{"DEXJS008"}, "detecta URLs salientes que consumen directamente fuentes de menor confianza; no resuelve DNS/redirects ni sigue valores interprocedurales"),
	},
	"CLOUD-AND-DEPLOYMENT.md#Secret exposure across workload boundaries": {
		goCoverage: partial([]string{"DEXG013"}, "detecta literales sensibles en ARG/ENV de Docker; no modela volúmenes, secretos externos ni lectores reales"),
		jsCoverage: partial([]string{"DEXG013"}, "detecta literales sensibles en ARG/ENV de Docker; no modela volúmenes, secretos externos ni lectores reales"),
	},
	"CLOUD-AND-DEPLOYMENT.md#Host or control-plane capability exposure": {
		goCoverage: partial([]string{"DEXG015"}, "detecta contenedor final sin reducción explícita de usuario; por sí solo es hardening, no una frontera demostrada"),
		jsCoverage: partial([]string{"DEXG015"}, "detecta contenedor final sin reducción explícita de usuario; por sí solo es hardening, no una frontera demostrada"),
	},
	"DATA-ISOLATION-AND-LIFECYCLE.md#Analytics, logs, traces, and diagnostics as alternate readers": {
		goCoverage: partial([]string{"DEXGO010"}, "detecta identificadores sensibles enviados a logging; no prueba quién puede leer esos sistemas"),
		jsCoverage: partial([]string{"DEXJS013"}, "detecta identificadores con semántica sensible enviados a console/logger sin redactor visible; no prueba sensibilidad real ni lectores del sistema de logs"),
	},
	"WEB-PROTOCOL-AND-AUTH.md#Certificate lifecycle fallback": {
		goCoverage: partial([]string{"DEXGO001"}, "detecta una forma explícita de deshabilitar la validación TLS; no cubre toda la renovación/fallback de certificados"),
		jsCoverage: partial([]string{"DEXJS001"}, "detecta rejectUnauthorized=false o deshabilitación global de TLS; no cubre toda la renovación/fallback"),
	},
}
