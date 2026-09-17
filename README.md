# DexAuditor

DexAuditor es un CLI de auditoría estática **source-first**, escrito 100% en Go y diseñado para compilarse en múltiples plataformas. Analiza un repositorio sin usar modelos LLM y emite resultados progresivos para personas o consumidores automatizados.

La V1 incluye un analizador genérico de repositorio/configuración, un analizador específico para Go basado en AST y un analizador JavaScript/TypeScript basado en tokenización real del lenguaje. La arquitectura permite agregar más analizadores cuando exista cobertura útil y verificable, sin crear módulos vacíos por adelantado.

## Principios

- No ejecuta el código del proyecto auditado.
- No instala dependencias ni contacta servicios externos durante el análisis.
- No transforma una señal sintáctica en una vulnerabilidad confirmada sin evidencia suficiente.
- Separa `confirmed`, `needs_validation` y `hardening`.
- Solo un hallazgo `confirmed` puede tener severidad.
- Expone qué clases no puede automatizar en vez de presentarlas como revisadas.
- Nunca imprime en claro un valor detectado como posible secreto; la evidencia sensible se redacta.

DexAuditor no sustituye una auditoría manual de autorización, lógica de negocio, modelos de amenaza o comportamiento de despliegue. Su objetivo es producir evidencia determinista útil y declarar con precisión sus límites.

## Requisitos

Para desarrollar desde fuente:

```text
Go 1.24 o superior
```

El binario compilado no necesita runtime de Go ni dependencias externas.

## Compilar

```bash
go build -o dexauditor ./cmd/dexauditor
```

En Windows:

```powershell
go build -o dexauditor.exe .\cmd\dexauditor
```

## Uso

Auditar un proyecto y ver progreso humano en tiempo real:

```bash
dexauditor /ruta/al/proyecto
```

También se acepta el subcomando explícito:

```bash
dexauditor audit /ruta/al/proyecto
```

En Windows:

```powershell
.\dexauditor.exe "C:\ruta\mi-proyecto"
```

Las rutas con espacios están soportadas. En PowerShell también se tolera el caso donde una ruta terminada en `\` llega al ejecutable con una comilla residual, por ejemplo:

```powershell
.\dexauditor.exe '..\..\Proyecto Go Con Espacios\'
```

DexAuditor intenta primero la ruta recibida literalmente y solo aplica reparación de comillas cuando esa ruta no existe, para no modificar nombres válidos.

Opciones principales:

```text
--format human|ai|json  salida humana, NDJSON streaming o JSON final
--ai                    alias de --format ai
--out RUTA              guarda además el reporte JSON final
--max-file-mb N         tamaño máximo por archivo leído; default 4 MiB
--exclude-tests         omite tests y fixtures
--include-ignored       incluye archivos ignorados por Git en el recorrido físico
--version               muestra la versión
-h, --help              muestra ayuda
```

La ruta por defecto es el directorio actual.

## Salida humana

El formato `human` es el predeterminado. Muestra descubrimiento, inicio/fin de analizadores y hallazgos a medida que aparecen:

```text
DexAuditor dev — auditoría source-first
Objetivo: C:/codigo/proyecto
[discovery] 57 archivos analizables, 1 omitidos
[generic] iniciando análisis
[HARDENING] DEXG009 .github/workflows/ci.yml:20 — GitHub Action referenciada por etiqueta o rama mutable
[generic] 1 hallazgos únicos
[go] iniciando análisis
[go] 0 hallazgos únicos

Resumen: 1 hallazgos (0 confirmados, 0 por validar, 1 hardening)
```

## Salida para consumidores automatizados

`--ai` no ejecuta ni integra ningún modelo. El nombre describe únicamente un contrato fácil de consumir por herramientas externas.

```bash
dexauditor --ai /ruta/al/proyecto
```

La salida es **NDJSON**: una línea JSON independiente por evento, seguida de un objeto final `report`. No contiene ANSI ni prosa fuera de JSON.

Tipos de evento actuales:

```text
audit.start
discovery.progress
discovery.done
analyzer.start
finding
analyzer.done
warning
audit.complete
report
```

Cada sobre incluye `schema_version`, `type`, `time`, `tool_version` y `target`. El último objeto contiene el reporte consolidado completo.

Esto permite consumir progreso mientras el escaneo continúa sin esperar al documento final.

## JSON final

Para obtener solamente el reporte consolidado:

```bash
dexauditor --format json /ruta/al/proyecto
```

Para conservar progreso humano y guardar simultáneamente el reporte:

```bash
dexauditor --out auditoria.json /ruta/al/proyecto
```

Los reportes escritos mediante `--out` se crean con permisos restrictivos cuando el sistema operativo lo permite.

## Veredictos

| Veredicto | Significado | Severidad |
| --- | --- | --- |
| `confirmed` | La evidencia determinista disponible establece una falla y un resultado concreto. | Sí |
| `needs_validation` | Existe una ruta/source signal concreta, pero falta un hecho decisivo de origen, despliegue, autoridad o runtime. | No |
| `hardening` | Mejora defensiva útil que no demuestra por sí sola una vulnerabilidad. | No |

La ausencia de `confirmed` no significa que el proyecto esté libre de vulnerabilidades.

## Cobertura

Cada analizador devuelve además registros de cobertura. Los estados actuales incluyen:

- `partial`: se ejecutaron reglas deterministas sobre una parte conocida de la superficie; no equivale a cobertura semántica exhaustiva.
- `blocked`: el analizador encontró una condición que impidió completar su trabajo.
- `not_applicable`: la superficie no existe en el proyecto.
- `not_automated`: DexAuditor declara explícitamente que esa clase requiere razonamiento que la V1 no automatiza.

La V1 usa deliberadamente `partial` para las clases que revisa automáticamente: reconocer sinks o construcciones concretas no demuestra que toda una clase de ataque esté cubierta. Para Go, Access control, Business logic y Chained vulnerabilities/trust boundaries se reportan como `not_automated`. Para JavaScript/TypeScript, la cobertura actual es léxica y conservadora: Injection, Cryptography and secrets, Client-side and rendering y Resource and file handling son `partial`; las clases que exigen flujo de datos, autorización o semántica más profunda permanecen `not_automated`.

### Matriz de `security-audit-skill`

DexAuditor mantiene además un catálogo explícito de las clases publicadas por `cloudflare/security-audit-skill`. La matriz actual se generó desde el commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` del repositorio de referencia y contiene 162 clases entre el núcleo y los companion guides.

```bash
dexauditor coverage
dexauditor coverage --language go
dexauditor coverage --language javascript-typescript
dexauditor coverage --format json
```

Cada fila informa de forma independiente si Go o JavaScript/TypeScript tienen cobertura `partial`, `not_automated` o `not_applicable`, las reglas `DEX*` que contribuyen y una nota con el límite exacto. El comando no audita ningún proyecto ni necesita una ruta: describe las capacidades compiladas del binario. El archivo `tools/generate-coverage-catalog.go` permite regenerar el inventario de clases desde un checkout de la skill cuando la referencia cambie.

## Analizador genérico

Opera sobre archivos de configuración y texto relevantes, independientemente del lenguaje principal. La V1 revisa, entre otras señales:

- archivos `.env` reales y formas de credenciales de alta señal;
- claves privadas y tokens con formatos conocidos;
- GitHub Actions con referencias mutables o permisos amplios;
- combinaciones riesgosas de `pull_request_target` y código de PR;
- secretos declarados en Docker build/runtime;
- descargas canalizadas directamente a shell;
- ejecución de contenedores sin reducción source-visible de privilegios;
- comentarios TODO/FIXME/HACK relacionados con controles de seguridad.

Los posibles secretos no se imprimen. La evidencia usa una representación como:

```text
[redacted len=42 sha256=1a2b3c4d5e6f]
```

El hash truncado solo sirve para correlacionar señales dentro del análisis; no reemplaza un hash criptográfico para otros propósitos.

## Analizador Go

El módulo Go usa `go/parser`, `go/ast` y `go/token`. No ejecuta, compila ni type-checkea el proyecto objetivo.

La V1 detecta patrones alrededor de:

- `tls.Config{InsecureSkipVerify: true}`;
- comandos dinámicos enviados a un intérprete con `os/exec`;
- SQL/ORM construido por concatenación o `fmt.Sprintf`;
- componentes dinámicos de rutas antes de sinks de filesystem;
- `math/rand` para valores con semántica aparente de secreto/token/nonce;
- `io.ReadAll(request.Body)` sin límite visible en ese sink;
- clientes y servidores HTTP sin timeouts visibles;
- conversión dinámica a `template.HTML`;
- posibles credenciales enviadas a logging/salida;
- modos world-writable literales;
- `log.Fatal`/`os.Exit` dentro de lógica reutilizable;
- exposición potencial de `net/http/pprof`;
- URLs salientes que consumen directamente datos del request (señal SSRF);
- `http.Redirect` cuyo destino viene directamente del request;
- ejecutables seleccionados directamente desde request/CLI antes de `exec.Command`/`CommandContext`;
- MD5/SHA-1 aplicados a valores cuyos nombres sugieren contraseña, token, secreto o credencial;
- reflexión directa de `Origin` junto con `Access-Control-Allow-Credentials: true` dentro de la misma función;
- cookies con nombre sensible sin `Secure`/`HttpOnly` plenamente habilitados;
- comentarios Go con deuda explícita de seguridad.

Muchas de estas reglas producen `needs_validation`, porque el AST puede mostrar un sink pero no siempre puede establecer quién controla el dato o qué barrera existe aguas arriba. Para reducir ruido, el analizador reconoce algunos hechos source-visible que sí puede demostrar, por ejemplo nombres devueltos por `os.ReadDir`, rangos sobre listas estáticas y segmentos validados por una regex estricta como `^[A-Za-z0-9_-]{8,80}$` antes de alcanzar un sink de ruta.

## Analizador JavaScript/TypeScript

El módulo `javascript-typescript` usa el lexer Go puro de `github.com/tdewolff/parse/v2` para tokenizar `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts` y `.tsx`. DexAuditor no ejecuta Node.js, no instala dependencias del objetivo y no type-checkea el proyecto durante esta pasada.

La cobertura inicial detecta patrones alrededor de:

- `rejectUnauthorized: false` y `NODE_TLS_REJECT_UNAUTHORIZED=0`;
- `child_process.exec`/`execSync` con comandos dinámicos, incluyendo aliases de `import` y `require`;
- `eval` y `new Function`, separando cadenas estáticas como hardening de expresiones dinámicas por validar;
- HTML dinámico en `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` y `dangerouslySetInnerHTML`;
- `Math.random` usado para valores con nombres que sugieren token, secreto, nonce, sesión, OTP u otra credencial;
- SQL/ORM dinámico en `query`, `execute`, APIs raw y variantes `*Unsafe` cuando la sintaxis es source-visible;
- operaciones `fs` con `path.join`/`path.resolve` y segmentos dinámicos no confinados, reconociendo constantes, listas estáticas y nombres de `readdirSync` como hechos confiables locales;
- requests HTTP salientes que consumen directamente fuentes de menor confianza (señal SSRF);
- navegación del navegador (`location`, `window.open`) controlada directamente por URL/mensajería/request-like input;
- `postMessage` con `targetOrigin="*"` cuando el payload contiene identificadores aparentemente sensibles;
- claves de token/sesión/credencial almacenadas en `localStorage` o `sessionStorage`;
- redirects servidor directos desde datos de menor confianza;
- posibles credenciales enviadas a `console`/`logger`, diferenciando métricas como `tokenBudget`/`estimatedTokens` de secretos;
- `import()`/`require()` cuyo selector de módulo proviene directamente de entrada de menor confianza;
- código no estático pasado a APIs conocidas de `node:vm` (`runInContext`, `runInNewContext`, `runInThisContext`, `compileFunction`, `Script`);
- `spawn`/`execFile` con ejecutable seleccionado directamente desde entrada de menor confianza;
- reflexión directa de origen CORS junto con credenciales habilitadas en el mismo bloque de respuesta.

La regla de shell evita marcar comandos que DexAuditor puede demostrar como estáticos y también plantillas cuya única interpolación sea `process.pid` o `process.ppid`. DexAuditor no intenta inferir seguridad por nombres arbitrarios ni seguir dataflow entre funciones. Las reglas que muestran una fuente de menor confianza junto al sink permanecen `needs_validation`; en `DEXJS004`, HTML dinámico sin una fuente de menor confianza visible se degrada a `hardening`, mientras que sanitización HTML source-visible demostrable se suprime.

Los archivos de test JavaScript/TypeScript se tokenizan para inventario y cobertura, pero sus construcciones de runtime no se reportan como comportamiento productivo. Esto evita que fixtures de `eval`, TLS inseguro o `Math.random` inflen el reporte real.

## Archivos ignorados y límites

El descubrimiento no sigue symlinks y omite directorios regenerables/comunes como:

```text
.git
node_modules
vendor
dist
build
coverage
target
bin
obj
.next
.nuxt
.terraform
```

En un repositorio Git, DexAuditor usa por defecto el inventario de archivos versionados y no versionados que Git no considera ignorados. Esto evita tratar `.env`, bases locales, artefactos de build u otros archivos ignorados como si formaran parte del código distribuido. La consulta es solo de metadatos: no ejecuta código del proyecto. Si Git no está disponible o el objetivo no es un repositorio, se usa el recorrido físico con los filtros internos.

`--include-ignored` fuerza el recorrido físico para incluir también archivos ignorados, útil cuando se desea auditar explícitamente el estado local de una estación de trabajo. El reporte indica la fuente del inventario y los motivos de omisión.

Los archivos regulares mayores al límite configurado se omiten. `--exclude-tests` permite excluir `_test.go`, `testdata`, `tests`, `fixtures`, `__tests__`, `e2e`, `evals` y nombres `.test.*`/`.spec.*` cuando se desea una pasada más acotada. Cuando los tests Go o JavaScript/TypeScript sí se incluyen, se parsean o tokenizan para inventario/cobertura pero sus construcciones de runtime no generan hallazgos productivos del analizador específico. Las firmas genéricas de secretos de alta señal siguen pudiendo detectarse en fixtures de prueba.

## Agregar soporte para otro lenguaje

Un analizador implementa el contrato mínimo de `internal/audit`:

```go
type Analyzer interface {
    Name() string
    Applies(Project) bool
    Analyze(context.Context, Project, EmitFunc) (AnalysisResult, error)
}
```

Un módulo nuevo debe:

1. Activarse solo cuando exista una superficie compatible.
2. Usar el parser/AST oficial o una estrategia determinista adecuada al lenguaje cuando sea viable.
3. Devolver hallazgos con evidencia repository-relative y cobertura explícita.
4. Usar `needs_validation` cuando falte una frontera o efecto demostrable.
5. Marcar como `not_automated` lo que no pueda evaluar con honestidad.
6. Incluir fixtures positivos y negativos antes de registrarse en el CLI.

No se deben agregar analizadores vacíos solo para anunciar soporte futuro.

## Seguridad de ejecución

DexAuditor V1 es deliberadamente estático. No corre `go test`, builds, binarios, scripts, fuzzers ni fixtures del repositorio objetivo.

Esa decisión sigue un principio importante de la metodología de referencia: ejecutar código no confiable durante una auditoría requiere aislamiento fuerte de red, entorno, filesystem y recursos. Hasta que DexAuditor tenga un sandbox portable que pueda imponer esas garantías, cualquier hecho que dependa de ejecución debe permanecer en `needs_validation` o fuera de cobertura.

## Desarrollo

Validación local:

```bash
gofmt -w ./cmd ./internal
go test -count=1 ./...
go vet ./...
git diff --check
```

El proyecto mantiene `contexto/` para decisiones persistentes y `tareas/` para el estado del trabajo.

## Estado de la V1

DexAuditor ya fue calibrado contra varios repositorios reales del usuario, incluyendo proyectos Go y un repositorio grande principalmente TypeScript. Esas pasadas se usaron para corregir falsos positivos de `.env` ignorados, placeholders, fixtures de prueba, nombres ambiguos como `sessions`, componentes de ruta ya confinados, manejo de privilege-drop en Docker y consistencia del inventario/cobertura.

Las calibraciones read-only se realizan contra proyectos reales Go y JavaScript/TypeScript sin publicar nombres, rutas ni detalles de esos repositorios.

Ninguno de esos proyectos fue modificado ni ejecutado por DexAuditor durante la auditoría. Sus estados Git se compararon antes y después de las pasadas.

## Metodología de referencia

El diseño source-first, la separación entre evidencia confirmada y hechos pendientes de validación, y el énfasis en fronteras de confianza fueron inspirados por el proyecto público `cloudflare/security-audit-skill` de Cloudflare.

DexAuditor es una implementación determinista independiente y no reproduce el flujo de agentes/LLM del proyecto de referencia. Consulta `THIRD_PARTY_NOTICES.md` para la atribución correspondiente.
