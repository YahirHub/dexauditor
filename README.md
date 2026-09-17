# DexAuditor

DexAuditor es un CLI de auditoría estática **source-first**, escrito 100% en Go y diseñado para compilarse en múltiples plataformas. Analiza un repositorio sin usar modelos LLM y emite resultados progresivos para personas o consumidores automatizados.

La V1 incluye un analizador genérico de repositorio/configuración y un analizador específico para Go basado en AST. La arquitectura permite agregar analizadores de otros lenguajes cuando exista cobertura real para ellos, sin crear módulos vacíos por adelantado.

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

- `covered`: se ejecutaron reglas deterministas para esa clase; no significa cobertura semántica exhaustiva.
- `partial`: parte de la superficie no pudo analizarse, por ejemplo por archivos Go que no parsean.
- `blocked`: el analizador encontró una condición que impidió completar su trabajo.
- `not_applicable`: la superficie no existe en el proyecto.
- `not_automated`: DexAuditor declara explícitamente que esa clase requiere razonamiento que la V1 no automatiza.

Para Go, Access control, Business logic y Chained vulnerabilities/trust boundaries se reportan deliberadamente como `not_automated`.

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
- comentarios Go con deuda explícita de seguridad.

Muchas de estas reglas producen `needs_validation`, porque el AST puede mostrar un sink pero no siempre puede establecer quién controla el dato o qué barrera existe aguas arriba.

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

Los archivos regulares mayores al límite configurado se omiten. `--exclude-tests` permite excluir `_test.go`, `testdata`, `tests`, `fixtures` y `__tests__` cuando se desea una pasada más acotada.

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

DexAuditor ya fue probado contra un repositorio Go real. Esa prueba se usó para corregir falsos positivos de placeholders, nombres ambiguos como `sessions`, manejo de privilege-drop en Docker y consistencia del conteo de hallazgos únicos.

El proyecto objetivo no fue modificado ni ejecutado durante esa validación.

## Metodología de referencia

El diseño source-first, la separación entre evidencia confirmada y hechos pendientes de validación, y el énfasis en fronteras de confianza fueron inspirados por el proyecto público `cloudflare/security-audit-skill` de Cloudflare.

DexAuditor es una implementación determinista independiente y no reproduce el flujo de agentes/LLM del proyecto de referencia. Consulta `THIRD_PARTY_NOTICES.md` para la atribución correspondiente.
