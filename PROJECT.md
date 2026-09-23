# sast-bench

Benchmark para medir qué tan bien detectan los escáneres de seguridad las
vulnerabilidades específicas de Angular. Mide dos cosas: **cuánto encuentran de
lo que hay** y **cuánto marcan de más**. Lo segundo casi ningún benchmark lo
reporta, y es lo que más duele en la práctica.

Existe RealVuln para Python y el OWASP Benchmark para Java. Para Angular no hay
nada equivalente. Ese es el hueco.

**Enfoque defensivo**: encontrar fallas en código propio para arreglarlas.

---

## Alcance v1

Tres familias de vulnerabilidades. El resto queda para después.

| id | familia | qué cubre |
|---|---|---|
| `xss-sanitizer-bypass` | XSS y escapes del sanitizador | marcar contenido como confiable a mano, HTML crudo en el DOM, manipulación directa del DOM esquivando el framework, URLs sin validar esquema |
| `client-side-secrets` | datos sensibles del lado del cliente | secretos en archivos de configuración, tokens en el almacenamiento del navegador, datos en estado o logs |
| `broken-authorization` | autorización mal ubicada | guards como única protección, UI por rol sin validación detrás, confiar en algo que el usuario puede modificar |

**Preparado para otros ecosistemas, sin abstraer todavía**: corpus por carpeta,
campo `ecosystem` en cada caso, scoring que recibe la ruta del corpus como
parámetro. Nada de capas de abstracción hasta que haya un segundo ecosistema real.

---

## Fase 1 — Corpus

36 pares etiquetados a mano = **72 variantes**.

### Regla de los gemelos

Por cada caso vulnerable existe su gemelo sano: el mismo patrón hecho bien.
Así se mide si la herramienta entiende el patrón o solo reconoce una forma.

### Distribución

|                       | obvio | indirecto | señuelo | total |
|-----------------------|-------|-----------|---------|-------|
| `xss-sanitizer-bypass`  | 4     | 4         | 4       | 12    |
| `client-side-secrets`   | 4     | 4         | 4       | 12    |
| `broken-authorization`  | 4     | 4         | 4       | 12    |
|                       |       |           |         | **36 pares** |

- **obvio** — el dato va del source al sink de forma directa.
- **indirecto** — el dato pasa por varias funciones antes de llegar al sink.
- **señuelo** — ambas variantes tienen validación visible; la del lado vulnerable
  es insuficiente. Mide si la herramienta *lee* la validación o solo ve que existe.
  El par se mantiene: no hay casos sueltos sin gemelo.

### Formato en disco

Carpeta por par, metadata compartida. El vínculo entre gemelos es la carpeta misma.

```
corpus/angular/xss-sanitizer-bypass/001-bypass-security-trust-html/
  meta.yaml
  vulnerable/
    profile.component.ts
    profile.component.html
  safe/
    profile.component.ts
    profile.component.html
```

```yaml
# meta.yaml
id: ng-xss-001
ecosystem: angular
family: xss-sanitizer-bypass
cwe: CWE-79
difficulty: obvious          # obvious | indirect | decoy
source: authored            # authored | oss
variants:
  vulnerable:
    label: vulnerable
    sink: {file: vulnerable/profile.component.ts, line: 24}
    rationale: >
      bypassSecurityTrustHtml aplicado a un valor que viene del
      query param sin sanitizar.
  safe:
    label: safe
    rationale: >
      Mismo render, usando binding [textContent]; Angular escapa por defecto.
```

### Restricciones del corpus

- **Cada variante es autocontenida**: la cadena source → sink vive dentro de los
  archivos de esa variante. Sin esto, las herramientas que resuelven imports
  quedan con ventaja arbitraria y los casos `indirect` no son comparables.
- Los casos los escribo yo o salen de proyectos open source (`source: oss`,
  con atribución). **Nada de código de trabajo.**
- `tests/` valida el `meta.yaml` de cada caso: campos obligatorios, familia y
  dificultad dentro del enum, rutas de `sink` existentes, ambas variantes presentes.

---

## Fase 2 — Scoring

Corre herramientas de reglas y LLMs contra el corpus y saca los números.
**Esta fase es publicable sola.**

### Herramientas de reglas

| herramienta | por qué está |
|---|---|
| **Semgrep OSS** | baseline obvio: reglas TS/Angular, corre local, salida SARIF |
| **CodeQL** (`javascript-typescript`) | el único con taint tracking real; debería brillar en los casos `indirect` |
| **ESLint** (`@angular-eslint` + `eslint-plugin-security`) | no es SAST, pero es lo que la mayoría de los equipos Angular ya tiene puesto. Es el piso: cuánto agarrás sin instalar nada nuevo |

Cada runner normaliza su salida a un `Finding` común: `{path, line, rule_id, severity}`.

### Matching — cuándo cuenta un acierto

Granularidad **caso + familia**. La precisión de ubicación se reporta aparte y
no castiga el recall.

```
TP  = variante vulnerable con >=1 hallazgo mapeado a la familia esperada
FN  = variante vulnerable sin ningún hallazgo de esa familia
FP  = variante safe con >=1 hallazgo de cualquier familia de seguridad
TN  = variante safe limpia
```

Requiere una tabla `rule_id → familia` por herramienta, en `scoring/rule_map/`,
mantenida a mano y versionada. Es la pieza más frágil del scoring: se documenta
qué versión de reglas se mapeó y cuándo.

### Métricas

**Titular — pair score:**

```
pair score = pares con (TP en vulnerable Y TN en safe) / 36
```

Una herramienta con recall 100% y FPR 100% saca pair score 0. Eso es exactamente
lo que el benchmark quiere mostrar.

**Siempre al lado:**

```
recall    = TP / (TP + FN)
FPR       = FP / (FP + TN)          <- sobre los gemelos sanos
precision = TP / (TP + FP)
F1
```

**Desglose:** por familia (3) y por dificultad (3), más:

```
localización = % de TPs cuyo hallazgo cae en sink.line ± 3
ruido        = hallazgos extra por variante
```

### LLMs

**Dos brazos**, el mismo corpus corrido dos veces. Separa "no sabe mirar" de
"no sabe qué buscar", y el brazo ciego es el único comparable de verdad contra
las herramientas de reglas.

- **A — ciego**: *"Sos un revisor de seguridad. Analizá este código Angular y
  reportá las vulnerabilidades que encuentres. Si no hay ninguna, devolvé una
  lista vacía."* No se nombran las familias.
- **B — guiado**: el mismo código más las tres familias descriptas. Mide el techo
  con el scope acotado.

En ambos brazos se pasa **una variante sola**, sin decir si es la vulnerable o la
sana. Structured output vía `output_config.format`:

```json
{"findings": [{"family": "...", "line": 0, "severity": "...", "rationale": "..."}]}
```

**Ejes a barrer** (una sola corrida por celda; sin repeticiones en v1):

| eje | valores |
|---|---|
| tier | `claude-opus-5`, `claude-sonnet-5`, `claude-haiku-4-5` |
| effort | `low` / `high` / `xhigh` sobre `claude-opus-5` |

Notas de API: thinking adaptativo (`thinking: {type: "adaptive"}`) en los modelos
que lo soportan; `output_config.effort` solo aplica a los modelos de la familia 5
— `claude-haiku-4-5` corre sin ese parámetro y queda fuera del barrido de effort.
Un solo proveedor en v1.

La clave de API va en `.env`, fuera del repo. `.env.example` versionado.

---

## Fase 3 — Analizador híbrido (opcional)

Reglas para la primera pasada + un LLM que revisa cada hallazgo y descarta falsas
alarmas. Se mide contra el mismo corpus, con las mismas métricas, y entra como
una fila más en la tabla de la fase 2.

Es la última fase. Si las fases 1 y 2 salen bien, esto es un extra; no es el
entregable.

---

## Stack y estructura

Python + `uv`. El corpus es Angular; el harness no necesita serlo.

```
sast-bench/
  corpus/
    angular/
      xss-sanitizer-bypass/001-.../
      client-side-secrets/...
      broken-authorization/...
  runners/
    semgrep.py  codeql.py  eslint.py
    llm.py
  scoring/
    normalize.py        # salida de cada herramienta -> Finding común
    rule_map/           # semgrep.yaml, codeql.yaml, eslint.yaml
    metrics.py
    report.py
  results/
    2026-09-22-semgrep.json   2026-09-22-codeql.json
    report-semgrep.md        report-codeql.md
    compare.md               # tabla lado a lado + solapamiento
  tests/                # valida el meta.yaml de cada caso
  pyproject.toml
  .env.example
```

El scoring recibe la ruta del corpus como parámetro (`--corpus corpus/angular`),
no la hardcodea.

---

## Abierto

- Mantenimiento del `rule_map`: se congela por versión de reglas o se regenera
  en cada corrida.
- Cómo se mapea la taxonomía libre del brazo ciego del LLM a las tres familias
  (a mano, o pidiendo el `family` del enum en el schema y aceptando `other`).
- Qué proyectos open source se usan como fuente para los casos `source: oss`.
