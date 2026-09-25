# sast-bench

Benchmark de escáneres de seguridad sobre vulnerabilidades de Angular. Mide
cuánto encuentran de lo que hay **y cuánto marcan de más**: cada caso vulnerable
tiene un gemelo sano con el mismo patrón bien hecho, y un par solo cuenta si la
herramienta acierta en los dos.

El diseño completo está en [PROJECT.md](PROJECT.md).

## Instalación

```bash
uv sync
uv run python -m scripts.fetch_rules    # reglas de Semgrep (no se redistribuyen)
uv run python -m scripts.fetch_codeql   # bundle de CodeQL (no se redistribuye)
cp .env.example .env                    # solo si vas a correr el híbrido
uv run sast-bench doctor                # dice qué falta y cómo resolverlo
```

## Comandos

```bash
# Correr
sast-bench run --engine semgrep                       # todo el corpus
sast-bench run --engine codeql --family secrets       # una familia (xss, secrets, authz)
sast-bench run --engine all --difficulty decoy        # una dificultad
sast-bench run --engine codeql --case ng-sec-011      # un solo caso
sast-bench run --engine codeql --codeql-ext           # CodeQL + la extensión de runners/codeql-ext
sast-bench run --engine hybrid --family xss --dry-run # llamadas y costo estimado, sin ejecutar

# Mirar
sast-bench history                                    # todas las corridas
sast-bench show latest                                # la tabla de una corrida
sast-bench compare <run-a> <run-b>                    # qué casos cambiaron de resultado
sast-bench compare <run-a>:codeql <run-b>:codeql+ext  # elegir engine dentro de cada corrida
sast-bench report <run-id>                            # report.md + report.svg

# Corpus
sast-bench corpus validate                            # los chequeos de meta.yaml
sast-bench corpus stats                               # pares por familia y dificultad
```

Con `uv run` delante si el venv no está activado. `sast-bench <comando> --help`
lista todas las opciones.

### Engines

| engine | qué es |
|---|---|
| `semgrep` | Semgrep OSS con las reglas oficiales de JS/TS, en un commit fijo |
| `codeql` | CodeQL con `javascript-security-extended` |
| `hybrid` | CodeQL + un LLM que revisa cada hallazgo y descarta falsas alarmas. Usa la clave de `.env` |

`--engine all` corre los tres en orden; el híbrido revisa lo que acaba de
encontrar CodeQL. Con `--engine hybrid` solo, revisa la última corrida de CodeQL
que cubra los mismos casos, o la que indiques con `--from-run`.

### Corridas

Cada `run` crea `results/runs/<run-id>/` con el results de cada engine (mismo
formato que siempre) y un `manifest.json` que registra: commit del repo, filtros,
casos, versión de cada engine, commit o bundle de las reglas, modelo y consumo
del híbrido, y cuántas bases de CodeQL salieron de la caché.

Los results sueltos de antes de la CLI (`results/*.json`) aparecen en `history`
como corridas `legacy`.

### Caché de CodeQL

Construir la base de cada variante es lo más lento de una corrida. Las bases se
guardan en `.cache/codeql-db/`, con el contenido de la variante y la versión de
CodeQL como clave: si no cambió nada, solo se corre el análisis. `--no-cache`
reconstruye todo.

## Licencia

MIT. Las reglas de Semgrep y la CLI de CodeQL tienen sus propias licencias y no
viajan en el repo; ver `scripts/`.
