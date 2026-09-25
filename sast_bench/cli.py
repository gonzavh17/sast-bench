"""sast-bench: correr, listar y comparar corridas del benchmark.

Todo por comandos con flags, sin menu interactivo: cada linea del README se
copia y se reproduce tal cual.

    sast-bench run --engine codeql --family secrets
    sast-bench history
    sast-bench show latest
    sast-bench compare <run-a> <run-b>
    sast-bench report <run-id>
    sast-bench doctor
    sast-bench corpus validate | stats

Es capa de interfaz: las metricas salen de scoring/metrics.py y los results
tienen el mismo formato que escriben los runners sueltos.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from runners import codeql as codeql_runner
from runners import semgrep as semgrep_runner
from sast_bench import corpus as corpus_checks
from sast_bench.diff import Change, cells, diff_scores
from sast_bench.doctor import MISSING, OK, WARN, run_checks
from sast_bench.estimate import count_findings, estimate
from sast_bench.runs import (
    DECISIONS,
    MANIFEST,
    RESULTS_DIR,
    RUNS_DIR,
    EngineRun,
    Run,
    decision_records,
    latest_results_for,
    list_runs,
    new_run_id,
    repo_state,
    resolve,
    results_filename,
    score_results,
    split_selector,
    summarize,
    write_json,
)
from scoring import compare as compare_md
from scoring import report as report_md
from scoring.console import (
    STYLES,
    cases_table,
    engine_label,
    export_svg,
    glossary,
    header,
    log_event,
    make_console,
    metrics_table,
    outcome_of,
    symbols_for,
    table_box,
)
from scoring.metrics import PairOutcome
from scoring.models import Case, Difficulty, Family, discover_cases
from scripts import fetch_codeql, fetch_rules
from scripts.fetch_codeql import REPO_ROOT

DEFAULT_MODEL = "claude-opus-5"  # el mismo que runners/hybrid.py
ENGINES = ("semgrep", "codeql", "hybrid")
EXT_SUITE = "runners/codeql-ext/security-extended-ext.qls"
FAMILY_ALIASES = {
    "xss": Family.XSS_SANITIZER_BYPASS,
    "secrets": Family.CLIENT_SIDE_SECRETS,
    "authz": Family.BROKEN_AUTHORIZATION,
}


class CliError(Exception):
    """Un error que se le muestra al usuario tal cual, sin traceback."""


# ---------------------------------------------------------------- helpers


def family_arg(value: str) -> Family:
    if value in FAMILY_ALIASES:
        return FAMILY_ALIASES[value]
    try:
        return Family(value)
    except ValueError:
        options = ", ".join([*FAMILY_ALIASES, *(f.value for f in Family)])
        raise argparse.ArgumentTypeError(f"familia desconocida {value!r}; opciones: {options}")


def repo_relative(path: Path) -> Path:
    """Resuelve contra el cwd del usuario y la deja relativa al repo si cae adentro.

    La CLI trabaja parada en la raiz del repo (los case_dir de los results son
    relativos a ella), asi que las rutas se resuelven antes del chdir.
    """
    absolute = path.expanduser().resolve()
    try:
        return absolute.relative_to(REPO_ROOT)
    except ValueError:
        return absolute


def local_time(iso: str) -> str:
    try:
        return dt.datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso or "?"


def triples(engines: list[EngineRun]) -> list[tuple[str, dict, Any]]:
    """El formato que esperan compare.render y las tablas de scoring/console.py."""
    return [(e.tool, e.results, e.score()) for e in engines]


def union_cases(engines: list[EngineRun]) -> list[Case]:
    by_id: dict[str, Case] = {}
    for engine in engines:
        for case in engine.cases():
            by_id.setdefault(case.meta.id, case)
    return sorted(by_id.values(), key=lambda c: c.meta.id)


def rules_line(results: dict[str, Any]) -> str:
    rules = results.get("rules", {})
    match rules.get("kind"):
        case "official":
            return f"{rules['repo']}@{rules['commit'][:12]}"
        case "bundle":
            return f"{rules['bundle']} · {rules['suite']}"
        case "custom":
            return f"custom: {rules['path']}"
    return "?"


# ---------------------------------------------------------------- run


def select_cases(corpus: Path, family: Family | None, difficulty: str | None, case_id: str | None) -> list[Case]:
    cases = discover_cases(corpus)
    if not cases:
        raise CliError(f"no hay ningun meta.yaml bajo {corpus}")
    if family:
        cases = [c for c in cases if c.meta.family == family]
    if difficulty:
        cases = [c for c in cases if c.meta.difficulty.value == difficulty]
    if case_id:
        cases = [c for c in cases if c.meta.id == case_id]
    if not cases:
        raise CliError("ningun caso cumple los filtros; `sast-bench corpus stats` muestra que hay")
    return cases


def preflight(engines: list[str], args: argparse.Namespace) -> list[str]:
    """Lo que falta para correr, con el comando que lo arregla."""
    problems = []
    if "semgrep" in engines:
        if shutil.which("semgrep") is None:
            problems.append("semgrep no esta instalado: uv sync")
        if not (fetch_rules.DEFAULT_DEST / fetch_rules.PROVENANCE).is_file():
            problems.append("faltan las reglas de semgrep: uv run python -m scripts.fetch_rules")
    if "codeql" in engines and not (fetch_codeql.DEFAULT_DEST / "codeql").is_file():
        problems.append("falta el bundle de CodeQL: uv run python -m scripts.fetch_codeql")
    if args.codeql_ext and not Path(EXT_SUITE).is_file():
        problems.append(f"falta la suite de la extension: {EXT_SUITE}")
    if "hybrid" in engines and not args.dry_run:
        from dotenv import load_dotenv

        load_dotenv(REPO_ROOT / ".env")
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if (not key or key.endswith("...")) and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            problems.append("el hibrido necesita ANTHROPIC_API_KEY en .env (ver .env.example)")
    return problems


def hybrid_base(
    args: argparse.Namespace, codeql_tool: str, case_ids: set[str], runs: list[Run]
) -> tuple[Run, EngineRun]:
    """La corrida de CodeQL que revisa el hibrido cuando no corre en la misma corrida."""
    if args.from_run:
        run = resolve(args.from_run, runs)
        engine = run.engine(codeql_tool)
        missing = case_ids - set(engine.case_ids)
        if missing:
            raise CliError(f"{run.run_id} no cubre {len(missing)} de los casos pedidos: {sorted(missing)[:3]}")
        return run, engine
    found = latest_results_for(codeql_tool, case_ids, runs)
    if found is None:
        raise CliError(
            f"no hay una corrida de {codeql_tool} que cubra estos casos; "
            "corre `--engine all` o primero `--engine codeql`"
        )
    return found


def only_cases(results: dict[str, Any], case_ids: set[str]) -> dict[str, Any]:
    """El mismo results, recortado a los casos pedidos."""
    return {**results, "variants": [v for v in results["variants"] if v["case_id"] in case_ids]}


def engine_tag(name: str) -> str:
    return f"  [cyan]{name:<11}[/cyan]"


INDENT = " " * 14  # continuacion debajo de engine_tag


def dry_run(
    console: Console,
    args: argparse.Namespace,
    engines: list[str],
    cases: list[Case],
    codeql_tool: str,
    suite: str,
    runs: list[Run],
) -> int:
    variants = [case.variant_dir(label) for case in cases for label in ("vulnerable", "safe")]
    case_ids = {c.meta.id for c in cases}
    console.print("[bold]dry-run[/bold]: no se ejecuta nada ni se escribe en results/", highlight=False)
    console.print(f"  corpus {args.corpus} · {filters_text(args)} · {len(cases)} casos · {len(variants)} variantes", highlight=False)

    for engine in engines:
        if engine == "semgrep":
            provenance = semgrep_runner.rules_provenance(fetch_rules.DEFAULT_DEST) if (
                fetch_rules.DEFAULT_DEST / fetch_rules.PROVENANCE
            ).is_file() else None
            rules = f"{provenance['repo']}@{provenance['commit'][:12]}" if provenance else "reglas faltantes"
            console.print(f"{engine_tag('semgrep')} {len(variants)} variantes · {rules}", highlight=False)
        elif engine == "codeql":
            console.print(
                f"{engine_tag(codeql_tool)} {len(variants)} variantes · {cache_forecast(variants, args.no_cache)}",
                highlight=False,
            )
            console.print(f"{INDENT}suite {suite}", highlight=False)
        elif engine == "hybrid":
            print_hybrid_estimate(console, args, engines, codeql_tool, case_ids, runs)

    problems = preflight(engines, args)
    for problem in problems:
        console.print(f"  [red]falta[/red] {problem}", highlight=False)
    return 1 if problems else 0


def cache_forecast(variants: list[Path], no_cache: bool) -> str:
    binary = fetch_codeql.DEFAULT_DEST / "codeql"
    if no_cache:
        return "cache desactivada: se construyen todas las bases"
    if not binary.is_file():
        return "sin CLI de CodeQL"
    version = codeql_runner.codeql_version(binary)
    hits = sum(
        (codeql_runner.CACHE_DIR / codeql_runner.variant_fingerprint(v, version) / "codeql-database.yml").is_file()
        for v in variants
    )
    return f"{hits} bases en cache, {len(variants) - hits} a construir"


def print_hybrid_estimate(
    console: Console,
    args: argparse.Namespace,
    engines: list[str],
    codeql_tool: str,
    case_ids: set[str],
    runs: list[Run],
) -> None:
    label = engine_tag(f"{codeql_tool}+llm")
    if "codeql" in engines:
        # CodeQL todavia no corrio: se usa la ultima corrida como referencia.
        found = latest_results_for(codeql_tool, case_ids, runs)
        basis = f"hallazgos de {found[0].run_id}; la corrida real puede dar otros" if found else None
    else:
        try:
            found = hybrid_base(args, codeql_tool, case_ids, runs)
            basis = f"revisa los hallazgos de {found[0].run_id}"
        except (CliError, LookupError) as error:
            console.print(f"{label} [red]{error}[/red]", highlight=False)
            return
    if found is None:
        console.print(f"{label} llamadas desconocidas: no hay una corrida previa de {codeql_tool} sobre estos casos", highlight=False)
        return

    calls = count_findings(found[1].results, case_ids)
    guess = estimate(calls, args.model, decision_records())
    cost = f"~US$ {guess.cost_usd:.2f}" if guess.cost_usd is not None else "precio desconocido para este modelo"
    console.print(
        f"{label} {calls} llamadas a {args.model} · ~{guess.input_tokens:,} tokens de entrada"
        f" + ~{guess.output_tokens:,} de salida · {cost}",
        highlight=False,
    )
    tokens = (
        f"promedio de {guess.sample} decisiones previas de {args.model}"
        if guess.sample
        else "tokens por llamada de referencia: no hay decisiones previas de este modelo"
    )
    console.print(f"{INDENT}{basis} · {tokens}", highlight=False)


def filters_text(args: argparse.Namespace) -> str:
    filters = run_filters(args)
    return " ".join(f"{k}={v}" for k, v in filters.items() if v) or "sin filtros"


def run_filters(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "family": args.family.value if args.family else None,
        "difficulty": args.difficulty,
        "case": args.case_id,
    }


def cmd_run(args: argparse.Namespace, console: Console) -> int:
    cases = select_cases(args.corpus, args.family, args.difficulty, args.case_id)
    engines = list(ENGINES) if args.engine == "all" else [args.engine]
    codeql_tool = "codeql+ext" if args.codeql_ext else "codeql"
    suite = EXT_SUITE if args.codeql_ext else fetch_codeql.SUITE
    runs = list_runs()

    if args.dry_run:
        return dry_run(console, args, engines, cases, codeql_tool, suite, runs)

    problems = preflight(engines, args)
    if problems:
        raise CliError("no se puede correr:\n  " + "\n  ".join(problems))

    case_ids = {c.meta.id for c in cases}
    base: tuple[dict[str, Any], str] | None = None
    if "hybrid" in engines and "codeql" not in engines:
        base_run, base_engine = hybrid_base(args, codeql_tool, case_ids, runs)
        base = (only_cases(base_engine.results, case_ids), str(base_engine.path.relative_to(REPO_ROOT)))

    now = dt.datetime.now(dt.UTC)
    run_id = new_run_id(now.astimezone())
    directory = RUNS_DIR / run_id
    manifest: dict[str, Any] = {
        "run_id": run_id,
        "status": "running",
        "started_at": now.isoformat(timespec="seconds"),
        "finished_at": None,
        "corpus": str(args.corpus),
        "filters": run_filters(args),
        "cases": sorted(case_ids),
        "repo": repo_state(),
        "engines": [],
    }
    write_json(directory / MANIFEST, manifest)
    log_event(console, "run", f"{run_id} · {len(cases)} casos · {', '.join(engines)} · {filters_text(args)}")

    def record(report: dict[str, Any], **extra: Any) -> Path:
        path = directory / results_filename(report["tool"])
        write_json(path, report)
        manifest["engines"].append(
            {
                "tool": report["tool"],
                "file": path.name,
                "tool_version": report["tool_version"],
                "rules": report["rules"],
                "model": extra.pop("model", None),
                **extra,
                "summary": summarize(score_results(report)),
            }
        )
        write_json(directory / MANIFEST, manifest)
        return path

    try:
        for engine in engines:
            if engine == "semgrep":
                record(semgrep_runner.scan(cases, fetch_rules.DEFAULT_DEST, console))
            elif engine == "codeql":
                stats: dict[str, int] = {}
                report = codeql_runner.scan(
                    cases,
                    fetch_codeql.DEFAULT_DEST,
                    suite,
                    console,
                    codeql_tool,
                    cache_dir=None if args.no_cache else codeql_runner.CACHE_DIR,
                    stats=stats,
                )
                path = record(report, cache=stats or None)
                base = (report, str(path.relative_to(REPO_ROOT)))
            elif engine == "hybrid":
                assert base is not None
                run_hybrid(console, args, cases, base, directory, record)
        manifest["status"] = "ok"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        manifest["finished_at"] = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
        write_json(directory / MANIFEST, manifest)

    console.print()
    run = resolve(run_id, list_runs())
    render_run(console, run)
    console.print(f"\nescrito {directory.relative_to(REPO_ROOT)}/", highlight=False)
    return 0


def run_hybrid(
    console: Console,
    args: argparse.Namespace,
    cases: list[Case],
    base: tuple[dict[str, Any], str],
    directory: Path,
    record: Any,
) -> None:
    import anthropic

    from runners import hybrid

    results, base_path = base
    calls = count_findings(results)
    guess = estimate(calls, args.model, decision_records())
    cost = f" · ~US$ {guess.cost_usd:.2f}" if guess.cost_usd is not None else ""
    log_event(console, "hibrido", f"{calls} hallazgos de {base_path} para revisar con {args.model}{cost}")

    filtered, records = hybrid.filter_results(
        results, base_path, {c.meta.id: c for c in cases}, anthropic.Anthropic(), args.model, console
    )
    (directory / DECISIONS).write_text(hybrid.dump_decisions(records), encoding="utf-8")
    record(
        filtered,
        model=args.model,
        base=base_path,
        decisions=DECISIONS,
        usage={
            "calls": len(records),
            "input_tokens": sum(r.input_tokens for r in records),
            "output_tokens": sum(r.output_tokens for r in records),
        },
    )


# ---------------------------------------------------------------- show / history


def render_run(console: Console, run: Run, engines: list[EngineRun] | None = None) -> None:
    engines = engines or run.engines
    if not engines:
        console.print(f"{run.run_id}: la corrida no tiene resultados ({run.status})", highlight=False)
        return
    rows = triples(engines)
    cases = union_cases(engines)

    kind = " · [dim]legacy[/dim]" if run.legacy else ""
    status = "" if run.status == "ok" else f" · [red]{run.status}[/red]"
    console.print(f"[bold]{run.run_id}[/bold] · {local_time(run.started_at)}{kind}{status}", highlight=False)
    repo = run.manifest.get("repo") or {}
    if repo.get("commit"):
        dirty = " (con cambios sin commitear)" if repo.get("dirty") else ""
        console.print(f"  repo {repo['commit'][:12]}{dirty}", highlight=False)
    for tool, results, _ in rows:
        console.print(f"  {engine_label(tool, results['tool_version'])} · {rules_line(results)}", highlight=False)
    console.print()
    header(console, corpus=run.corpus_label, runs=rows)
    console.print()
    glossary(console)
    console.print()
    console.print(cases_table(console, rows, cases))
    console.print(metrics_table(console, rows))


def cmd_show(args: argparse.Namespace, console: Console) -> int:
    run_id, tool = split_selector(args.run)
    run = resolve(run_id, list_runs())
    render_run(console, run, [run.engine(tool)] if tool else None)
    return 0


def engine_summary(run: Run, engine: EngineRun) -> str:
    for entry in run.manifest.get("engines", []):
        if entry.get("tool") == engine.tool and "summary" in entry:
            summary = entry["summary"]
            return f"{engine.tool} {summary['solved']}/{summary['pairs']}"
    try:
        score = engine.score()
    except FileNotFoundError:
        return f"{engine.tool} ?"
    return f"{engine.tool} {sum(p.solved for p in score.pairs)}/{len(score.pairs)}"


def cmd_history(args: argparse.Namespace, console: Console) -> int:
    runs = list_runs()
    if args.family:
        runs = [
            r
            for r in runs
            if any(args.family.value in v["case_dir"] for e in r.engines for v in e.results["variants"])
        ]
    if args.engine:
        runs = [r for r in runs if any(e.tool == args.engine for e in r.engines)]
    if not runs:
        console.print("no hay corridas que coincidan", highlight=False)
        return 0

    table = Table(box=table_box(console), pad_edge=False)
    for column in ("run-id", "fecha", "corpus", "engines", "resultado"):
        table.add_column(column, no_wrap=column != "corpus")
    for run in runs[: args.limit]:
        style = "dim" if run.legacy else ""
        result = " · ".join(engine_summary(run, e) for e in run.engines)
        if run.status != "ok":
            result = f"[red]{run.status}[/red] {result}".strip()
        table.add_row(
            f"[{style}]{run.run_id}[/{style}]" if style else run.run_id,
            local_time(run.started_at),
            run.corpus_label,
            ", ".join(e.tool for e in run.engines) or "—",
            result or "—",
        )
    console.print(table)
    shown = min(len(runs), args.limit)
    note = "gris = results sueltos de antes de la CLI · resultado = pares resueltos"
    console.print(f"[dim]{shown} de {len(runs)} corridas · {note}[/dim]", highlight=False)
    return 0


# ---------------------------------------------------------------- compare


def pick_pairs(a: Run, tool_a: str | None, b: Run, tool_b: str | None) -> list[tuple[EngineRun, EngineRun]]:
    """Que engine de cada corrida se compara con cual."""
    if tool_a or tool_b:
        left = a.engine(tool_a) if tool_a else None
        right = b.engine(tool_b) if tool_b else None
        if left is None:
            left = a.engine(right.tool) if len(a.engines) != 1 else a.engines[0]
        if right is None:
            right = b.engine(left.tool) if len(b.engines) != 1 else b.engines[0]
        return [(left, right)]
    common = [e.tool for e in a.engines if any(e.tool == f.tool for f in b.engines)]
    if common:
        return [(a.engine(t), b.engine(t)) for t in common]
    if len(a.engines) == 1 and len(b.engines) == 1:
        return [(a.engines[0], b.engines[0])]
    raise CliError(
        "las corridas no tienen engines en comun; elegi cuales con <run-id>:<engine>, "
        f"p. ej. {a.run_id}:{a.engines[0].tool}"
    )


def outcome_text(console: Console, pair: PairOutcome) -> str:
    key = outcome_of(pair)
    mark = getattr(symbols_for(console), key)
    return f"[{STYLES[key]}]{mark}[/{STYLES[key]}] {cells(pair)}"


def changes_table(console: Console, changes: list[Change], difficulties: dict[str, str]) -> Table:
    table = Table(box=table_box(console), pad_edge=False)
    for column in ("caso", "dificultad", "antes", "despues"):
        table.add_column(column, no_wrap=True)
    for change in changes:
        table.add_row(
            change.case_id,
            difficulties.get(change.case_id, "?"),
            outcome_text(console, change.before),
            outcome_text(console, change.after),
        )
    return table


def cmd_compare(args: argparse.Namespace, console: Console) -> int:
    runs = list_runs()
    id_a, tool_a = split_selector(args.run_a)
    id_b, tool_b = split_selector(args.run_b)
    a, b = resolve(id_a, runs), resolve(id_b, runs)

    for left, right in pick_pairs(a, tool_a, b, tool_b):
        score_a, score_b = left.score(), right.score()
        difficulties = {c.meta.id: c.meta.difficulty.value for c in union_cases([left, right])}
        console.print(
            f"[bold]A[/bold] {a.run_id}:{left.tool}  →  [bold]B[/bold] {b.run_id}:{right.tool}",
            highlight=False,
        )
        console.print(
            metrics_table(
                console,
                [(f"A {left.tool}", left.results, score_a), (f"B {right.tool}", right.results, score_b)],
            )
        )
        diff = diff_scores(score_a, score_b)
        sections = (
            ("pasaron de fallo a acierto", "green", diff.fixed),
            ("pasaron de acierto a fallo", "red", diff.broken),
            ("mismo par, otro resultado", "yellow", diff.shifted),
        )
        for title, style, changes in sections:
            console.print(f"[{style}]{title}[/{style}]: {len(changes)}", highlight=False)
            if changes:
                console.print(changes_table(console, changes, difficulties))
        console.print(f"sin cambios: {diff.unchanged} casos", highlight=False)
        if diff.only_before:
            console.print(f"solo en A: {', '.join(diff.only_before)}", highlight=False)
        if diff.only_after:
            console.print(f"solo en B: {', '.join(diff.only_after)}", highlight=False)
        console.print()
    return 0


# ---------------------------------------------------------------- report


def cmd_report(args: argparse.Namespace, console: Console) -> int:
    run = resolve(args.run, list_runs())
    if not run.engines:
        raise CliError(f"{run.run_id} no tiene resultados para reportar")
    out_dir = args.out_dir or run.directory or RESULTS_DIR / "reports" / run.run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = triples(run.engines)
    cases = union_cases(run.engines)
    sections = [report_md.render(score, results) for _, results, score in rows]
    if len(rows) > 1:
        sections.insert(0, compare_md.render(rows, cases))
    markdown = f"<!-- sast-bench report {run.run_id} -->\n\n" + "\n".join(sections)
    (out_dir / "report.md").write_text(markdown, encoding="utf-8")

    recorder = make_console(record=True)
    render_run(recorder, run)
    svg = out_dir / "report.svg"
    export_svg(recorder, svg, title=f"sast-bench {run.run_id}")

    for path in (out_dir / "report.md", svg):
        console.print(f"escrito {repo_relative(path)}", highlight=False)
    return 0


# ---------------------------------------------------------------- doctor / corpus


def cmd_doctor(args: argparse.Namespace, console: Console) -> int:
    checks = run_checks(args.corpus)
    marks = {OK: "[green]ok[/green]", WARN: "[yellow]aviso[/yellow]", MISSING: "[red]falta[/red]"}
    table = Table(box=table_box(console), pad_edge=False)
    for column in ("", "chequeo", "detalle"):
        table.add_column(column, no_wrap=column != "detalle")
    for check in checks:
        table.add_row(marks[check.status], check.name, check.detail)
    console.print(table)

    fixes = [c for c in checks if c.status != OK and c.fix]
    if fixes:
        console.print("\ncomo resolverlo:", highlight=False)
        for check in fixes:
            console.print(f"  {check.name}: [bold]{check.fix}[/bold]", highlight=False)
    return 1 if any(c.status == MISSING for c in checks) else 0


def cmd_corpus_validate(args: argparse.Namespace, console: Console) -> int:
    cases, problems = corpus_checks.validate(args.corpus)
    if not problems:
        console.print(f"[green]ok[/green] {len(cases)} pares validos en {args.corpus}", highlight=False)
        return 0
    table = Table(box=table_box(console), pad_edge=False)
    table.add_column("caso", no_wrap=True)
    table.add_column("problema")
    for problem in problems:
        table.add_row(str(repo_relative(Path(problem.where))), problem.message)
    console.print(table)
    console.print(f"[red]{len(problems)} problemas[/red] en {len(cases)} casos", highlight=False)
    return 1


def cmd_corpus_stats(args: argparse.Namespace, console: Console) -> int:
    cases, problems = corpus_checks.validate(args.corpus)
    counts = corpus_checks.distribution(cases)
    target = corpus_checks.PAIRS_PER_CELL

    table = Table(box=table_box(console), pad_edge=False)
    table.add_column("familia", no_wrap=True)
    for difficulty in Difficulty:
        table.add_column(difficulty.value, justify="right")
    table.add_column("total", justify="right")
    for family in Family:
        row = [family.value]
        for difficulty in Difficulty:
            n = counts[(family, difficulty)]
            row.append(str(n) if n >= target else f"[yellow]{n}[/yellow]")
        row.append(str(sum(counts[(family, d)] for d in Difficulty)))
        table.add_row(*row)
    table.add_row(
        "[bold]total[/bold]",
        *[str(sum(counts[(f, d)] for f in Family)) for d in Difficulty],
        f"[bold]{len(cases)}[/bold]",
    )
    console.print(table)
    console.print(f"{len(cases)} pares · {len(cases) * 2} variantes · objetivo {target} por celda", highlight=False)

    short = corpus_checks.short_cells(cases)
    broken = sorted({p.where for p in problems})
    if not short and not broken:
        console.print("incompletos: ninguno", highlight=False)
        return 0
    console.print("incompletos:", highlight=False)
    for family, difficulty, n in short:
        console.print(f"  [yellow]{family.value} / {difficulty.value}[/yellow]: {n} de {target} pares", highlight=False)
    for where in broken:
        console.print(f"  [red]{repo_relative(Path(where))}[/red]: `sast-bench corpus validate` dice por que", highlight=False)
    return 0


# ---------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast-bench",
        description="Benchmark de escaneres de seguridad sobre vulnerabilidades de Angular.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="comando")

    run = sub.add_parser("run", help="corre engines sobre el corpus")
    run.add_argument("--corpus", type=Path, default=Path("corpus/angular"), help="default: corpus/angular")
    run.add_argument("--engine", required=True, choices=[*ENGINES, "all"], help="all = semgrep, codeql e hybrid")
    run.add_argument("--family", type=family_arg, help="id de familia o alias: xss, secrets, authz")
    run.add_argument("--difficulty", choices=[d.value for d in Difficulty])
    run.add_argument("--case", dest="case_id", metavar="ID", help="un solo caso, p. ej. ng-sec-002")
    run.add_argument("--codeql-ext", action="store_true", help="CodeQL con runners/codeql-ext (fila codeql+ext)")
    run.add_argument("--model", default=DEFAULT_MODEL, help=f"modelo del hibrido (default {DEFAULT_MODEL})")
    run.add_argument("--from-run", metavar="RUN", help="hibrido sin codeql: corrida de la que sale la base")
    run.add_argument("--no-cache", action="store_true", help="reconstruye las bases de CodeQL")
    run.add_argument("--dry-run", action="store_true", help="muestra el plan y el costo estimado, sin ejecutar")
    run.set_defaults(handler=cmd_run)

    history = sub.add_parser("history", help="lista las corridas")
    history.add_argument("--family", type=family_arg)
    history.add_argument("--engine", help="solo corridas con este engine, p. ej. codeql+ext")
    history.add_argument("--limit", type=int, default=30)
    history.set_defaults(handler=cmd_history)

    show = sub.add_parser("show", help="imprime la tabla de una corrida")
    show.add_argument("run", nargs="?", default="latest", help="run-id, prefijo, latest, o <run-id>:<engine>")
    show.set_defaults(handler=cmd_show)

    compare = sub.add_parser("compare", help="que casos cambiaron entre dos corridas")
    compare.add_argument("run_a", metavar="RUN_A", help="run-id o <run-id>:<engine>")
    compare.add_argument("run_b", metavar="RUN_B", help="run-id o <run-id>:<engine>")
    compare.set_defaults(handler=cmd_compare)

    report = sub.add_parser("report", help="genera report.md y el SVG de una corrida")
    report.add_argument("run", help="run-id, prefijo o latest")
    report.add_argument("--out-dir", type=Path, help="default: la carpeta de la corrida")
    report.set_defaults(handler=cmd_report)

    doctor = sub.add_parser("doctor", help="chequea el entorno y dice que falta")
    doctor.add_argument("--corpus", type=Path, default=Path("corpus"))
    doctor.set_defaults(handler=cmd_doctor)

    corpus = sub.add_parser("corpus", help="validar y contar el corpus")
    corpus_sub = corpus.add_subparsers(dest="corpus_command", required=True, metavar="accion")
    validate = corpus_sub.add_parser("validate", help="los chequeos de meta.yaml de tests/test_meta.py")
    validate.add_argument("--corpus", type=Path, default=Path("corpus"))
    validate.set_defaults(handler=cmd_corpus_validate)
    stats = corpus_sub.add_parser("stats", help="pares por familia y dificultad, y cuales faltan")
    stats.add_argument("--corpus", type=Path, default=Path("corpus"))
    stats.set_defaults(handler=cmd_corpus_stats)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for name in ("corpus", "out_dir"):
        if isinstance(getattr(args, name, None), Path):
            setattr(args, name, repo_relative(getattr(args, name)))

    # Los case_dir de los results son relativos a la raiz del repo, y semgrep
    # vive en el venv aunque nadie lo haya activado.
    os.chdir(REPO_ROOT)
    os.environ["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"

    console = make_console()
    try:
        return args.handler(args, console)
    except (CliError, LookupError, FileNotFoundError) as error:
        console.print(f"[red]error:[/red] {error}", highlight=False)
        return 1


if __name__ == "__main__":
    sys.exit(main())
