"""sast-bench: run, list and compare benchmark runs.

Everything is commands and flags, no interactive menu: every line in the
README can be copied and reproduced as is.

    sast-bench run --engine codeql --family secrets
    sast-bench history
    sast-bench show latest
    sast-bench compare <run-a> <run-b>
    sast-bench report <run-id>
    sast-bench doctor
    sast-bench corpus validate | stats

It is an interface layer: metrics come from scoring/metrics.py and results
have the same format the standalone runners write.
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

DEFAULT_MODEL = "claude-opus-5"  # same as runners/hybrid.py
ENGINES = ("semgrep", "codeql", "hybrid")
EXT_SUITE = "runners/codeql-ext/security-extended-ext.qls"
FAMILY_ALIASES = {
    "xss": Family.XSS_SANITIZER_BYPASS,
    "secrets": Family.CLIENT_SIDE_SECRETS,
    "authz": Family.BROKEN_AUTHORIZATION,
}


class CliError(Exception):
    """An error shown to the user as is, without a traceback."""


# ---------------------------------------------------------------- helpers


def family_arg(value: str) -> Family:
    if value in FAMILY_ALIASES:
        return FAMILY_ALIASES[value]
    try:
        return Family(value)
    except ValueError:
        options = ", ".join([*FAMILY_ALIASES, *(f.value for f in Family)])
        raise argparse.ArgumentTypeError(f"unknown family {value!r}; options: {options}")


def repo_relative(path: Path) -> Path:
    """Resolve against the user's cwd and make it repo-relative if it falls inside.

    The CLI works from the repo root (results' case_dirs are relative to it),
    so paths are resolved before the chdir.
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
    """The shape compare.render and the scoring/console.py tables expect."""
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
        raise CliError(f"no meta.yaml under {corpus}")
    if family:
        cases = [c for c in cases if c.meta.family == family]
    if difficulty:
        cases = [c for c in cases if c.meta.difficulty.value == difficulty]
    if case_id:
        cases = [c for c in cases if c.meta.id == case_id]
    if not cases:
        raise CliError("no case matches the filters; `sast-bench corpus stats` shows what there is")
    return cases


def preflight(engines: list[str], args: argparse.Namespace) -> list[str]:
    """What is missing to run, with the command that fixes it."""
    problems = []
    if "semgrep" in engines:
        if shutil.which("semgrep") is None:
            problems.append("semgrep is not installed: uv sync")
        if not (fetch_rules.DEFAULT_DEST / fetch_rules.PROVENANCE).is_file():
            problems.append("the semgrep rules are missing: uv run python -m scripts.fetch_rules")
    if "codeql" in engines and not (fetch_codeql.DEFAULT_DEST / "codeql").is_file():
        problems.append("the CodeQL bundle is missing: uv run python -m scripts.fetch_codeql")
    if args.codeql_ext and not Path(EXT_SUITE).is_file():
        problems.append(f"the extension suite is missing: {EXT_SUITE}")
    if "hybrid" in engines and not args.dry_run:
        from dotenv import load_dotenv

        load_dotenv(REPO_ROOT / ".env")
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if (not key or key.endswith("...")) and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            problems.append("the hybrid needs ANTHROPIC_API_KEY in .env (see .env.example)")
    return problems


def hybrid_base(
    args: argparse.Namespace, codeql_tool: str, case_ids: set[str], runs: list[Run]
) -> tuple[Run, EngineRun]:
    """The CodeQL run the hybrid reviews when CodeQL is not part of the same run."""
    if args.from_run:
        run = resolve(args.from_run, runs)
        engine = run.engine(codeql_tool)
        missing = case_ids - set(engine.case_ids)
        if missing:
            raise CliError(f"{run.run_id} does not cover {len(missing)} of the requested cases: {sorted(missing)[:3]}")
        return run, engine
    found = latest_results_for(codeql_tool, case_ids, runs)
    if found is None:
        raise CliError(
            f"no {codeql_tool} run covers these cases; "
            "run `--engine all`, or `--engine codeql` first"
        )
    return found


def only_cases(results: dict[str, Any], case_ids: set[str]) -> dict[str, Any]:
    """The same results, trimmed to the requested cases."""
    return {**results, "variants": [v for v in results["variants"] if v["case_id"] in case_ids]}


def engine_tag(name: str) -> str:
    return f"  [cyan]{name:<11}[/cyan]"


INDENT = " " * 14  # continuation under engine_tag


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
    console.print("[bold]dry-run[/bold]: nothing runs and nothing is written to results/", highlight=False)
    console.print(f"  corpus {args.corpus} · {filters_text(args)} · {len(cases)} cases · {len(variants)} variants", highlight=False)

    for engine in engines:
        if engine == "semgrep":
            provenance = semgrep_runner.rules_provenance(fetch_rules.DEFAULT_DEST) if (
                fetch_rules.DEFAULT_DEST / fetch_rules.PROVENANCE
            ).is_file() else None
            rules = f"{provenance['repo']}@{provenance['commit'][:12]}" if provenance else "rules missing"
            console.print(f"{engine_tag('semgrep')} {len(variants)} variants · {rules}", highlight=False)
        elif engine == "codeql":
            console.print(
                f"{engine_tag(codeql_tool)} {len(variants)} variants · {cache_forecast(variants, args.no_cache)}",
                highlight=False,
            )
            console.print(f"{INDENT}suite {suite}", highlight=False)
        elif engine == "hybrid":
            print_hybrid_estimate(console, args, engines, codeql_tool, case_ids, runs)

    problems = preflight(engines, args)
    for problem in problems:
        console.print(f"  [red]missing[/red] {problem}", highlight=False)
    return 1 if problems else 0


def cache_forecast(variants: list[Path], no_cache: bool) -> str:
    binary = fetch_codeql.DEFAULT_DEST / "codeql"
    if no_cache:
        return "cache disabled: every database gets built"
    if not binary.is_file():
        return "no CodeQL CLI"
    version = codeql_runner.codeql_version(binary)
    hits = sum(
        (codeql_runner.CACHE_DIR / codeql_runner.variant_fingerprint(v, version) / "codeql-database.yml").is_file()
        for v in variants
    )
    return f"{hits} databases cached, {len(variants) - hits} to build"


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
        # CodeQL has not run yet: the latest run is used as a reference.
        found = latest_results_for(codeql_tool, case_ids, runs)
        basis = f"findings from {found[0].run_id}; the real run may differ" if found else None
    else:
        try:
            found = hybrid_base(args, codeql_tool, case_ids, runs)
            basis = f"reviews the findings from {found[0].run_id}"
        except (CliError, LookupError) as error:
            console.print(f"{label} [red]{error}[/red]", highlight=False)
            return
    if found is None:
        console.print(f"{label} unknown number of calls: no previous {codeql_tool} run over these cases", highlight=False)
        return

    calls = count_findings(found[1].results, case_ids)
    guess = estimate(calls, args.model, decision_records())
    cost = f"~US$ {guess.cost_usd:.2f}" if guess.cost_usd is not None else "unknown price for this model"
    console.print(
        f"{label} {calls} calls to {args.model} · ~{guess.input_tokens:,} input tokens"
        f" + ~{guess.output_tokens:,} output · {cost}",
        highlight=False,
    )
    tokens = (
        f"average of {guess.sample} previous {args.model} decisions"
        if guess.sample
        else "reference tokens per call: no previous decisions for this model"
    )
    console.print(f"{INDENT}{basis} · {tokens}", highlight=False)


def filters_text(args: argparse.Namespace) -> str:
    filters = run_filters(args)
    return " ".join(f"{k}={v}" for k, v in filters.items() if v) or "no filters"


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
        raise CliError("cannot run:\n  " + "\n  ".join(problems))

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
    log_event(console, "run", f"{run_id} · {len(cases)} cases · {', '.join(engines)} · {filters_text(args)}")

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
    console.print(f"\nwrote {directory.relative_to(REPO_ROOT)}/", highlight=False)
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
    log_event(console, "hybrid", f"{calls} findings from {base_path} to review with {args.model}{cost}")

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
        console.print(f"{run.run_id}: the run has no results ({run.status})", highlight=False)
        return
    rows = triples(engines)
    cases = union_cases(engines)

    kind = " · [dim]legacy[/dim]" if run.legacy else ""
    status = "" if run.status == "ok" else f" · [red]{run.status}[/red]"
    console.print(f"[bold]{run.run_id}[/bold] · {local_time(run.started_at)}{kind}{status}", highlight=False)
    repo = run.manifest.get("repo") or {}
    if repo.get("commit"):
        dirty = " (with uncommitted changes)" if repo.get("dirty") else ""
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
        console.print("no matching runs", highlight=False)
        return 0

    table = Table(box=table_box(console), pad_edge=False)
    for column in ("run-id", "date", "corpus", "engines", "result"):
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
    note = "dim = loose results from before the CLI · result = solved pairs"
    console.print(f"[dim]{shown} of {len(runs)} runs · {note}[/dim]", highlight=False)
    return 0


# ---------------------------------------------------------------- compare


def pick_pairs(a: Run, tool_a: str | None, b: Run, tool_b: str | None) -> list[tuple[EngineRun, EngineRun]]:
    """Which engine of each run is compared with which."""
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
        "the runs have no engine in common; pick them with <run-id>:<engine>, "
        f"e.g. {a.run_id}:{a.engines[0].tool}"
    )


def outcome_text(console: Console, pair: PairOutcome) -> str:
    key = outcome_of(pair)
    mark = getattr(symbols_for(console), key)
    return f"[{STYLES[key]}]{mark}[/{STYLES[key]}] {cells(pair)}"


def changes_table(console: Console, changes: list[Change], difficulties: dict[str, str]) -> Table:
    table = Table(box=table_box(console), pad_edge=False)
    for column in ("case", "difficulty", "before", "after"):
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
            ("newly solved", "green", diff.fixed),
            ("no longer solved", "red", diff.broken),
            ("still unsolved, different cells", "yellow", diff.shifted),
        )
        for title, style, changes in sections:
            console.print(f"[{style}]{title}[/{style}]: {len(changes)}", highlight=False)
            if changes:
                console.print(changes_table(console, changes, difficulties))
        console.print(f"unchanged: {diff.unchanged} cases", highlight=False)
        if diff.only_before:
            console.print(f"only in A: {', '.join(diff.only_before)}", highlight=False)
        if diff.only_after:
            console.print(f"only in B: {', '.join(diff.only_after)}", highlight=False)
        console.print()
    return 0


# ---------------------------------------------------------------- report


def cmd_report(args: argparse.Namespace, console: Console) -> int:
    run = resolve(args.run, list_runs())
    if not run.engines:
        raise CliError(f"{run.run_id} has no results to report")
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
        console.print(f"wrote {repo_relative(path)}", highlight=False)
    return 0


# ---------------------------------------------------------------- doctor / corpus


def cmd_doctor(args: argparse.Namespace, console: Console) -> int:
    checks = run_checks(args.corpus)
    marks = {OK: "[green]ok[/green]", WARN: "[yellow]warning[/yellow]", MISSING: "[red]missing[/red]"}
    table = Table(box=table_box(console), pad_edge=False)
    for column in ("", "check", "detail"):
        table.add_column(column, no_wrap=column != "detail")
    for check in checks:
        table.add_row(marks[check.status], check.name, check.detail)
    console.print(table)

    fixes = [c for c in checks if c.status != OK and c.fix]
    if fixes:
        console.print("\nhow to fix it:", highlight=False)
        for check in fixes:
            console.print(f"  {check.name}: [bold]{check.fix}[/bold]", highlight=False)
    return 1 if any(c.status == MISSING for c in checks) else 0


def cmd_corpus_validate(args: argparse.Namespace, console: Console) -> int:
    cases, problems = corpus_checks.validate(args.corpus)
    if not problems:
        console.print(f"[green]ok[/green] {len(cases)} valid pairs in {args.corpus}", highlight=False)
        return 0
    table = Table(box=table_box(console), pad_edge=False)
    table.add_column("case", no_wrap=True)
    table.add_column("problem")
    for problem in problems:
        table.add_row(str(repo_relative(Path(problem.where))), problem.message)
    console.print(table)
    console.print(f"[red]{len(problems)} problems[/red] in {len(cases)} cases", highlight=False)
    return 1


def cmd_corpus_stats(args: argparse.Namespace, console: Console) -> int:
    cases, problems = corpus_checks.validate(args.corpus)
    counts = corpus_checks.distribution(cases)
    target = corpus_checks.PAIRS_PER_CELL

    table = Table(box=table_box(console), pad_edge=False)
    table.add_column("family", no_wrap=True)
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
    console.print(f"{len(cases)} pairs · {len(cases) * 2} variants · target {target} per cell", highlight=False)

    short = corpus_checks.short_cells(cases)
    broken = sorted({p.where for p in problems})
    if not short and not broken:
        console.print("incomplete: none", highlight=False)
        return 0
    console.print("incomplete:", highlight=False)
    for family, difficulty, n in short:
        console.print(f"  [yellow]{family.value} / {difficulty.value}[/yellow]: {n} of {target} pairs", highlight=False)
    for where in broken:
        console.print(f"  [red]{repo_relative(Path(where))}[/red]: `sast-bench corpus validate` says why", highlight=False)
    return 0


# ---------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sast-bench",
        description="Benchmark of security scanners on Angular vulnerabilities.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    run = sub.add_parser("run", help="run engines over the corpus")
    run.add_argument("--corpus", type=Path, default=Path("corpus/angular"), help="default: corpus/angular")
    run.add_argument("--engine", required=True, choices=[*ENGINES, "all"], help="all = semgrep, codeql and hybrid")
    run.add_argument("--family", type=family_arg, help="family id or alias: xss, secrets, authz")
    run.add_argument("--difficulty", choices=[d.value for d in Difficulty])
    run.add_argument("--case", dest="case_id", metavar="ID", help="a single case, e.g. ng-sec-002")
    run.add_argument("--codeql-ext", action="store_true", help="CodeQL with runners/codeql-ext (row codeql+ext)")
    run.add_argument("--model", default=DEFAULT_MODEL, help=f"hybrid model (default {DEFAULT_MODEL})")
    run.add_argument("--from-run", metavar="RUN", help="hybrid without codeql: the run to take the base from")
    run.add_argument("--no-cache", action="store_true", help="rebuild the CodeQL databases")
    run.add_argument("--dry-run", action="store_true", help="show the plan and the estimated cost, without running")
    run.set_defaults(handler=cmd_run)

    history = sub.add_parser("history", help="list the runs")
    history.add_argument("--family", type=family_arg)
    history.add_argument("--engine", help="only runs with this engine, e.g. codeql+ext")
    history.add_argument("--limit", type=int, default=30)
    history.set_defaults(handler=cmd_history)

    show = sub.add_parser("show", help="print the table of a run")
    show.add_argument("run", nargs="?", default="latest", help="run-id, prefix, latest, or <run-id>:<engine>")
    show.set_defaults(handler=cmd_show)

    compare = sub.add_parser("compare", help="which cases changed between two runs")
    compare.add_argument("run_a", metavar="RUN_A", help="run-id or <run-id>:<engine>")
    compare.add_argument("run_b", metavar="RUN_B", help="run-id or <run-id>:<engine>")
    compare.set_defaults(handler=cmd_compare)

    report = sub.add_parser("report", help="write report.md and the SVG of a run")
    report.add_argument("run", help="run-id, prefix or latest")
    report.add_argument("--out-dir", type=Path, help="default: the run directory")
    report.set_defaults(handler=cmd_report)

    doctor = sub.add_parser("doctor", help="check the environment and say what is missing")
    doctor.add_argument("--corpus", type=Path, default=Path("corpus"))
    doctor.set_defaults(handler=cmd_doctor)

    corpus = sub.add_parser("corpus", help="validate and count the corpus")
    corpus_sub = corpus.add_subparsers(dest="corpus_command", required=True, metavar="action")
    validate = corpus_sub.add_parser("validate", help="the meta.yaml checks from tests/test_meta.py")
    validate.add_argument("--corpus", type=Path, default=Path("corpus"))
    validate.set_defaults(handler=cmd_corpus_validate)
    stats = corpus_sub.add_parser("stats", help="pairs per family and difficulty, and which are missing")
    stats.add_argument("--corpus", type=Path, default=Path("corpus"))
    stats.set_defaults(handler=cmd_corpus_stats)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for name in ("corpus", "out_dir"):
        if isinstance(getattr(args, name, None), Path):
            setattr(args, name, repo_relative(getattr(args, name)))

    # Results' case_dirs are relative to the repo root, and semgrep lives in
    # the venv even if nobody activated it.
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
