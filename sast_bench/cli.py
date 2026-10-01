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
from runners.providers import DEFAULT_MODEL as PROVIDER_DEFAULTS
from runners.providers import NIM_KEY_ENV, PROVIDERS, ProviderError, make_provider
from sast_bench.estimate import Estimate, count_findings, estimate, estimate_llm, usage_costs
from sast_bench.runs import (
    DECISIONS,
    MANIFEST,
    RESULTS_DIR,
    RUNS_DIR,
    Cost,
    EngineRun,
    Run,
    engine_cost,
    decision_records,
    latest_results_for,
    list_runs,
    llm_records,
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

DEFAULT_MODEL = PROVIDER_DEFAULTS["anthropic"]
ENGINES = ("semgrep", "codeql", "hybrid")  # what `--engine all` runs
LLM_ARMS = ("blind", "guided")
EFFORTS = ("low", "medium", "high", "xhigh", "max")
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
        case "prompt":
            effort = f" effort={rules['effort']}" if rules.get("effort") else ""
            return f"{rules['arm']} prompt{effort}"
        case "auditor":
            return f"funnel up to {rules['stop_after'] or 'skeptic'}"
    return "?"


# ---------------------------------------------------------------- run


def select_cases(corpus: Path, family: Family | None, difficulty: str | None, case_ids: list[str] | None) -> list[Case]:
    cases = discover_cases(corpus)
    if not cases:
        raise CliError(f"no meta.yaml under {corpus}")
    if family:
        cases = [c for c in cases if c.meta.family == family]
    if difficulty:
        cases = [c for c in cases if c.meta.difficulty.value == difficulty]
    if case_ids:
        cases = [c for c in cases if c.meta.id in case_ids]
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
    if uses_model(engines, args):
        if not args.model:
            problems.append(f"--model is required with --provider {args.provider} (or SAST_BENCH_MODEL)")
        if not args.dry_run:
            from dotenv import load_dotenv

            load_dotenv(REPO_ROOT / ".env")
            if args.provider == "nim":
                if not os.environ.get(NIM_KEY_ENV):
                    problems.append(f"the nim provider needs {NIM_KEY_ENV} in .env (see .env.example)")
            else:
                key = os.environ.get("ANTHROPIC_API_KEY", "")
                if (not key or key.endswith("...")) and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
                    problems.append("the hybrid and llm engines need ANTHROPIC_API_KEY in .env (see .env.example)")
    return problems


def uses_model(engines: list[str], args: argparse.Namespace | None = None) -> bool:
    if "hybrid" in engines or "llm" in engines:
        return True
    return "auditor" in engines and (args is None or getattr(args, "stop_after", None) != "slice")


def is_debug(args: argparse.Namespace, engines: list[str]) -> bool:
    """A run that calls a debug provider is a debug run, whatever else it runs."""
    return uses_model(engines, args) and args.provider != "anthropic"


def cost_text(guess: Estimate, provider: str) -> str:
    if provider != "anthropic":
        opus = guess.opus_equivalent_usd
        return "US$ 0 (debug)" + (f" · ~US$ {opus:.2f} with Opus" if opus is not None else "")
    return f"~US$ {guess.cost_usd:.2f}" if guess.cost_usd is not None else "unknown price for this model"


def model_label(args: argparse.Namespace) -> str:
    return args.model if args.provider == "anthropic" else f"{args.provider}:{args.model}"


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


def standalone_base(
    args: argparse.Namespace, codeql_tool: str, case_ids: set[str], runs: list[Run]
) -> tuple[str, dict[str, Any], str]:
    """What the hybrid reviews when the base engine is not part of the same run.

    Either a results file (`--base-results`, e.g. one of results/merged/) or an
    engine of a previous run (`--from-run`, `--base-engine`; CodeQL by default).
    Returns (where it came from, results, repo-relative path).
    """
    if args.base_results:
        path = Path(args.base_results)
        if not path.is_file():
            raise CliError(f"no results file at {path}")
        import json

        results = json.loads(path.read_text(encoding="utf-8"))
        missing = case_ids - {e["case_id"] for e in results["variants"]}
        if missing:
            raise CliError(f"{path} does not cover {len(missing)} of the requested cases: {sorted(missing)[:3]}")
        return str(path), results, str(path)
    run, engine = hybrid_base(args, args.base_engine or codeql_tool, case_ids, runs)
    return run.run_id, engine.results, str(engine.path.relative_to(REPO_ROOT))


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
        elif engine == "llm":
            print_llm_estimate(console, args, variants)
        elif engine == "auditor":
            print_auditor_estimate(console, args, cases)

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
    base_tool = codeql_tool if "codeql" in engines else (args.base_engine or codeql_tool)
    label = engine_tag(f"{base_tool}+llm")
    if "codeql" in engines:
        # CodeQL has not run yet: the latest run is used as a reference.
        found = latest_results_for(codeql_tool, case_ids, runs)
        if found is None:
            console.print(f"{label} unknown number of calls: no previous {codeql_tool} run over these cases", highlight=False)
            return
        basis, base_results = f"findings from {found[0].run_id}; the real run may differ", found[1].results
    else:
        try:
            origin, base_results, _ = standalone_base(args, codeql_tool, case_ids, runs)
        except (CliError, LookupError) as error:
            console.print(f"{label} [red]{error}[/red]", highlight=False)
            return
        label = engine_tag(f"{base_results['tool']}+llm")
        basis = f"reviews the findings from {origin}"

    calls = count_findings(base_results, case_ids)
    guess = estimate(calls, args.model, decision_records())
    cost = cost_text(guess, args.provider)
    console.print(
        f"{label} {calls} calls to {model_label(args)} · ~{guess.input_tokens:,} input tokens"
        f" + ~{guess.output_tokens:,} output · {cost}",
        highlight=False,
    )
    tokens = (
        f"average of {guess.sample} previous {args.model} decisions"
        if guess.sample
        else "reference tokens per call: no previous decisions for this model"
    )
    console.print(f"{INDENT}{basis} · {tokens}", highlight=False)


def llm_arms(args: argparse.Namespace) -> tuple[str, ...]:
    return LLM_ARMS if args.arm == "both" else (args.arm,)


def print_llm_estimate(console: Console, args: argparse.Namespace, variants: list[Path]) -> None:
    from runners.hybrid import build_context

    contexts = [build_context(v) for v in variants]
    history = llm_records()
    for arm in llm_arms(args):
        guess = estimate(0, args.model, []) if not contexts else estimate_llm(contexts, args.model, arm, history)
        cost = cost_text(guess, args.provider)
        effort = f" effort={args.effort}" if args.effort else ""
        console.print(
            f"{engine_tag(f'llm-{arm}')} {guess.calls} calls to {model_label(args)}{effort} · "
            f"~{guess.input_tokens:,} input tokens + ~{guess.output_tokens:,} output · {cost}",
            highlight=False,
        )
        tokens = (
            f"average of {guess.sample} previous {args.model} {arm} responses"
            if guess.sample
            else f"input from code size, output a reference of {guess.output_per_call:,} tokens per call"
        )
        console.print(f"{INDENT}{tokens}", highlight=False)


def filters_text(args: argparse.Namespace) -> str:
    filters = run_filters(args)
    return " ".join(f"{k}={v}" for k, v in filters.items() if v) or "no filters"


def run_filters(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "family": args.family.value if args.family else None,
        "difficulty": args.difficulty,
        "case": ",".join(args.case_id) if args.case_id else None,
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
        _, base_results, base_path = standalone_base(args, codeql_tool, case_ids, runs)
        base = (only_cases(base_results, case_ids), base_path)

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
        "provider": args.provider if uses_model(engines, args) else None,
        "debug": is_debug(args, engines),
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
            elif engine == "llm":
                run_llm(console, args, cases, directory, record)
            elif engine == "auditor":
                run_auditor(console, args, cases, directory, record)
        manifest["status"] = "ok"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        manifest["finished_at"] = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
        write_json(directory / MANIFEST, manifest)

    console.print()
    run = resolve(run_id, list_runs(include_debug=True))
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
    from runners import hybrid

    provider = make_provider(args.provider, args.model)
    results, base_path = base
    calls = count_findings(results)
    guess = estimate(calls, args.model, decision_records())
    log_event(
        console,
        "hybrid",
        f"{calls} findings from {base_path} to review with {model_label(args)} · {cost_text(guess, args.provider)}",
    )

    filtered, records = hybrid.filter_results(
        results, base_path, {c.meta.id: c for c in cases}, provider, console, trail=directory / DECISIONS
    )
    (directory / DECISIONS).write_text(hybrid.dump_decisions(records), encoding="utf-8")
    record(
        filtered,
        model=args.model,
        provider=args.provider,
        base=base_path,
        decisions=DECISIONS,
        usage=usage_block(args, records),
    )


def usage_block(args: argparse.Namespace, records: list[Any]) -> dict[str, Any]:
    """Tokens, stop reasons and cost, for the manifest."""
    tokens_in = sum(r.input_tokens for r in records)
    tokens_out = sum(r.output_tokens for r in records)
    reasons = [getattr(r, "stop_reason", None) for r in records]
    return {
        "calls": len(records),
        "refusals": reasons.count("refusal"),
        "format_errors": reasons.count("format_error"),
        "input_tokens": tokens_in,
        "output_tokens": tokens_out,
        **usage_costs(args.provider, args.model, tokens_in, tokens_out),
    }


def print_auditor_estimate(console: Console, args: argparse.Namespace, cases: list[Case]) -> None:
    from auditor.funnel import measure

    rows = measure(cases)
    slices = sum(r.slices for r in rows)
    tokens = sum(r.slice_tokens for r in rows)
    console.print(
        f"{engine_tag('auditor')} {slices} slices ({tokens:,} tokens) · triage {slices} calls · "
        f"analysis up to {slices} · skeptic one per finding",
        highlight=False,
    )
    if args.stop_after != "slice":
        console.print(f"{INDENT}models: {model_label(args)} (triage {args.triage_model or args.model}, skeptic {args.skeptic_model or args.model})", highlight=False)


def run_auditor(
    console: Console,
    args: argparse.Namespace,
    cases: list[Case],
    directory: Path,
    record: Any,
) -> None:
    from auditor.funnel import survival
    from auditor.pipeline import STAGES, Providers, StageUsage, audit

    providers = None
    if args.stop_after != "slice":
        providers = Providers(
            triage=make_provider(args.provider, args.triage_model or args.model),
            analysis=make_provider(args.provider, args.model),
            skeptic=make_provider(args.provider, args.skeptic_model or args.model),
        )
    label = providers.label() if providers else "no model"
    variants: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    totals = {stage: StageUsage() for stage in STAGES}

    for case in cases:
        for variant in ("vulnerable", "safe"):
            result = audit(case.variant_dir(variant), providers, stop_after=args.stop_after)
            variants.append(
                {
                    "case_id": case.meta.id,
                    "case_dir": str(case.directory),
                    "variant": variant,
                    "findings": [f.model_dump() for f in result.findings],
                }
            )
            row = survival(case, variant, result)
            rows.append(row)
            decisions += [{"case_id": case.meta.id, "variant": variant, **d} for d in result.decisions]
            for stage in STAGES:
                for name in ("calls", "input_tokens", "output_tokens", "format_errors"):
                    setattr(totals[stage], name, getattr(totals[stage], name) + getattr(result.usage[stage], name))
            log_event(console, "auditor", f"{case.meta.id} {variant:10} {survival_text(row)}")
            write_json(directory / "auditor-funnel.json", rows)
            write_json(directory / "auditor-decisions.json", decisions)

    report = {
        "tool": "auditor",
        "tool_version": label,
        "run_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "rules": {"kind": "auditor", "stop_after": args.stop_after, "providers": label},
        "variants": variants,
    }
    stages = {}
    for stage, usage in totals.items():
        model = {"triage": args.triage_model, "skeptic": args.skeptic_model}.get(stage) or args.model
        stages[stage] = {
            "model": model,
            "calls": usage.calls,
            "format_errors": usage.format_errors,
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            **(usage_costs(args.provider, model, usage.input_tokens, usage.output_tokens) if model else {}),
        }
    total_cost = [v.get("cost_usd") for v in stages.values()]
    total_opus = [v.get("opus_equivalent_usd") for v in stages.values()]
    record(
        report,
        model=args.model,
        provider=args.provider if providers else None,
        stop_after=args.stop_after,
        funnel="auditor-funnel.json",
        decisions="auditor-decisions.json",
        stages=stages,
        usage={
            "calls": sum(u.calls for u in totals.values()),
            "format_errors": sum(u.format_errors for u in totals.values()),
            "input_tokens": sum(u.input_tokens for u in totals.values()),
            "output_tokens": sum(u.output_tokens for u in totals.values()),
            "cost_usd": None if None in total_cost else round(sum(total_cost), 4),
            "opus_equivalent_usd": None if None in total_opus else round(sum(total_opus), 4),
        },
    )
    print_survival(console, rows, label)


def survival_text(row: dict[str, Any]) -> str:
    if row["variant"] == "vulnerable":
        stages = [s for s in ("rules", "slice", "triage", "analysis", "skeptic") if s in row]
        lost = next((s for s in stages[1:] if not row[s]), None)
        return f"{row['slices']} slices · " + ("[green]survives[/green]" if lost is None else f"[red]lost at {lost}[/red]")
    flagged = row.get("flagged_after_skeptic")
    return f"{row['slices']} slices · " + ("[yellow]flagged[/yellow]" if flagged else "clean")


def print_survival(console: Console, rows: list[dict[str, Any]], label: str) -> None:
    """How many real vulnerabilities survive each stage, and how many safe twins stay flagged."""
    vulnerable = [r for r in rows if r["variant"] == "vulnerable"]
    safe = [r for r in rows if r["variant"] == "safe"]
    n = len(vulnerable)
    parts = []
    for stage in ("rules", "slice", "triage", "analysis", "skeptic"):
        if vulnerable and stage in vulnerable[0]:
            parts.append(f"{stage} {sum(bool(r[stage]) for r in vulnerable)}/{n}")
    console.print("vulnerable lines surviving each stage: " + " → ".join(parts), highlight=False)
    if safe and "flagged_after_analysis" in safe[0]:
        console.print(
            f"safe twins flagged: after analysis {sum(r['flagged_after_analysis'] for r in safe)}/{len(safe)}"
            f" → after skeptic {sum(r['flagged_after_skeptic'] for r in safe)}/{len(safe)}",
            highlight=False,
        )
    console.print(f"[dim]{label}[/dim]", highlight=False)


def run_llm(
    console: Console,
    args: argparse.Namespace,
    cases: list[Case],
    directory: Path,
    record: Any,
) -> None:
    from runners import llm

    provider = make_provider(args.provider, args.model)
    for arm in llm_arms(args):
        responses = f"llm-{arm}-responses.json"
        results, records = llm.scan(cases, arm, provider, args.effort, console, trail=directory / responses)
        write_json(directory / responses, [r.model_dump() for r in records])
        record(
            results,
            model=args.model,
            provider=args.provider,
            arm=arm,
            effort=args.effort,
            responses=responses,
            usage=usage_block(args, records),
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
    console.print(metrics_table(console, rows, costs_for(run, engines, rows)))


def resolve_run(selector: str, include_debug: bool) -> Run:
    """Resolve a run, and say so when the one asked for is a hidden debug run."""
    try:
        return resolve(selector, list_runs(include_debug=include_debug))
    except LookupError:
        if include_debug:
            raise
        try:
            hidden = resolve(selector, list_runs(include_debug=True))
        except LookupError:
            raise
        raise CliError(f"{hidden.run_id} is a debug run; add --include-debug to use it") from None


def cost_cells(cost: Cost, solved: int) -> tuple[str, str]:
    """(cost, pairs per dollar) for the metrics table."""
    if cost.usd is None:
        return "—", "—"
    if cost.debug:
        opus = f" (~US$ {cost.opus_equivalent:.2f} Opus)" if cost.opus_equivalent is not None else ""
        return f"US$ 0{opus}", "debug"
    if cost.usd == 0:
        return "US$ 0", "free"
    return f"US$ {cost.usd:.2f}", f"{solved / cost.usd:.1f}"


def cost_short(cost: Cost) -> str:
    if cost.usd is None or cost.usd == 0 and not cost.debug:
        return ""
    return " · debug" if cost.debug else f" · US$ {cost.usd:.2f}"


def costs_for(run: Run, engines: list[EngineRun], rows: list[tuple[str, dict, Any]]) -> list[tuple[str, str]]:
    return [
        cost_cells(engine_cost(run, engine), sum(p.solved for p in score.pairs))
        for engine, (_, _, score) in zip(engines, rows)
    ]


def cmd_show(args: argparse.Namespace, console: Console) -> int:
    run_id, tool = split_selector(args.run)
    run = resolve_run(run_id, args.include_debug)
    render_run(console, run, [run.engine(tool)] if tool else None)
    return 0


def engine_summary(run: Run, engine: EngineRun) -> str:
    for entry in run.manifest.get("engines", []):
        if entry.get("tool") == engine.tool and "summary" in entry:
            summary = entry["summary"]
            return f"{engine.tool} {summary['solved']}/{summary['pairs']}{cost_short(engine_cost(run, engine))}"
    try:
        score = engine.score()
    except FileNotFoundError:
        return f"{engine.tool} ?"
    solved = sum(p.solved for p in score.pairs)
    return f"{engine.tool} {solved}/{len(score.pairs)}{cost_short(engine_cost(run, engine))}"


def cmd_history(args: argparse.Namespace, console: Console) -> int:
    runs = list_runs(include_debug=args.include_debug)
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
        if not result and run.manifest.get("funnel"):
            f = run.manifest["funnel"]
            result = f"funnel: slice shows sink {f['slice_has_sink']}/{f['vulnerable']} · {f['slice_tokens']:,} tokens"
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
    runs = list_runs(include_debug=args.include_debug)
    id_a, tool_a = split_selector(args.run_a)
    id_b, tool_b = split_selector(args.run_b)
    a, b = resolve_run(id_a, args.include_debug), resolve_run(id_b, args.include_debug)

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
                [
                    cost_cells(engine_cost(a, left), sum(p.solved for p in score_a.pairs)),
                    cost_cells(engine_cost(b, right), sum(p.solved for p in score_b.pairs)),
                ],
            )
        )
        cost_a, cost_b = engine_cost(a, left), engine_cost(b, right)
        if cost_a.usd and cost_b.usd and not (cost_a.debug or cost_b.debug):
            change = (cost_b.usd - cost_a.usd) / cost_a.usd
            console.print(f"cost: US$ {cost_a.usd:.2f} → US$ {cost_b.usd:.2f} ({change:+.0%})", highlight=False)
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
    run = resolve_run(args.run, args.include_debug)
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


# ---------------------------------------------------------------- funnel


def cmd_funnel(args: argparse.Namespace, console: Console) -> int:
    """Rules + slices over the corpus, no model: where each vulnerable line survives or is lost."""
    from auditor.funnel import measure, to_json

    cases = select_cases(args.corpus, args.family, args.difficulty, args.case_id)
    rows = measure(cases)
    vulnerable = [r for r in rows if r.variant == "vulnerable"]

    table = Table(box=table_box(console), pad_edge=False)
    for column in ("case", "difficulty", "candidates", "rules at sink", "slice has sink", "slices", "tokens"):
        table.add_column(column, no_wrap=True, justify="left" if column in ("case", "difficulty") else "right")
    mark = {True: "[green]yes[/green]", False: "[red]no[/red]", None: "—"}
    by_case: dict[str, dict[str, Any]] = {}
    for row in rows:
        by_case.setdefault(row.case_id, {})[row.variant] = row
    for case_id, pair in sorted(by_case.items()):
        v, s = pair["vulnerable"], pair["safe"]
        table.add_row(
            case_id,
            v.difficulty,
            f"{v.candidates} / {s.candidates}",
            mark[v.rules_hit],
            mark[v.slice_hit],
            f"{v.slices} / {s.slices}",
            f"{v.slice_tokens + s.slice_tokens:,} of {v.full_tokens + s.full_tokens:,}",
        )
    console.print(table)
    slice_tokens = sum(r.slice_tokens for r in rows)
    full_tokens = sum(r.full_tokens for r in rows)
    summary = {
        "rules_at_sink": sum(bool(r.rules_hit) for r in vulnerable),
        "slice_has_sink": sum(bool(r.slice_hit) for r in vulnerable),
        "vulnerable": len(vulnerable),
        "slices": sum(r.slices for r in rows),
        "variants": len(rows),
        "slice_tokens": slice_tokens,
        "full_tokens": full_tokens,
    }
    console.print(
        f"rules at the sink: {summary['rules_at_sink']}/{len(vulnerable)} · "
        f"a slice shows the sink: {summary['slice_has_sink']}/{len(vulnerable)} · "
        f"{summary['slices']} slices for {len(rows)} variants · "
        f"{slice_tokens:,} tokens in slices vs {full_tokens:,} reading every variant whole",
        highlight=False,
    )
    console.print("[dim]candidates, slices and tokens are vulnerable / safe; no model was called[/dim]", highlight=False)

    now = dt.datetime.now(dt.UTC)
    run_id = new_run_id(now.astimezone())
    directory = RUNS_DIR / run_id
    write_json(directory / "funnel.json", to_json(rows))
    write_json(
        directory / MANIFEST,
        {
            "run_id": run_id,
            "status": "ok",
            "kind": "funnel",
            "started_at": now.isoformat(timespec="seconds"),
            "corpus": str(args.corpus),
            "filters": run_filters(args),
            "repo": repo_state(),
            "provider": None,
            "debug": False,
            "funnel": summary,
            "engines": [],
        },
    )
    console.print(f"wrote {directory.relative_to(REPO_ROOT)}/", highlight=False)
    return 0


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
    run.add_argument(
        "--engine",
        required=True,
        choices=[*ENGINES, "llm", "auditor", "all"],
        help="all = semgrep, codeql and hybrid; llm (the model alone) only runs when asked for",
    )
    run.add_argument("--family", type=family_arg, help="family id or alias: xss, secrets, authz")
    run.add_argument("--difficulty", choices=[d.value for d in Difficulty])
    run.add_argument("--case", dest="case_id", metavar="ID", action="append", help="one case, e.g. ng-sec-002; repeat for several")
    run.add_argument("--codeql-ext", action="store_true", help="CodeQL with runners/codeql-ext (row codeql+ext)")
    run.add_argument(
        "--provider",
        choices=PROVIDERS,
        default=os.environ.get("SAST_BENCH_PROVIDER", "anthropic"),
        help="LLM provider for hybrid and llm (default anthropic, or SAST_BENCH_PROVIDER); nim runs are debug runs",
    )
    run.add_argument(
        "--model",
        default=os.environ.get("SAST_BENCH_MODEL"),
        help=f"model for hybrid and llm (default {DEFAULT_MODEL} with anthropic, or SAST_BENCH_MODEL; required with nim)",
    )
    run.add_argument("--from-run", metavar="RUN", help="hybrid without codeql: the run to take the base from")
    run.add_argument("--base-engine", metavar="TOOL", help="hybrid with --from-run: which engine to review (default codeql)")
    run.add_argument("--base-results", metavar="FILE", type=Path, help="hybrid: review this results file instead of a run")
    run.add_argument("--arm", choices=[*LLM_ARMS, "both"], default="both", help="llm engine: which arm (default both)")
    run.add_argument(
        "--stop-after",
        choices=("slice", "triage", "analysis"),
        help="auditor engine: stop after this stage (slice runs no model)",
    )
    run.add_argument("--triage-model", help="auditor engine: model for the triage stage (default: --model)")
    run.add_argument("--skeptic-model", help="auditor engine: model for the skeptic stage (default: --model)")
    run.add_argument("--effort", choices=EFFORTS, help="llm engine: output_config.effort (default: the model's)")
    run.add_argument("--no-cache", action="store_true", help="rebuild the CodeQL databases")
    run.add_argument("--dry-run", action="store_true", help="show the plan and the estimated cost, without running")
    run.set_defaults(handler=cmd_run)

    history = sub.add_parser("history", help="list the runs")
    history.add_argument("--family", type=family_arg)
    history.add_argument("--engine", help="only runs with this engine, e.g. codeql+ext")
    history.add_argument("--limit", type=int, default=30)
    history.add_argument("--include-debug", action="store_true", help="also list debug runs (nim)")
    history.set_defaults(handler=cmd_history)

    show = sub.add_parser("show", help="print the table of a run")
    show.add_argument("run", nargs="?", default="latest", help="run-id, prefix, latest, or <run-id>:<engine>")
    show.add_argument("--include-debug", action="store_true", help="allow debug runs (nim)")
    show.set_defaults(handler=cmd_show)

    compare = sub.add_parser("compare", help="which cases changed between two runs")
    compare.add_argument("run_a", metavar="RUN_A", help="run-id or <run-id>:<engine>")
    compare.add_argument("run_b", metavar="RUN_B", help="run-id or <run-id>:<engine>")
    compare.add_argument("--include-debug", action="store_true", help="allow debug runs (nim)")
    compare.set_defaults(handler=cmd_compare)

    report = sub.add_parser("report", help="write report.md and the SVG of a run")
    report.add_argument("run", help="run-id, prefix or latest")
    report.add_argument("--out-dir", type=Path, help="default: the run directory")
    report.add_argument("--include-debug", action="store_true", help="allow debug runs (nim)")
    report.set_defaults(handler=cmd_report)

    funnel = sub.add_parser("funnel", help="measure rules + slices on the corpus, without any model")
    funnel.add_argument("--corpus", type=Path, default=Path("corpus/angular"))
    funnel.add_argument("--family", type=family_arg)
    funnel.add_argument("--difficulty", choices=[d.value for d in Difficulty])
    funnel.add_argument("--case", dest="case_id", metavar="ID", action="append")
    funnel.set_defaults(handler=cmd_funnel)

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
    if getattr(args, "provider", None) and not args.model:
        args.model = PROVIDER_DEFAULTS.get(args.provider)
    for name in ("corpus", "out_dir", "base_results"):
        if isinstance(getattr(args, name, None), Path):
            setattr(args, name, repo_relative(getattr(args, name)))

    # Results' case_dirs are relative to the repo root, and semgrep lives in
    # the venv even if nobody activated it.
    os.chdir(REPO_ROOT)
    os.environ["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{os.environ.get('PATH', '')}"

    console = make_console()
    try:
        return args.handler(args, console)
    except (CliError, LookupError, FileNotFoundError, ProviderError) as error:
        console.print(f"[red]error:[/red] {error}", highlight=False)
        return 1


if __name__ == "__main__":
    sys.exit(main())
