"""Corridas: donde se guardan, como se listan y como se leen.

Una corrida de la CLI es una carpeta `results/runs/<run-id>/` con:

    manifest.json          quien corrio, cuando, sobre que, con que filtros
    <tool>.json            el results de cada engine, en el formato de siempre
    hybrid-decisions.json  el rastro del filtro LLM, si corrio

El manifest va aparte a proposito: el JSON de resultados no cambia de formato.

Los results sueltos de antes de la CLI (`results/2026-09-22-codeql.json` y
compania) aparecen como corridas `legacy`, una por archivo, con el nombre del
archivo como run-id. No se mueven ni se renombran.
"""

from __future__ import annotations

import datetime as dt
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scoring.metrics import Score, tally
from scoring.models import Case, load_case, load_rule_map
from scripts.fetch_codeql import REPO_ROOT

RESULTS_DIR = REPO_ROOT / "results"
RUNS_DIR = RESULTS_DIR / "runs"
RULE_MAP_DIR = REPO_ROOT / "scoring" / "rule_map"
MANIFEST = "manifest.json"
DECISIONS = "hybrid-decisions.json"


@dataclass
class EngineRun:
    """El results de un engine dentro de una corrida."""

    tool: str
    path: Path
    results: dict[str, Any]

    @property
    def case_ids(self) -> list[str]:
        return sorted({entry["case_id"] for entry in self.results["variants"]})

    def cases(self) -> list[Case]:
        """Los casos que cubre este results, leidos del corpus tal como esta hoy."""
        return cases_of(self.results)

    def score(self) -> Score:
        return score_results(self.results)


@dataclass
class Run:
    run_id: str
    started_at: str
    legacy: bool
    engines: list[EngineRun]
    directory: Path | None = None
    manifest: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        return self.manifest.get("status", "ok")

    @property
    def corpus_label(self) -> str:
        if self.manifest:
            label = self.manifest.get("corpus", "?")
            filters = {k: v for k, v in self.manifest.get("filters", {}).items() if v}
            if filters:
                label += " " + " ".join(f"{k}={v}" for k, v in filters.items())
            return label
        return corpus_label_of(self.engines)

    def engine(self, tool: str) -> EngineRun:
        for engine in self.engines:
            if engine.tool == tool:
                return engine
        available = ", ".join(e.tool for e in self.engines) or "ninguno"
        raise LookupError(f"la corrida {self.run_id} no tiene {tool} (tiene: {available})")


# ---------------------------------------------------------------- lectura


def cases_of(results: dict[str, Any]) -> list[Case]:
    directories = {entry["case_dir"] for entry in results["variants"]}
    cases = []
    for directory in directories:
        path = Path(directory)
        cases.append(load_case(path if path.is_absolute() else REPO_ROOT / path))
    return sorted(cases, key=lambda c: c.meta.id)


def rule_map_path(results: dict[str, Any]) -> Path:
    # Un engine derivado (codeql+ext, codeql+llm) declara con que rule_map se lee.
    return RULE_MAP_DIR / f"{results.get('rule_map', results['tool'])}.yaml"


def score_results(results: dict[str, Any]) -> Score:
    path = rule_map_path(results)
    if not path.is_file():
        raise FileNotFoundError(f"falta el rule_map de {results['tool']}: {path}")
    return tally(cases_of(results), results, load_rule_map(path))


def corpus_label_of(engines: list[EngineRun]) -> str:
    """`angular/xss-sanitizer-bypass` a partir de los case_dir del results."""
    families = set()
    for engine in engines:
        for entry in engine.results["variants"]:
            parts = Path(entry["case_dir"]).parts
            if "corpus" in parts:
                i = parts.index("corpus")
                families.add("/".join(parts[i + 1 : i + 3]))
    return ", ".join(sorted(families)) or "?"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _is_results(payload: Any) -> bool:
    return isinstance(payload, dict) and "variants" in payload and "tool" in payload


def load_run(directory: Path) -> Run | None:
    manifest = _load_json(directory / MANIFEST)
    if not isinstance(manifest, dict):
        return None
    engines = []
    for entry in manifest.get("engines", []):
        path = directory / entry["file"]
        results = _load_json(path)
        if _is_results(results):
            engines.append(EngineRun(tool=results["tool"], path=path, results=results))
    return Run(
        run_id=manifest["run_id"],
        started_at=manifest.get("started_at", ""),
        legacy=False,
        engines=engines,
        directory=directory,
        manifest=manifest,
    )


def load_legacy(path: Path) -> Run | None:
    results = _load_json(path)
    if not _is_results(results):
        return None  # p. ej. el rastro de decisiones, que es una lista
    return Run(
        run_id=path.stem,
        started_at=results.get("run_at", ""),
        legacy=True,
        engines=[EngineRun(tool=results["tool"], path=path, results=results)],
    )


def list_runs(results_dir: Path = RESULTS_DIR) -> list[Run]:
    """Todas las corridas, la mas nueva primero."""
    runs: list[Run] = []
    runs_dir = results_dir / "runs"
    if runs_dir.is_dir():
        for directory in sorted(runs_dir.iterdir()):
            if directory.is_dir() and (run := load_run(directory)):
                runs.append(run)
    for path in sorted(results_dir.glob("*.json")):
        if run := load_legacy(path):
            runs.append(run)
    return sorted(runs, key=lambda r: r.started_at, reverse=True)


def resolve(selector: str, runs: list[Run]) -> Run:
    """Un run-id completo, un prefijo que no sea ambiguo, o `latest`."""
    if not runs:
        raise LookupError("no hay corridas todavia: `sast-bench run --help`")
    if selector == "latest":
        return runs[0]
    exact = [r for r in runs if r.run_id == selector]
    if exact:
        return exact[0]
    matches = [r for r in runs if r.run_id.startswith(selector)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise LookupError(f"no hay ninguna corrida {selector!r}: `sast-bench history` las lista")
    ids = ", ".join(r.run_id for r in matches[:5])
    raise LookupError(f"{selector!r} es ambiguo: {ids}")


def split_selector(selector: str) -> tuple[str, str | None]:
    """`<run-id>:<engine>` -> (run-id, engine). El engine es opcional."""
    run_id, _, tool = selector.partition(":")
    return run_id, tool or None


def latest_results_for(
    tool: str, case_ids: set[str], runs: list[Run], *, exclude: str | None = None
) -> tuple[Run, EngineRun] | None:
    """La corrida mas nueva de `tool` que cubre todos los casos pedidos."""
    for run in runs:
        if run.run_id == exclude:
            continue
        for engine in run.engines:
            if engine.tool == tool and case_ids <= set(engine.case_ids):
                return run, engine
    return None


def decision_records(results_dir: Path = RESULTS_DIR) -> list[dict[str, Any]]:
    """Todas las decisiones del filtro LLM guardadas hasta hoy, legacy y nuevas."""
    paths = list(results_dir.glob("*hybrid-decisions.json"))
    runs_dir = results_dir / "runs"
    if runs_dir.is_dir():
        paths += list(runs_dir.glob(f"*/{DECISIONS}"))
    records: list[dict[str, Any]] = []
    for path in paths:
        payload = _load_json(path)
        if isinstance(payload, list):
            records += [r for r in payload if isinstance(r, dict)]
    return records


# ---------------------------------------------------------------- escritura


def new_run_id(now: dt.datetime, runs_dir: Path = RUNS_DIR) -> str:
    base = now.strftime("%Y%m%d-%H%M%S")
    run_id, n = base, 2
    while (runs_dir / run_id).exists():
        run_id, n = f"{base}-{n}", n + 1
    return run_id


def repo_state() -> dict[str, Any]:
    """Commit del repo y si habia cambios sin commitear: define que corpus se midio."""

    def git(*args: str) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
        )
        return completed.stdout.strip() if completed.returncode == 0 else ""

    commit = git("rev-parse", "HEAD")
    return {"commit": commit or None, "dirty": bool(git("status", "--porcelain")) if commit else None}


def results_filename(tool: str) -> str:
    return f"{tool}.json"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def summarize(score: Score) -> dict[str, Any]:
    return {
        "solved": sum(p.solved for p in score.pairs),
        "pairs": len(score.pairs),
        "recall": round(score.recall, 4),
        "fpr": round(score.fpr, 4),
    }
