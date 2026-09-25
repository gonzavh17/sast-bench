"""La CLI y lo que tiene debajo: cache de CodeQL, corridas, diff, estimacion.

Nada de esto corre CodeQL, Semgrep ni el modelo. La cache se prueba con un
binario falso que solo crea la carpeta de la base.
"""

from __future__ import annotations

import json
import shutil
import stat
from pathlib import Path

import pytest

from runners.codeql import cached_database, variant_fingerprint
from sast_bench import cli
from sast_bench.corpus import PAIRS_PER_CELL, distribution, validate
from sast_bench.diff import diff_scores
from sast_bench.estimate import FALLBACK_TOKENS, count_findings, estimate
from sast_bench.runs import MANIFEST, list_runs, resolve, split_selector
from scoring.metrics import PairOutcome, Score, VariantOutcome
from scoring.models import Family

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "corpus"
SECRETS_002 = "corpus/angular/client-side-secrets/002-token-in-localstorage"


# ---------------------------------------------------------------- cache de CodeQL


def _variant(root: Path, content: str) -> Path:
    variant = root / "safe"
    variant.mkdir(parents=True)
    (variant / "a.ts").write_text(content, encoding="utf-8")
    return variant


def test_fingerprint_depende_del_contenido_y_no_de_la_ruta(tmp_path):
    one = _variant(tmp_path / "uno", "const x = 1;\n")
    two = _variant(tmp_path / "dos", "const x = 1;\n")
    other = _variant(tmp_path / "tres", "const x = 2;\n")
    assert variant_fingerprint(one, "2.27.1") == variant_fingerprint(two, "2.27.1")
    assert variant_fingerprint(one, "2.27.1") != variant_fingerprint(other, "2.27.1")
    assert variant_fingerprint(one, "2.27.1") != variant_fingerprint(one, "2.28.0")


@pytest.fixture
def fake_codeql(tmp_path) -> Path:
    """Un `codeql` que anota cada llamada y crea la base como la real."""
    calls = tmp_path / "calls.log"
    binary = tmp_path / "codeql"
    binary.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{calls}"\n'
        'mkdir -p "$3" && touch "$3/codeql-database.yml"\n',
        encoding="utf-8",
    )
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    return binary


def test_la_segunda_vez_la_base_sale_de_la_cache(tmp_path, fake_codeql):
    variant = _variant(tmp_path / "caso", "const x = 1;\n")
    cache = tmp_path / "cache"

    first, hit_first = cached_database(variant, fake_codeql, cache, "2.27.1")
    second, hit_second = cached_database(variant, fake_codeql, cache, "2.27.1")

    assert (hit_first, hit_second) == (False, True)
    assert first == second
    assert len((tmp_path / "calls.log").read_text().splitlines()) == 1


def test_editar_la_variante_invalida_la_cache(tmp_path, fake_codeql):
    variant = _variant(tmp_path / "caso", "const x = 1;\n")
    cache = tmp_path / "cache"
    cached_database(variant, fake_codeql, cache, "2.27.1")
    (variant / "a.ts").write_text("const x = 2;\n", encoding="utf-8")
    _, hit = cached_database(variant, fake_codeql, cache, "2.27.1")
    assert hit is False


def test_una_base_a_medio_construir_no_cuenta_como_hit(tmp_path, fake_codeql):
    variant = _variant(tmp_path / "caso", "const x = 1;\n")
    cache = tmp_path / "cache"
    (cache / variant_fingerprint(variant, "2.27.1")).mkdir(parents=True)  # sin codeql-database.yml
    _, hit = cached_database(variant, fake_codeql, cache, "2.27.1")
    assert hit is False


# ---------------------------------------------------------------- corridas


def _results(tool: str, run_at: str, findings: list[dict] | None = None) -> dict:
    return {
        "tool": tool,
        "tool_version": "2.27.1",
        "run_at": run_at,
        "rules": {"kind": "custom", "path": "x"},
        "variants": [
            {"case_id": "ng-sec-002", "case_dir": SECRETS_002, "variant": "vulnerable", "findings": findings or []},
            {"case_id": "ng-sec-002", "case_dir": SECRETS_002, "variant": "safe", "findings": []},
        ],
    }


@pytest.fixture
def results_dir(tmp_path) -> Path:
    (tmp_path / "2026-09-22-codeql.json").write_text(
        json.dumps(_results("codeql", "2026-09-22T10:00:00+00:00")), encoding="utf-8"
    )
    (tmp_path / "2026-09-23-hybrid-decisions.json").write_text("[]", encoding="utf-8")
    run = tmp_path / "runs" / "20260925-120000"
    run.mkdir(parents=True)
    finding = {"path": "auth.service.ts", "line": 12, "rule_id": "sast-bench/clear-text-storage-ext", "severity": "ERROR"}
    (run / "codeql+ext.json").write_text(
        json.dumps(_results("codeql+ext", "2026-09-25T12:00:00+00:00", [finding]) | {"rule_map": "codeql"}),
        encoding="utf-8",
    )
    (run / MANIFEST).write_text(
        json.dumps(
            {
                "run_id": "20260925-120000",
                "status": "ok",
                "started_at": "2026-09-25T12:00:00+00:00",
                "corpus": "corpus/angular",
                "filters": {"family": "client-side-secrets", "difficulty": None, "case": None},
                "engines": [{"tool": "codeql+ext", "file": "codeql+ext.json"}],
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_list_runs_junta_legacy_y_nuevas_la_mas_nueva_primero(results_dir):
    runs = list_runs(results_dir)
    assert [r.run_id for r in runs] == ["20260925-120000", "2026-09-22-codeql"]
    assert [r.legacy for r in runs] == [False, True]
    assert runs[0].corpus_label == "corpus/angular family=client-side-secrets"
    assert runs[1].corpus_label == "angular/client-side-secrets"


def test_resolve_acepta_id_prefijo_y_latest(results_dir):
    runs = list_runs(results_dir)
    assert resolve("latest", runs).run_id == "20260925-120000"
    assert resolve("2026-09-22", runs).run_id == "2026-09-22-codeql"
    assert resolve("20260925-120000", runs).run_id == "20260925-120000"
    with pytest.raises(LookupError, match="ambiguo"):
        resolve("2026", runs)
    with pytest.raises(LookupError):
        resolve("nada", runs)


def test_split_selector():
    assert split_selector("20260925-120000:codeql+ext") == ("20260925-120000", "codeql+ext")
    assert split_selector("latest") == ("latest", None)


def test_el_score_de_una_corrida_usa_el_rule_map_declarado(results_dir):
    run = resolve("latest", list_runs(results_dir))
    score = run.engine("codeql+ext").score()
    assert [p.solved for p in score.pairs] == [True]


# ---------------------------------------------------------------- diff


def _pair(case_id: str, vulnerable: str, safe: str) -> PairOutcome:
    return PairOutcome(
        case_id,
        VariantOutcome(case_id, "vulnerable", vulnerable),
        VariantOutcome(case_id, "safe", safe),
    )


def _score(*pairs: PairOutcome) -> Score:
    return Score(list(pairs), 0, 0, 0, 0, unmapped=None)


def test_diff_separa_arreglados_rotos_y_corridos():
    before = _score(_pair("a", "FN", "TN"), _pair("b", "TP", "TN"), _pair("c", "FN", "TN"), _pair("d", "TP", "TN"), _pair("x", "FN", "TN"))
    after = _score(_pair("a", "TP", "TN"), _pair("b", "FN", "TN"), _pair("c", "TP", "FP"), _pair("d", "TP", "TN"), _pair("y", "FN", "TN"))
    diff = diff_scores(before, after)
    assert [c.case_id for c in diff.fixed] == ["a"]
    assert [c.case_id for c in diff.broken] == ["b"]
    assert [c.case_id for c in diff.shifted] == ["c"]
    assert diff.unchanged == 1
    assert (diff.only_before, diff.only_after) == (["x"], ["y"])


# ---------------------------------------------------------------- estimacion


def test_estimate_promedia_solo_el_mismo_modelo():
    history = [
        {"model": "claude-opus-5", "input_tokens": 1000, "output_tokens": 300},
        {"model": "claude-opus-5", "input_tokens": 2000, "output_tokens": 500},
        {"model": "claude-sonnet-5", "input_tokens": 9000, "output_tokens": 9000},
    ]
    guess = estimate(10, "claude-opus-5", history)
    assert (guess.input_per_call, guess.output_per_call, guess.sample) == (1500, 400, 2)
    assert guess.cost_usd == pytest.approx((15000 * 5 + 4000 * 25) / 1_000_000)


def test_estimate_sin_historia_usa_la_referencia_y_modelo_desconocido_no_inventa_precio():
    guess = estimate(3, "otro-modelo", [])
    assert (guess.input_per_call, guess.output_per_call) == FALLBACK_TOKENS
    assert guess.sample == 0
    assert guess.cost_usd is None


def test_count_findings_filtra_por_caso():
    results = _results("codeql", "", [{"path": "a", "line": 1, "rule_id": "r", "severity": "x"}])
    assert count_findings(results) == 1
    assert count_findings(results, {"otro"}) == 0


# ---------------------------------------------------------------- corpus


def test_distribucion_del_corpus_completo():
    cases, problems = validate(CORPUS)
    assert not problems
    counts = distribution(cases)
    assert all(n == PAIRS_PER_CELL for n in counts.values())
    assert len(counts) == 9


def test_validate_junta_problemas_sin_cortar(tmp_path):
    source = CORPUS / "angular" / "client-side-secrets" / "002-token-in-localstorage"
    broken = tmp_path / "002"
    shutil.copytree(source, broken)
    meta = broken / "meta.yaml"
    meta.write_text(meta.read_text().replace("line: 12", "line: 999"), encoding="utf-8")
    shutil.copytree(source, tmp_path / "002-bis")  # mismo id
    (tmp_path / "003").mkdir()
    (tmp_path / "003" / "meta.yaml").write_text("id: x\nfamily: nope\n", encoding="utf-8")

    cases, problems = validate(tmp_path)
    messages = " | ".join(p.message for p in problems)
    assert len(cases) == 2
    assert "fuera de" in messages
    assert "repetido" in messages
    assert any(p.where.endswith("003") for p in problems)


# ---------------------------------------------------------------- parser


def test_family_acepta_alias_y_id():
    assert cli.family_arg("secrets") is Family.CLIENT_SIDE_SECRETS
    assert cli.family_arg("broken-authorization") is Family.BROKEN_AUTHORIZATION


def test_run_exige_engine():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["run"])


def test_corpus_stats_de_punta_a_punta(capsys):
    assert cli.main(["corpus", "stats"]) == 0
    assert "36 pares" in capsys.readouterr().out
