"""The CLI and what sits under it: CodeQL cache, runs, diff, estimate.

None of this runs CodeQL, Semgrep or the model. The cache is tested with a fake
binary that only creates the database directory.
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


# ---------------------------------------------------------------- CodeQL cache


def _variant(root: Path, content: str) -> Path:
    variant = root / "safe"
    variant.mkdir(parents=True)
    (variant / "a.ts").write_text(content, encoding="utf-8")
    return variant


def test_fingerprint_depends_on_content_not_on_path(tmp_path):
    one = _variant(tmp_path / "one", "const x = 1;\n")
    two = _variant(tmp_path / "two", "const x = 1;\n")
    other = _variant(tmp_path / "three", "const x = 2;\n")
    assert variant_fingerprint(one, "2.27.1") == variant_fingerprint(two, "2.27.1")
    assert variant_fingerprint(one, "2.27.1") != variant_fingerprint(other, "2.27.1")
    assert variant_fingerprint(one, "2.27.1") != variant_fingerprint(one, "2.28.0")


@pytest.fixture
def fake_codeql(tmp_path) -> Path:
    """A `codeql` that logs each call and creates the database like the real one."""
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


def test_the_second_time_the_database_comes_from_the_cache(tmp_path, fake_codeql):
    variant = _variant(tmp_path / "case", "const x = 1;\n")
    cache = tmp_path / "cache"

    first, hit_first = cached_database(variant, fake_codeql, cache, "2.27.1")
    second, hit_second = cached_database(variant, fake_codeql, cache, "2.27.1")

    assert (hit_first, hit_second) == (False, True)
    assert first == second
    assert len((tmp_path / "calls.log").read_text().splitlines()) == 1


def test_editing_the_variant_invalidates_the_cache(tmp_path, fake_codeql):
    variant = _variant(tmp_path / "case", "const x = 1;\n")
    cache = tmp_path / "cache"
    cached_database(variant, fake_codeql, cache, "2.27.1")
    (variant / "a.ts").write_text("const x = 2;\n", encoding="utf-8")
    _, hit = cached_database(variant, fake_codeql, cache, "2.27.1")
    assert hit is False


def test_a_half_built_database_is_not_a_hit(tmp_path, fake_codeql):
    variant = _variant(tmp_path / "case", "const x = 1;\n")
    cache = tmp_path / "cache"
    (cache / variant_fingerprint(variant, "2.27.1")).mkdir(parents=True)  # no codeql-database.yml
    _, hit = cached_database(variant, fake_codeql, cache, "2.27.1")
    assert hit is False


# ---------------------------------------------------------------- runs


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


def test_list_runs_merges_legacy_and_new_newest_first(results_dir):
    runs = list_runs(results_dir)
    assert [r.run_id for r in runs] == ["20260925-120000", "2026-09-22-codeql"]
    assert [r.legacy for r in runs] == [False, True]
    assert runs[0].corpus_label == "corpus/angular family=client-side-secrets"
    assert runs[1].corpus_label == "angular/client-side-secrets"


def test_resolve_accepts_id_prefix_and_latest(results_dir):
    runs = list_runs(results_dir)
    assert resolve("latest", runs).run_id == "20260925-120000"
    assert resolve("2026-09-22", runs).run_id == "2026-09-22-codeql"
    assert resolve("20260925-120000", runs).run_id == "20260925-120000"
    with pytest.raises(LookupError, match="ambiguous"):
        resolve("2026", runs)
    with pytest.raises(LookupError):
        resolve("nothing", runs)


def test_split_selector():
    assert split_selector("20260925-120000:codeql+ext") == ("20260925-120000", "codeql+ext")
    assert split_selector("latest") == ("latest", None)


def test_a_run_score_uses_the_declared_rule_map(results_dir):
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


def test_diff_separates_fixed_broken_and_shifted():
    before = _score(_pair("a", "FN", "TN"), _pair("b", "TP", "TN"), _pair("c", "FN", "TN"), _pair("d", "TP", "TN"), _pair("x", "FN", "TN"))
    after = _score(_pair("a", "TP", "TN"), _pair("b", "FN", "TN"), _pair("c", "TP", "FP"), _pair("d", "TP", "TN"), _pair("y", "FN", "TN"))
    diff = diff_scores(before, after)
    assert [c.case_id for c in diff.fixed] == ["a"]
    assert [c.case_id for c in diff.broken] == ["b"]
    assert [c.case_id for c in diff.shifted] == ["c"]
    assert diff.unchanged == 1
    assert (diff.only_before, diff.only_after) == (["x"], ["y"])


# ---------------------------------------------------------------- estimate


def test_estimate_averages_only_the_same_model():
    history = [
        {"model": "claude-opus-5", "input_tokens": 1000, "output_tokens": 300},
        {"model": "claude-opus-5", "input_tokens": 2000, "output_tokens": 500},
        {"model": "claude-sonnet-5", "input_tokens": 9000, "output_tokens": 9000},
    ]
    guess = estimate(10, "claude-opus-5", history)
    assert (guess.input_per_call, guess.output_per_call, guess.sample) == (1500, 400, 2)
    assert guess.cost_usd == pytest.approx((15000 * 5 + 4000 * 25) / 1_000_000)


def test_estimate_without_history_uses_the_reference_and_does_not_invent_a_price():
    guess = estimate(3, "another-model", [])
    assert (guess.input_per_call, guess.output_per_call) == FALLBACK_TOKENS
    assert guess.sample == 0
    assert guess.cost_usd is None


def test_count_findings_filters_by_case():
    results = _results("codeql", "", [{"path": "a", "line": 1, "rule_id": "r", "severity": "x"}])
    assert count_findings(results) == 1
    assert count_findings(results, {"other"}) == 0


# ---------------------------------------------------------------- corpus


def test_distribution_of_the_full_corpus():
    cases, problems = validate(CORPUS)
    assert not problems
    counts = distribution(cases)
    assert all(n == PAIRS_PER_CELL for n in counts.values())
    assert len(counts) == 9


def test_validate_collects_problems_without_stopping(tmp_path):
    source = CORPUS / "angular" / "client-side-secrets" / "002-token-in-localstorage"
    broken = tmp_path / "002"
    shutil.copytree(source, broken)
    meta = broken / "meta.yaml"
    meta.write_text(meta.read_text().replace("line: 12", "line: 999"), encoding="utf-8")
    shutil.copytree(source, tmp_path / "002-bis")  # same id
    (tmp_path / "003").mkdir()
    (tmp_path / "003" / "meta.yaml").write_text("id: x\nfamily: nope\n", encoding="utf-8")

    cases, problems = validate(tmp_path)
    messages = " | ".join(p.message for p in problems)
    assert len(cases) == 2
    assert "out of" in messages
    assert "duplicated" in messages
    assert any(p.where.endswith("003") for p in problems)


# ---------------------------------------------------------------- parser


def test_family_accepts_alias_and_id():
    assert cli.family_arg("secrets") is Family.CLIENT_SIDE_SECRETS
    assert cli.family_arg("broken-authorization") is Family.BROKEN_AUTHORIZATION


def test_run_requires_engine():
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["run"])


def test_corpus_stats_end_to_end(capsys):
    assert cli.main(["corpus", "stats"]) == 0
    assert "36 pairs" in capsys.readouterr().out
