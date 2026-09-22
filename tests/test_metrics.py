"""Metricas sobre Finding sinteticos.

La corrida real de Semgrep sobre el corpus actual no produce ningun FP, asi que
esa celda quedaria sin ejercitar. Aca se arma todo en memoria: cubre TP/FN/FP/TN
sin invocar la herramienta, y separa "el scoring es correcto" de "Semgrep
encontro algo".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scoring.metrics import tally
from scoring.models import Case, CaseMeta, Finding, RuleMap

XSS = "xss-sanitizer-bypass"
SECRETS = "client-side-secrets"

RULE_MAP = RuleMap.model_validate(
    {
        "meta": {"tool": "test", "rules_source": "test@0000000", "mapped_at": "2026-09-21"},
        "rules": {"xss-rule": XSS, "secrets-rule": SECRETS},
        "ignore": ["style-rule"],
    }
)


def make_case(case_id: str = "ng-xss-001", sink_line: int = 19) -> Case:
    meta = CaseMeta.model_validate(
        {
            "id": case_id,
            "ecosystem": "angular",
            "family": XSS,
            "cwe": "CWE-79",
            "difficulty": "obvious",
            "source": "authored",
            "variants": {
                "vulnerable": {
                    "label": "vulnerable",
                    "rationale": "x",
                    "sink": {"file": "vulnerable/c.ts", "line": sink_line},
                },
                "safe": {"label": "safe", "rationale": "y"},
            },
        }
    )
    return Case(meta=meta, directory=Path("/nowhere") / case_id)


def make_results(case_id: str, vulnerable: list[dict], safe: list[dict]) -> dict:
    return {
        "variants": [
            {"case_id": case_id, "variant": "vulnerable", "findings": vulnerable},
            {"case_id": case_id, "variant": "safe", "findings": safe},
        ]
    }


def finding(rule_id: str, line: int = 19, path: str = "c.ts") -> dict:
    return Finding(path=path, line=line, rule_id=rule_id, severity="ERROR").model_dump()


def score_for(vulnerable: list[dict], safe: list[dict], case: Case | None = None):
    case = case or make_case()
    return tally([case], make_results(case.meta.id, vulnerable, safe), RULE_MAP)


def test_par_resuelto_tp_mas_tn():
    score = score_for([finding("xss-rule")], [])
    assert (score.tp, score.fn, score.fp, score.tn) == (1, 0, 0, 1)
    assert score.pairs[0].solved
    assert score.pair_score == 1.0


def test_fn_cuando_la_vulnerable_no_dispara_nada():
    score = score_for([], [])
    assert (score.tp, score.fn, score.fp, score.tn) == (0, 1, 0, 1)
    assert not score.pairs[0].solved
    assert score.recall == 0.0


def test_fp_cuando_la_safe_dispara():
    """La celda que la corrida real no ejercita."""
    score = score_for([finding("xss-rule")], [finding("xss-rule")])
    assert (score.tp, score.fn, score.fp, score.tn) == (1, 0, 1, 0)
    assert not score.pairs[0].solved
    assert score.fpr == 1.0
    assert score.precision == 0.5


def test_fp_con_cualquier_familia_de_seguridad_no_solo_la_esperada():
    """PROJECT.md: FP = variante safe con >=1 hallazgo de *cualquier* familia."""
    score = score_for([finding("xss-rule")], [finding("secrets-rule")])
    assert score.fp == 1


def test_tp_exige_la_familia_esperada():
    """Un hallazgo de otra familia en la vulnerable no salva el caso."""
    score = score_for([finding("secrets-rule")], [])
    assert (score.tp, score.fn) == (0, 1)


def test_recall_100_y_fpr_100_dan_pair_score_0():
    """El escenario que PROJECT.md nombra como el punto del benchmark."""
    cases = [make_case("ng-xss-001"), make_case("ng-xss-002")]
    results = {"variants": []}
    for case in cases:
        results["variants"] += make_results(case.meta.id, [finding("xss-rule")], [finding("xss-rule")])["variants"]
    score = tally(cases, results, RULE_MAP)
    assert score.recall == 1.0
    assert score.fpr == 1.0
    assert score.pair_score == 0.0


def test_rule_id_sin_mapear_no_cuenta_ni_tp_ni_fp():
    score = score_for([finding("regla-nueva")], [finding("otra-nueva")])
    assert (score.tp, score.fn, score.fp, score.tn) == (0, 1, 0, 1)
    assert score.unmapped == {"regla-nueva": 1, "otra-nueva": 1}
    assert score.noise == 1.0


def test_rule_id_en_ignore_no_es_ruido_ni_fp():
    score = score_for([finding("xss-rule")], [finding("style-rule")])
    assert (score.tp, score.tn) == (1, 1)
    assert score.unmapped == {}
    assert score.noise == 0.0
    assert score.pairs[0].solved


@pytest.mark.parametrize("line,localized", [(19, True), (22, True), (23, False)])
def test_localizacion_tolera_mas_menos_tres_lineas(line: int, localized: bool):
    score = score_for([finding("xss-rule", line=line)], [])
    assert score.pairs[0].vulnerable.localized is localized
    assert score.localization == (1.0 if localized else 0.0)


def test_localizacion_exige_el_archivo_del_sink():
    score = score_for([finding("xss-rule", path="otro.ts")], [])
    assert score.pairs[0].vulnerable.localized is False


def test_corpus_vacio_no_divide_por_cero():
    score = tally([], {"variants": []}, RULE_MAP)
    assert score.pair_score == 0.0
    assert score.f1 == 0.0
    assert score.noise == 0.0
