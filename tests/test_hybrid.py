"""Las partes puras del filtro de la fase 3, sin tocar la API.

Lo que se mide aca es que filtrar no rompa el scoring: que una variante que
queda sin hallazgos siga existiendo, y que descartar un hallazgo de varios no
vacie la variante entera.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from runners.hybrid import DecisionRecord, apply_decisions, build_context
from scoring.models import Finding


def finding(rule_id: str = "js/xss", path: str = "a.ts", line: int = 5) -> Finding:
    return Finding(path=path, line=line, rule_id=rule_id, severity="ERROR")


def record(
    case_id: str,
    variant: str,
    f: Finding,
    veredicto: str = "descartado",
) -> DecisionRecord:
    return DecisionRecord(
        case_id=case_id,
        variant=variant,
        finding=f,
        veredicto=veredicto,
        motivo="test",
        control="",
        model="test-model",
        input_tokens=1,
        output_tokens=1,
        decided_at="2026-09-23T00:00:00+00:00",
    )


def results(variants: list[dict]) -> dict:
    return {"tool": "codeql", "variants": variants}


def test_descartar_el_unico_hallazgo_deja_la_variante_vacia_pero_presente():
    """Si la variante se cayera, tally la leeria como ausente en vez de limpia."""
    f = finding()
    payload = results(
        [{"case_id": "ng-xss-009", "variant": "safe", "findings": [f.model_dump()]}]
    )
    out = apply_decisions(payload, [record("ng-xss-009", "safe", f)])
    assert len(out) == 1
    assert out[0]["case_id"] == "ng-xss-009"
    assert out[0]["findings"] == []


def test_descartar_uno_de_tres_conserva_los_otros_dos():
    keep_a, drop, keep_b = (
        finding("js/xss", line=8),
        finding("js/bad-tag-filter", line=3),
        finding("js/incomplete-multi-character-sanitization", line=7),
    )
    payload = results(
        [
            {
                "case_id": "ng-xss-011",
                "variant": "vulnerable",
                "findings": [f.model_dump() for f in (keep_a, drop, keep_b)],
            }
        ]
    )
    out = apply_decisions(payload, [record("ng-xss-011", "vulnerable", drop)])
    assert [f["rule_id"] for f in out[0]["findings"]] == [keep_a.rule_id, keep_b.rule_id]


def test_confirmado_no_descarta_nada():
    f = finding()
    payload = results([{"case_id": "c", "variant": "vulnerable", "findings": [f.model_dump()]}])
    out = apply_decisions(payload, [record("c", "vulnerable", f, veredicto="confirmado")])
    assert len(out[0]["findings"]) == 1


def test_el_descarte_no_cruza_de_variante():
    """Mismo rule_id, misma linea, distinto gemelo: no se deben confundir."""
    f = finding()
    payload = results(
        [
            {"case_id": "c", "variant": "vulnerable", "findings": [f.model_dump()]},
            {"case_id": "c", "variant": "safe", "findings": [f.model_dump()]},
        ]
    )
    out = apply_decisions(payload, [record("c", "safe", f)])
    by_variant = {e["variant"]: e["findings"] for e in out}
    assert len(by_variant["vulnerable"]) == 1
    assert by_variant["safe"] == []


@pytest.fixture
def variant_dir(tmp_path: Path) -> Path:
    (tmp_path / "svc.ts").write_text("uno\ndos\ntres\n", encoding="utf-8")
    (tmp_path / "cmp.ts").write_text("alfa\nbeta\n", encoding="utf-8")
    return tmp_path


def test_el_contexto_incluye_todos_los_archivos_de_la_variante(variant_dir: Path):
    """Sin esto los casos indirectos se juzgarian sin ver el origen del dato."""
    context = build_context(variant_dir, finding(path="cmp.ts", line=2))
    assert "--- svc.ts ---" in context
    assert "--- cmp.ts ---" in context
    assert "uno" in context and "beta" in context


def test_el_contexto_marca_la_linea_del_hallazgo_y_solo_esa(variant_dir: Path):
    context = build_context(variant_dir, finding(path="cmp.ts", line=2))
    marked = [line for line in context.splitlines() if line.startswith(">>>")]
    assert len(marked) == 1
    assert "beta" in marked[0]


def test_la_marca_no_se_pone_en_la_misma_linea_de_otro_archivo(variant_dir: Path):
    """La linea 2 existe en los dos archivos; solo se marca la del hallazgo."""
    context = build_context(variant_dir, finding(path="svc.ts", line=2))
    marked = [line for line in context.splitlines() if line.startswith(">>>")]
    assert len(marked) == 1
    assert "dos" in marked[0]
