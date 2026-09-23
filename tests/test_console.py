"""La capa de presentacion. No mide nada: comprueba que muestre lo que se calculo.

Lo que importa aca es que no se rompa en terminales ajenas: sin color, sin
soporte de unicode, y a 80 columnas.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from rich.console import Console

from scoring.console import (
    ASCII,
    UNICODE,
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
)
from scoring.metrics import PairOutcome, Score, VariantOutcome
from scoring.models import Case, CaseMeta

XSS = "xss-sanitizer-bypass"


def pair(case_id: str, vulnerable: str, safe: str) -> PairOutcome:
    return PairOutcome(
        case_id=case_id,
        vulnerable=VariantOutcome(case_id=case_id, label="vulnerable", cell=vulnerable),
        safe=VariantOutcome(case_id=case_id, label="safe", cell=safe),
    )


def case(case_id: str, difficulty: str = "obvious") -> Case:
    meta = CaseMeta.model_validate(
        {
            "id": case_id,
            "ecosystem": "angular",
            "family": XSS,
            "cwe": "CWE-79",
            "difficulty": difficulty,
            "source": "authored",
            "variants": {
                "vulnerable": {
                    "label": "vulnerable",
                    "rationale": "x",
                    "sink": {"file": "vulnerable/c.ts", "line": 1},
                },
                "safe": {"label": "safe", "rationale": "y"},
            },
        }
    )
    return Case(meta=meta, directory=Path("/nowhere") / case_id)


def score(pairs: list[PairOutcome]) -> Score:
    cells = [v.cell for p in pairs for v in (p.vulnerable, p.safe)]
    return Score(
        pairs=pairs,
        tp=cells.count("TP"),
        fn=cells.count("FN"),
        fp=cells.count("FP"),
        tn=cells.count("TN"),
        unmapped=__import__("collections").Counter(),
    )


@pytest.fixture
def runs():
    pairs = [
        pair("ng-xss-001", "TP", "TN"),
        pair("ng-xss-002", "FN", "TN"),
        pair("ng-xss-003", "TP", "FP"),
    ]
    return [
        ("semgrep", {"tool_version": "semgrep 1.177.0"}, score(pairs)),
        ("codeql", {"tool_version": "codeql 2.27.1"}, score(pairs)),
    ]


@pytest.fixture
def cases():
    return [case("ng-xss-001"), case("ng-xss-002", "indirect"), case("ng-xss-003", "decoy")]


# --- los tres estados ---------------------------------------------------


def test_un_par_resuelto_es_solved():
    assert outcome_of(pair("c", "TP", "TN")) == "solved"


def test_una_falla_que_se_escapa_es_missed():
    assert outcome_of(pair("c", "FN", "TN")) == "missed"


def test_marcar_el_gemelo_sano_es_falsa_alarma():
    assert outcome_of(pair("c", "TP", "FP")) == "false_alarm"


def test_si_se_escapa_la_falla_eso_gana_sobre_la_falsa_alarma():
    """Las dos cosas a la vez: se reporta la peor para la deteccion."""
    assert outcome_of(pair("c", "FN", "FP")) == "missed"


# --- terminales ajenas --------------------------------------------------


def test_no_color_apaga_el_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert make_console().no_color is True


def test_sin_no_color_el_color_queda_como_lo_decida_rich(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert make_console().no_color is False


def test_fallback_ascii_si_la_terminal_no_banca_los_simbolos():
    ascii_only = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="ascii"))
    assert symbols_for(ascii_only) == ASCII


def test_utf8_usa_los_simbolos_lindos():
    utf8 = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    assert symbols_for(utf8) == UNICODE


def test_se_puede_forzar_ascii_por_entorno(monkeypatch):
    monkeypatch.setenv("SAST_BENCH_ASCII", "1")
    utf8 = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    assert symbols_for(utf8) == ASCII


# --- 80 columnas --------------------------------------------------------


def render_at(width: int, runs, cases) -> list[str]:
    console = make_console(width=width)
    with console.capture() as capture:
        header(console, corpus="corpus/angular", runs=runs)
        glossary(console)
        console.print(cases_table(console, runs, cases))
        console.print(metrics_table(console, runs))
    return capture.get().splitlines()


def test_nada_se_pasa_de_80_columnas(runs, cases):
    for line in render_at(80, runs, cases):
        assert len(line) <= 80, f"{len(line)} columnas: {line!r}"


def test_las_tablas_siguen_completas_a_80_columnas(runs, cases):
    salida = "\n".join(render_at(80, runs, cases))
    for expected in ("caso", "dificultad", "semgrep", "codeql", "pares", "encuentra", "ruido"):
        assert expected in salida
    for case_id in ("ng-xss-001", "ng-xss-002", "ng-xss-003"):
        assert case_id in salida


def test_el_encabezado_es_una_sola_linea(runs):
    console = make_console(width=200)
    with console.capture() as capture:
        header(console, corpus="corpus/angular", runs=runs)
    assert len(capture.get().strip().splitlines()) == 1


def test_el_glosario_son_tres_lineas():
    console = make_console(width=80)
    with console.capture() as capture:
        glossary(console)
    assert len(capture.get().strip().splitlines()) == 3


# --- numeros ------------------------------------------------------------


def test_la_tabla_de_metricas_usa_porcentajes_y_nombres_en_castellano(runs):
    console = make_console(width=80)
    with console.capture() as capture:
        console.print(metrics_table(console, runs))
    salida = capture.get()
    # Solo 001 esta resuelto: 002 se le escapo y 003 marco al gemelo sano.
    assert "1/3" in salida  # pares resueltos sobre total
    assert "67%" in salida  # encuentra: 2 TP de 3 vulnerables
    assert "33%" in salida  # ruido: 1 FP de 3 sanas


def test_export_svg(tmp_path: Path, runs, cases):
    console = make_console(record=True, width=80)
    console.print(cases_table(console, runs, cases))
    destino = tmp_path / "tabla.svg"
    export_svg(console, destino, title="sast-bench")
    contenido = destino.read_text(encoding="utf-8")
    assert contenido.startswith("<svg") or "<svg" in contenido
    assert "ng-xss-001" in contenido


def test_el_encabezado_nombra_cada_engine_con_su_version(runs):
    console = make_console(width=200)
    with console.capture() as capture:
        header(console, corpus="corpus/angular", runs=runs)
    salida = capture.get()
    assert "semgrep 1.177.0" in salida
    assert "codeql 2.27.1" in salida
    assert "12 pares" not in salida  # el fixture tiene 3


def test_el_runner_derivado_no_duplica_el_nombre_en_el_encabezado():
    """`codeql+llm` ya trae nombre y modelo en su tool_version."""
    assert engine_label("codeql+llm", "codeql 2.27.1 + claude-opus-5") == (
        "codeql 2.27.1 + claude-opus-5"
    )
    assert engine_label("semgrep", "1.177.0") == "semgrep 1.177.0"


def test_un_evento_largo_sigue_siendo_una_sola_linea():
    """El motivo completo queda en el JSON de decisiones; el log es de un vistazo."""
    console = make_console(width=80)
    with console.capture() as capture:
        log_event(console, "hibrido", "ng-xss-009 safe " + "motivo muy largo " * 20)
    lineas = capture.get().rstrip("\n").splitlines()
    assert len(lineas) == 1
    assert len(lineas[0]) <= 80


def test_el_engine_va_entre_corchetes_literales():
    console = make_console(width=200)
    with console.capture() as capture:
        log_event(console, "hibrido", "algo paso")
    assert "[hibrido]" in capture.get()
